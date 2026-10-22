//go:build linux

package session

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const traceHost = "www.cloudflare.com"
const Interface = "usque0"

// All probe sockets are bound to the native TUN, including DNS. A failed
// tunnel must never be mistaken for a successful direct-network probe.
func deviceDialer(iface string) *net.Dialer {
	return &net.Dialer{Timeout: 5 * time.Second, Control: func(_, _ string, raw syscall.RawConn) error {
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return sockErr
	}}
}

func dnsName(data []byte, offset int) (string, int, error) {
	var labels []string
	end := -1
	seen := map[int]bool{}
	for steps := 0; steps < 128; steps++ {
		if offset >= len(data) || offset < 0 || seen[offset] {
			break
		}
		seen[offset] = true
		n := int(data[offset])
		offset++
		if n&0xc0 == 0xc0 {
			if offset >= len(data) {
				break
			}
			if end < 0 {
				end = offset + 1
			}
			offset = (n&63)<<8 | int(data[offset])
			continue
		}
		if n == 0 {
			if end < 0 {
				end = offset
			}
			return strings.ToLower(strings.Join(labels, ".")), end, nil
		}
		if n > 63 || offset+n > len(data) {
			break
		}
		labels = append(labels, string(data[offset:offset+n]))
		offset += n
	}
	return "", 0, fmt.Errorf("invalid or cyclic DNS name")
}

func publicIP(ip netip.Addr) bool {
	return ip.IsValid() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.Is4In6()
}

func parseDNS(data []byte, id uint16, host string, qtype uint16) ([]netip.Addr, error) {
	if len(data) < 12 || binary.BigEndian.Uint16(data) != id || binary.BigEndian.Uint16(data[2:])&0xfa0f != 0x8000 || binary.BigEndian.Uint16(data[2:])&0x200 != 0 || binary.BigEndian.Uint16(data[4:]) != 1 {
		return nil, fmt.Errorf("DNS response mismatch, truncation or failure")
	}
	name, offset, err := dnsName(data, 12)
	if err != nil || name != host || offset+4 > len(data) || binary.BigEndian.Uint16(data[offset:]) != qtype || binary.BigEndian.Uint16(data[offset+2:]) != 1 {
		return nil, fmt.Errorf("DNS question mismatch")
	}
	offset += 4
	var ips []netip.Addr
	for range int(binary.BigEndian.Uint16(data[6:])) {
		_, next, err := dnsName(data, offset)
		if err != nil || next+10 > len(data) {
			return nil, fmt.Errorf("short DNS answer")
		}
		typ, class, size := binary.BigEndian.Uint16(data[next:]), binary.BigEndian.Uint16(data[next+2:]), int(binary.BigEndian.Uint16(data[next+8:]))
		offset = next + 10
		if offset+size > len(data) {
			return nil, fmt.Errorf("short DNS data")
		}
		if typ == qtype && class == 1 {
			ip, ok := netip.AddrFromSlice(data[offset : offset+size])
			if ok && publicIP(ip) && ((qtype == 1 && ip.Is4()) || (qtype == 28 && ip.Is6())) {
				ips = append(ips, ip)
			}
		}
		offset += size
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("DNS returned no public addresses")
	}
	return ips, nil
}

func tunnelDNS(ctx context.Context, iface, host string, family int) ([]netip.Addr, error) {
	qtype, server, network := uint16(1), "1.1.1.1:53", "udp4"
	if family == 6 {
		qtype, server, network = 28, "[2606:4700:4700::1111]:53", "udp6"
	}
	var last error
	for range 3 {
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		ips, err := func() ([]netip.Addr, error) {
			conn, err := deviceDialer(iface).DialContext(attempt, network, server)
			if err != nil {
				return nil, err
			}
			defer conn.Close()
			deadline, _ := attempt.Deadline()
			_ = conn.SetDeadline(deadline)
			query := make([]byte, 12)
			if _, err = rand.Read(query[:2]); err != nil {
				return nil, err
			}
			binary.BigEndian.PutUint16(query[2:], 0x100)
			binary.BigEndian.PutUint16(query[4:], 1)
			for _, label := range strings.Split(host, ".") {
				query = append(query, byte(len(label)))
				query = append(query, label...)
			}
			query = append(query, 0, byte(qtype>>8), byte(qtype), 0, 1)
			if _, err = conn.Write(query); err != nil {
				return nil, err
			}
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if err != nil {
				return nil, err
			}
			return parseDNS(buf[:n], binary.BigEndian.Uint16(query), host, qtype)
		}()
		cancel()
		if err == nil {
			return ips, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("TUN IPv%d UDP DNS failed: %w", family, last)
}

type Health struct {
	Family int    `json:"family"`
	Warp   string `json:"warp"`
	Colo   string `json:"colo"`
	MS     int64  `json:"elapsed_ms"`
}

func parseTrace(data []byte, family int) (Health, error) {
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		k, v, ok := strings.Cut(strings.TrimSuffix(line, "\r"), "=")
		if !ok {
			return Health{}, fmt.Errorf("invalid trace")
		}
		if _, exists := fields[k]; exists {
			return Health{}, fmt.Errorf("duplicate trace field")
		}
		fields[k] = v
	}
	ip, err := netip.ParseAddr(fields["ip"])
	if err != nil || ip.Is4In6() || ip.Is4() != (family == 4) || (fields["warp"] != "on" && fields["warp"] != "plus") {
		return Health{}, fmt.Errorf("trace did not confirm inner IPv%d WARP", family)
	}
	colo := fields["colo"]
	if len(colo) != 3 || strings.IndexFunc(colo, func(c rune) bool { return c < 'A' || c > 'Z' }) >= 0 {
		return Health{}, fmt.Errorf("invalid trace location")
	}
	// The full client address is deliberately discarded.
	return Health{Family: family, Warp: fields["warp"], Colo: colo}, nil
}

func checkFamily(ctx context.Context, iface string, family int) (Health, error) {
	start := time.Now()
	ips, err := tunnelDNS(ctx, iface, traceHost, family)
	if err != nil {
		return Health{}, err
	}
	dialer := deviceDialer(iface)
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var last error
		for _, ip := range ips[:min(2, len(ips))] {
			conn, err := dialer.DialContext(ctx, "tcp"+strconv.Itoa(family), net.JoinHostPort(ip.String(), "443"))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, last
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("trace redirects refused") }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+traceHost+"/cdn-cgi/trace", nil)
	resp, err := client.Do(req)
	if err != nil {
		return Health{}, fmt.Errorf("TUN IPv%d HTTPS failed: %w", family, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Health{}, fmt.Errorf("trace HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16385))
	if err != nil {
		return Health{}, err
	}
	if len(data) > 16384 {
		return Health{}, fmt.Errorf("oversize trace")
	}
	h, err := parseTrace(data, family)
	h.MS = time.Since(start).Milliseconds()
	return h, err
}

// Check verifies both inner address families. DNS is UDP in the same family;
// HTTPS keeps the normal hostname/CA checks and ignores environment proxies.
func Check(ctx context.Context, iface string) ([]Health, error) {
	type result struct {
		h   Health
		err error
	}
	results := make(chan result, 2)
	for _, family := range []int{4, 6} {
		go func() { h, err := checkFamily(ctx, iface, family); results <- result{h, err} }()
	}
	var out []Health
	var failures []error
	for range 2 {
		r := <-results
		if r.err != nil {
			failures = append(failures, r.err)
		} else {
			out = append(out, r.h)
		}
	}
	if len(failures) > 0 {
		return out, fmt.Errorf("dual-stack health check failed: %v", failures)
	}
	return out, nil
}
