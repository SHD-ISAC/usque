//go:build linux

package session

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

const cnDNSPort = 1053

type dnsQuestion struct {
	id   uint16
	name string
	kind uint16
	end  int
}

func question(data []byte, response bool) (dnsQuestion, error) {
	if len(data) < 12 || binary.BigEndian.Uint16(data[4:]) != 1 {
		return dnsQuestion{}, fmt.Errorf("DNS needs one question")
	}
	flags := binary.BigEndian.Uint16(data[2:])
	if flags&0x7800 != 0 || (flags&0x8000 != 0) != response {
		return dnsQuestion{}, fmt.Errorf("unsupported DNS opcode")
	}
	name, end, err := dnsName(data, 12)
	if err != nil || name == "" || len(name) > 253 || end+4 > len(data) {
		return dnsQuestion{}, fmt.Errorf("invalid DNS question")
	}
	if binary.BigEndian.Uint16(data[end+2:]) != 1 {
		return dnsQuestion{}, fmt.Errorf("DNS class must be IN")
	}
	return dnsQuestion{binary.BigEndian.Uint16(data), name, binary.BigEndian.Uint16(data[end:]), end + 4}, nil
}

func validateDNSReply(query, reply []byte) error {
	q, err := question(query, false)
	if err != nil {
		return err
	}
	r, err := question(reply, true)
	if err != nil || r.id != q.id || r.name != q.name || r.kind != q.kind {
		return fmt.Errorf("DNS reply question/transaction mismatch")
	}
	return nil
}

// Only address answers for the original name and its validated CNAME chain are
// learned. Unrelated answer/additional records cannot inject bypass routes.
func learnedAddresses(query, reply []byte) (map[netip.Addr]time.Duration, error) {
	if err := validateDNSReply(query, reply); err != nil {
		return nil, err
	}
	q, _ := question(reply, true)
	out := map[netip.Addr]time.Duration{}
	flags := binary.BigEndian.Uint16(reply[2:])
	if flags&0x020f != 0 || (q.kind != 1 && q.kind != 28) {
		return out, nil
	}
	type record struct {
		name, alias string
		ip          netip.Addr
		ttl         time.Duration
	}
	var records []record
	offset := q.end
	for range int(binary.BigEndian.Uint16(reply[6:])) {
		name, next, err := dnsName(reply, offset)
		if err != nil || next+10 > len(reply) {
			return nil, fmt.Errorf("short DNS answer")
		}
		kind, class := binary.BigEndian.Uint16(reply[next:]), binary.BigEndian.Uint16(reply[next+2:])
		ttl := time.Duration(binary.BigEndian.Uint32(reply[next+4:])) * time.Second
		size := int(binary.BigEndian.Uint16(reply[next+8:]))
		offset = next + 10
		if offset+size > len(reply) {
			return nil, fmt.Errorf("short DNS RDATA")
		}
		if class == 1 {
			if kind == 5 {
				alias, end, err := dnsName(reply, offset)
				if err != nil || end > offset+size {
					return nil, fmt.Errorf("invalid DNS CNAME")
				}
				records = append(records, record{name: name, alias: alias, ttl: ttl})
			}
			if kind == 1 && size == 4 || kind == 28 && size == 16 {
				ip, ok := netip.AddrFromSlice(reply[offset : offset+size])
				if ok && publicIP(ip) {
					records = append(records, record{name: name, ip: ip, ttl: ttl})
				}
			}
		}
		offset += size
	}
	allowed := map[string]bool{q.name: true}
	current := q.name
	limit := 10 * time.Minute
	for depth := 0; depth < 16; depth++ {
		next := ""
		for _, r := range records {
			if r.name == current && r.alias != "" {
				if next != "" && next != r.alias {
					return nil, fmt.Errorf("ambiguous CNAME chain")
				}
				next = r.alias
				limit = min(limit, r.ttl)
			}
		}
		if next == "" {
			break
		}
		if allowed[next] {
			return nil, fmt.Errorf("cyclic CNAME chain")
		}
		allowed[next] = true
		current = next
	}
	for _, r := range records {
		if r.ip.IsValid() && allowed[r.name] {
			ttl := min(r.ttl, limit)
			if old, exists := out[r.ip]; !exists || ttl > old {
				out[r.ip] = ttl
			}
		}
	}
	return out, nil
}

type splitDNS struct {
	udp       *net.UDPConn
	tcp       net.Listener
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	sem       chan struct{}
	closeOnce sync.Once
	err       chan error
	local     netip.Addr
	router    *cnRouter
	data      *CNData
	domestic  []netip.AddrPort
	exchange  func(context.Context, []byte, bool, bool) ([]byte, error)
}

func startSplitDNS(parent context.Context, local netip.Addr, router *cnRouter, data *CNData, servers []netip.AddrPort) (*splitDNS, error) {
	return startSplitDNSAt(parent, local, cnDNSPort, router, data, servers, nil)
}

func startSplitDNSAt(parent context.Context, local netip.Addr, port int, router *cnRouter, data *CNData, servers []netip.AddrPort, exchange func(context.Context, []byte, bool, bool) ([]byte, error)) (*splitDNS, error) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(local.AsSlice()), Port: port})
	if err != nil {
		return nil, fmt.Errorf("bind local split DNS: %w", err)
	}
	port = udp.LocalAddr().(*net.UDPAddr).Port
	tcp, err := net.Listen("tcp4", net.JoinHostPort(local.String(), strconv.Itoa(port)))
	if err != nil {
		udp.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	s := &splitDNS{udp: udp, tcp: tcp, cancel: cancel, sem: make(chan struct{}, 64), err: make(chan error, 1), local: local, router: router, data: data, domestic: servers}
	s.exchange = s.upstream
	if exchange != nil {
		s.exchange = exchange
	}
	s.wg.Add(3)
	go s.serveUDP(ctx)
	go s.serveTCP(ctx)
	go s.expire(ctx)
	context.AfterFunc(ctx, s.closeSockets)
	return s, nil
}

func (s *splitDNS) closeSockets() { s.closeOnce.Do(func() { s.udp.Close(); s.tcp.Close() }) }
func (s *splitDNS) Close()        { s.cancel(); s.closeSockets(); s.wg.Wait() }
func (s *splitDNS) fail(err error) {
	select {
	case s.err <- err:
	default:
	}
}

func (s *splitDNS) allowed(peer net.Addr) bool {
	host, _, err := net.SplitHostPort(peer.String())
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && (ip == s.local || ip.IsLoopback())
}

func (s *splitDNS) answer(ctx context.Context, query []byte, tcp bool) []byte {
	q, err := question(query, false)
	if err == nil {
		attempt, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		cn := s.data.Domain(q.name)
		reply, e := s.exchange(attempt, query, cn, tcp)
		if e == nil {
			if e = validateDNSReply(query, reply); e == nil {
				if cn {
					addresses, e := learnedAddresses(query, reply)
					if e != nil {
						return dnsFailure(query)
					}
					if e = s.router.Learn(attempt, addresses); e != nil {
						return dnsFailure(query)
					}
				}
				return reply
			}
		}
	}
	return dnsFailure(query)
}

func dnsFailure(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	q, err := question(query, false)
	if err != nil {
		return nil
	}
	reply := append([]byte{}, query[:q.end]...)
	flags := binary.BigEndian.Uint16(query[2:])
	binary.BigEndian.PutUint16(reply[2:], 0x8000|0x0080|(flags&0x0100)|2)
	for i := 6; i < 12; i++ {
		reply[i] = 0
	}
	return reply
}

func (s *splitDNS) serveUDP(ctx context.Context) {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, peer, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() == nil {
				s.fail(fmt.Errorf("split DNS UDP listener stopped"))
			}
			return
		}
		if !s.allowed(peer) {
			continue
		}
		select {
		case s.sem <- struct{}{}:
		default:
			continue
		}
		packet := append([]byte{}, buf[:n]...)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			reply := s.answer(ctx, packet, false)
			if len(reply) > 0 {
				_, _ = s.udp.WriteToUDP(reply, peer)
			}
		}()
	}
}

func (s *splitDNS) serveTCP(ctx context.Context) {
	defer s.wg.Done()
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			if ctx.Err() == nil {
				s.fail(fmt.Errorf("split DNS TCP listener stopped"))
			}
			return
		}
		if !s.allowed(conn.RemoteAddr()) {
			conn.Close()
			continue
		}
		select {
		case s.sem <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { conn.Close() })
			defer stop()
			for range 32 {
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				var header [2]byte
				if _, err := io.ReadFull(conn, header[:]); err != nil {
					return
				}
				size := int(binary.BigEndian.Uint16(header[:]))
				if size < 12 {
					return
				}
				query := make([]byte, size)
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				reply := s.answer(ctx, query, true)
				if len(reply) == 0 {
					return
				}
				binary.BigEndian.PutUint16(header[:], uint16(len(reply)))
				if _, err := conn.Write(append(header[:], reply...)); err != nil {
					return
				}
			}
		}()
	}
}

func (s *splitDNS) expire(ctx context.Context) {
	defer s.wg.Done()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			if err := s.router.expire(now); err != nil {
				s.fail(fmt.Errorf("expire CN domain routes: %w", err))
				return
			}
		}
	}
}

func (s *splitDNS) upstream(ctx context.Context, query []byte, cn, tcp bool) ([]byte, error) {
	servers := []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:53"), netip.MustParseAddrPort("1.0.0.1:53")}
	if cn {
		servers = s.domestic
	}
	var last error
	for _, server := range servers {
		iface := Interface
		var source netip.Addr
		if cn {
			phy, ok := s.router.physical[server.Addr().Is6()]
			if !ok {
				continue
			}
			iface, source = phy.device, phy.source
		}
		dialer := deviceDialer(iface)
		network := "udp"
		if tcp {
			network = "tcp"
		}
		if source.IsValid() {
			if tcp {
				dialer.LocalAddr = &net.TCPAddr{IP: net.IP(source.AsSlice())}
			} else {
				dialer.LocalAddr = &net.UDPAddr{IP: net.IP(source.AsSlice())}
			}
		}
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		reply, err := func() ([]byte, error) {
			conn, err := dialer.DialContext(attempt, network, server.String())
			if err != nil {
				return nil, err
			}
			defer conn.Close()
			stop := context.AfterFunc(attempt, func() { conn.Close() })
			defer stop()
			deadline, _ := attempt.Deadline()
			_ = conn.SetDeadline(deadline)
			if tcp {
				var length [2]byte
				binary.BigEndian.PutUint16(length[:], uint16(len(query)))
				if _, err = conn.Write(append(length[:], query...)); err != nil {
					return nil, err
				}
				if _, err = io.ReadFull(conn, length[:]); err != nil {
					return nil, err
				}
				reply := make([]byte, int(binary.BigEndian.Uint16(length[:])))
				_, err = io.ReadFull(conn, reply)
				return reply, err
			}
			if _, err = conn.Write(query); err != nil {
				return nil, err
			}
			reply := make([]byte, 65535)
			n, err := conn.Read(reply)
			return reply[:n], err
		}()
		cancel()
		if err == nil {
			err = validateDNSReply(query, reply)
		}
		if err == nil {
			return reply, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	if last == nil {
		last = fmt.Errorf("no physical route to domestic DNS")
	}
	return nil, last
}

func (s *splitDNS) Server() string { return s.udp.LocalAddr().String() }
