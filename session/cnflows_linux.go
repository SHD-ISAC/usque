//go:build linux

package session

// DNS leases must not tear down an established direct connection. Read only
// local kernel socket/conntrack metadata when leases expire; nothing is logged
// or persisted. Conntrack also covers QUIC using unconnected UDP sockets.
import (
	"bufio"
	"encoding/binary"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
)

func procAddress(value string) (netip.Addr, bool) {
	hex, _, ok := strings.Cut(value, ":")
	if !ok || (len(hex) != 8 && len(hex) != 32) {
		return netip.Addr{}, false
	}
	data := make([]byte, len(hex)/2)
	for offset := 0; offset < len(hex); offset += 8 {
		n, err := strconv.ParseUint(hex[offset:offset+8], 16, 32)
		if err != nil {
			return netip.Addr{}, false
		}
		binary.NativeEndian.PutUint32(data[offset/2:], uint32(n))
	}
	ip, ok := netip.AddrFromSlice(data)
	return ip.Unmap(), ok
}

func activeDestinations(ct *netlink.Handle) map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f, err := os.Open("/proc/net/" + name)
		if err != nil {
			continue
		}
		s := bufio.NewScanner(io.LimitReader(f, 8<<20))
		for s.Scan() {
			fields := strings.Fields(s.Text())
			if len(fields) < 4 || fields[3] == "0A" || fields[3] == "07" || fields[3] == "06" {
				continue
			}
			if ip, ok := procAddress(fields[2]); ok && publicIP(ip) {
				out[ip] = true
			}
		}
		f.Close()
	}
	if ct != nil {
		for _, family := range []netlink.InetFamily{syscall.AF_INET, syscall.AF_INET6} {
			flows, _ := ct.ConntrackTableList(netlink.ConntrackTable, family)
			for _, flow := range flows {
				if ip, ok := netip.AddrFromSlice(flow.Forward.DstIP); ok {
					ip = ip.Unmap()
					if publicIP(ip) {
						out[ip] = true
					}
				}
			}
		}
	}
	return out
}
