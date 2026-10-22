//go:build linux

package session

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
)

const cnTable = 51872

type physicalRoute struct {
	index           int
	device          string
	source, gateway netip.Addr
}

type cnRouter struct {
	data        *CNData
	physical    map[bool]physicalRoute
	learned     map[netip.Addr]time.Time
	permanent   map[netip.Addr]bool
	mu          sync.Mutex
	handle      *netlink.Handle
	ct          *netlink.Handle
	active      func() map[netip.Addr]bool
	add, remove func(*netlink.Route) error
}

func (h *Host) checkCNTable(ctx context.Context) error {
	for _, family := range []int{4, 6} {
		routes, err := h.ip(ctx, family, "route", "show", "table", strconv.Itoa(cnTable))
		if err != nil {
			return err
		}
		if len(routes) > 0 {
			return fmt.Errorf("CN bypass routing table %d is already in use", cnTable)
		}
	}
	return nil
}

func (h *Host) CheckCNTable(ctx context.Context) error { return h.checkCNTable(ctx) }

func (h *Host) physicalRoutes(ctx context.Context) map[bool]physicalRoute {
	out := map[bool]physicalRoute{}
	for _, family := range []int{4, 6} {
		ip := netip.MustParseAddr("162.159.197.2")
		if family == 6 {
			ip = netip.MustParseAddr("2606:4700:102::2")
		}
		if _, err := h.Route(ctx, ip); err != nil {
			continue
		}
		routes, err := h.ip(ctx, family, "route", "get", ip.String())
		if err != nil || len(routes) == 0 {
			continue
		}
		r := routes[0]
		device, _ := r["dev"].(string)
		link, err := net.InterfaceByName(device)
		if err != nil {
			continue
		}
		src, _ := r["prefsrc"].(string)
		if src == "" {
			src, _ = r["src"].(string)
		}
		source, err := netip.ParseAddr(src)
		if err != nil {
			continue
		}
		var gateway netip.Addr
		if gw, _ := r["gateway"].(string); gw != "" {
			gateway, err = netip.ParseAddr(gw)
			if err != nil {
				continue
			}
		}
		out[family == 6] = physicalRoute{link.Index, device, source, gateway}
	}
	return out
}

func (r *cnRouter) route(prefix netip.Prefix) (*netlink.Route, bool) {
	phy, ok := r.physical[prefix.Addr().Is6()]
	if !ok {
		return nil, false
	}
	route := &netlink.Route{LinkIndex: phy.index, Src: net.IP(phy.source.AsSlice()), Dst: &net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())}, Table: cnTable, Protocol: protocol}
	if phy.gateway.IsValid() {
		route.Gw = net.IP(phy.gateway.AsSlice())
	}
	return route, true
}

func (h *Host) installCN(ctx context.Context, st *state, data *CNData, servers []netip.AddrPort) (*cnRouter, error) {
	handle, err := netlink.NewHandle(syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err = handle.SetSocketTimeout(3 * time.Second); err != nil {
		handle.Close()
		return nil, err
	}
	r := &cnRouter{data: data, physical: h.physicalRoutes(ctx), learned: map[netip.Addr]time.Time{}, permanent: map[netip.Addr]bool{}, handle: handle, add: handle.RouteAdd, remove: handle.RouteDel}
	if data.DomainCount() > 0 {
		if ct, e := netlink.NewHandle(syscall.NETLINK_NETFILTER); e == nil {
			if e = ct.SetSocketTimeout(time.Second); e == nil {
				r.ct = ct
			} else {
				ct.Close()
			}
		}
		r.active = func() map[netip.Addr]bool { return activeDestinations(r.ct) }
	}
	success := false
	defer func() {
		if !success {
			r.Close()
		}
	}()
	for _, family := range []int{4, 6} {
		if _, ok := r.physical[family == 6]; !ok {
			log.Printf("CN bypass: no usable physical IPv%d; that family's traffic keeps using TUN", family)
			continue
		}
		st.Undo = append(st.Undo, action{Kind: "cnroutes", Family: family})
		if err = h.save(st); err != nil {
			return nil, err
		}
		prefixes := append([]netip.Prefix{}, data.Prefixes...)
		// The domestic DNS sockets also need a physical route before replies
		// can teach new domain routes. Host routes carry the physical source.
		for _, server := range servers {
			prefixes = append(prefixes, netip.PrefixFrom(server.Addr(), server.Addr().BitLen()))
		}
		seen := map[netip.Prefix]bool{}
		count := 0
		for _, p := range prefixes {
			if p.Addr().Is6() != (family == 6) || seen[p] {
				continue
			}
			seen[p] = true
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			route, ok := r.route(p)
			if !ok {
				continue
			}
			if err = r.add(route); err != nil && !errors.Is(err, syscall.EEXIST) {
				return nil, fmt.Errorf("install CN bypass routes: %w", err)
			}
			count++
			if p.Bits() == p.Addr().BitLen() {
				r.permanent[p.Addr()] = true
			}
		}
		log.Printf("CN bypass: %d IPv%d prefixes use physical routing", count, family)
	}
	st.CNEnabled = true
	success = true
	return r, nil
}

func (r *cnRouter) Close() {
	if r != nil && r.ct != nil {
		r.ct.Close()
	}
	if r != nil && r.handle != nil {
		r.handle.Close()
	}
}

// Install before returning the DNS answer so a new application socket chooses
// the physical source address on its first route lookup. No NAT/firewall rule
// or change to the system main table is necessary.
func (r *cnRouter) Learn(ctx context.Context, addresses map[netip.Addr]time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for ip, ttl := range addresses {
		if !publicIP(ip) || r.data.Contains(ip) || r.permanent[ip] || ttl < 0 {
			continue
		}
		route, ok := r.route(netip.PrefixFrom(ip, ip.BitLen()))
		if !ok {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A zero DNS TTL forbids answer caching, but the new socket still needs
		// a physical route. Keep it briefly; established flows retain it below.
		until := now.Add(max(time.Second, min(ttl, 10*time.Minute)))
		if old, exists := r.learned[ip]; exists {
			if until.After(old) {
				r.learned[ip] = until
			}
			continue
		}
		if len(r.learned) >= 8192 {
			return fmt.Errorf("CN domain route cache is full")
		}
		if err := r.add(route); err != nil && !errors.Is(err, syscall.EEXIST) {
			return err
		}
		r.learned[ip] = until
	}
	return nil
}

func (r *cnRouter) expire(now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var active map[netip.Addr]bool
	if r.active != nil {
		for _, until := range r.learned {
			if !now.Before(until) {
				active = r.active()
				break
			}
		}
	}
	for ip, until := range r.learned {
		if now.Before(until) {
			continue
		}
		if active[ip] {
			r.learned[ip] = now.Add(30 * time.Second)
			continue
		}
		route, ok := r.route(netip.PrefixFrom(ip, ip.BitLen()))
		if !ok {
			delete(r.learned, ip)
			continue
		}
		if err := r.remove(route); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
		delete(r.learned, ip)
	}
	return nil
}

func parseDNSServers(servers []string) ([]netip.AddrPort, error) {
	if len(servers) < 1 || len(servers) > 4 {
		return nil, fmt.Errorf("supply 1..4 domestic DNS servers")
	}
	var out []netip.AddrPort
	for _, s := range servers {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			ip, e := netip.ParseAddr(s)
			if e != nil {
				return nil, fmt.Errorf("CN DNS must be a literal IP with an optional port")
			}
			ap = netip.AddrPortFrom(ip, 53)
		}
		if !publicIP(ap.Addr()) || ap.Addr().Zone() != "" || ap.Port() == 0 {
			return nil, fmt.Errorf("CN DNS must use a public unicast address")
		}
		out = append(out, ap)
	}
	return out, nil
}
