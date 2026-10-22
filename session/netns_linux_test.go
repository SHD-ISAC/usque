//go:build linux

package session

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"
)

// CI runs this test inside a new network namespace. No production interface,
// default route, DNS configuration or external network is touched.
func TestNamespaceRouting(t *testing.T) {
	if os.Getenv("USQUE_NETNS_TEST") != "1" {
		t.Skip("run in an isolated root network namespace")
	}
	ctx := context.Background()
	run := func(args ...string) {
		t.Helper()
		if _, err := execute(ctx, "ip", args...); err != nil {
			t.Fatal(err)
		}
	}
	run("link", "set", "lo", "up")
	run("link", "add", "uplink0", "type", "veth", "peer", "name", "uplink1")
	run("link", "set", "uplink0", "up")
	run("link", "set", "uplink1", "up")
	run("addr", "add", "192.0.2.2/24", "dev", "uplink0")
	run("-6", "addr", "add", "2001:db8::2/64", "dev", "uplink0", "nodad")
	run("route", "add", "default", "via", "192.0.2.1", "dev", "uplink0")
	run("-6", "route", "add", "default", "via", "2001:db8::1", "dev", "uplink0")
	run("link", "add", Interface, "type", "veth", "peer", "name", "usque-peer")
	run("link", "set", Interface, "up")
	run("link", "set", "usque-peer", "up")
	run("addr", "add", "172.16.0.2/32", "dev", Interface)
	run("-6", "addr", "add", "fd42::2/128", "dev", Interface, "nodad")
	h := fixtureHost(t)
	h.stateUID = 0
	h.Exec = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "resolvectl" {
			return nil, nil
		}
		return execute(ctx, name, args...)
	}
	before := map[int][]map[string]any{}
	for _, family := range []int{4, 6} {
		r, err := h.ip(ctx, family, "rule", "show")
		if err != nil {
			t.Fatal(err)
		}
		before[family] = r
	}
	link, err := net.InterfaceByName(Interface)
	if err != nil {
		t.Fatal(err)
	}
	st := &state{Owner: "usque-native-v1", IfIndex: link.Index}
	if err = h.save(st); err != nil {
		t.Fatal(err)
	}
	if err = h.bypass(ctx, st); err != nil {
		t.Fatal(err)
	}
	if err = h.deviceRoutes(ctx, st, Config{IPv4: "172.16.0.2", IPv6: "fd42::2"}); err != nil {
		t.Fatal(err)
	}
	if err = h.fullRoutes(ctx, st); err != nil {
		t.Fatal(err)
	}
	for _, tg := range []Target{target("162.159.197.2", 500), target("2606:4700:102::2", 4500)} {
		if err = h.validateRoutes(ctx, tg); err != nil {
			t.Fatal(err)
		}
	}
	// An endpoint must never fall back into usque0 if the physical IPv6
	// default disappears while full-tunnel policies still exist.
	run("-6", "route", "del", "default", "via", "2001:db8::1", "dev", "uplink0")
	if _, err = h.Route(ctx, team6.Addr()); err == nil {
		t.Fatal("missing physical IPv6 route fell through to the TUN")
	}
	if err = h.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err = h.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	for _, family := range []int{4, 6} {
		after, err := h.ip(ctx, family, "rule", "show")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(after, before[family]) {
			t.Fatal("original policy changed", family, after, before[family])
		}
		routes, err := h.ip(ctx, family, "route", "show", "table", fmt.Sprint(table))
		if err != nil || len(routes) != 0 {
			t.Fatal("own table not cleaned", family, routes, err)
		}
	}
	// Exercise optional CN routing with real kernel FIB lookups. Preferred
	// physical sources are essential: a mark-only reroute would keep TUN IPs.
	run("-6", "route", "add", "default", "via", "2001:db8::1", "dev", "uplink0")
	st = &state{Owner: "usque-native-v1", IfIndex: link.Index}
	if err = h.save(st); err != nil {
		t.Fatal(err)
	}
	if err = h.bypass(ctx, st); err != nil {
		t.Fatal(err)
	}
	if err = h.deviceRoutes(ctx, st, Config{IPv4: "172.16.0.2", IPv6: "fd42::2"}); err != nil {
		t.Fatal(err)
	}
	d := &CNData{Prefixes: []netip.Prefix{netip.MustParsePrefix("223.0.0.0/8"), netip.MustParsePrefix("240e::/16")}, prefixSet: map[netip.Prefix]bool{netip.MustParsePrefix("223.0.0.0/8"): true, netip.MustParsePrefix("240e::/16"): true}}
	cn, err := h.installCN(ctx, st, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cn.Close()
	if err = h.fullRoutes(ctx, st); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		family   int
		dst, src string
	}{{4, "223.5.5.5", "192.0.2.2"}, {6, "240e::1", "2001:db8::2"}} {
		routes, e := h.ip(ctx, item.family, "route", "get", item.dst)
		if e != nil || len(routes) == 0 || routes[0]["dev"] != "uplink0" {
			t.Fatal("CN route did not bypass TUN", routes, e)
		}
		src, _ := routes[0]["prefsrc"].(string)
		if src == "" {
			src, _ = routes[0]["src"].(string)
		}
		if src != item.src {
			t.Fatal("CN route kept the TUN source address", routes)
		}
	}
	forced, err := h.ip(ctx, 4, "route", "get", "223.5.5.5", "oif", Interface)
	if err != nil || len(forced) == 0 || forced[0]["dev"] != Interface {
		t.Fatal("interface-bound checks escaped the TUN", forced, err)
	}
	if err = h.validateRoutes(ctx, target("2606:4700:102::2", 500)); err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("104.16.1.2")
	if err = cn.Learn(ctx, map[netip.Addr]time.Duration{ip: time.Minute}); err != nil {
		t.Fatal(err)
	}
	routes, err := h.ip(ctx, 4, "route", "get", ip.String())
	if err != nil || len(routes) == 0 || routes[0]["dev"] != "uplink0" {
		t.Fatal("learned CN domain did not bypass", routes, err)
	}
	if err = cn.expire(time.Now().Add(2 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	routes, err = h.ip(ctx, 4, "route", "get", ip.String())
	if err != nil || len(routes) == 0 || routes[0]["dev"] != Interface {
		t.Fatal("expired domain route remained", routes, err)
	}
	// resolved binds its per-link socket to usque0; local DNS at the TUN's
	// own address must still be delivered locally rather than re-encapsulated.
	dns, err := startSplitDNSAt(ctx, netip.MustParseAddr("172.16.0.2"), 0, cn, &CNData{}, nil, func(_ context.Context, q []byte, _, _ bool) ([]byte, error) { return makeReply(q), nil })
	if err != nil {
		t.Fatal(err)
	}
	client, err := deviceDialer(Interface).DialContext(ctx, "udp4", dns.Server())
	if err != nil {
		t.Fatal(err)
	}
	_ = client.SetDeadline(time.Now().Add(time.Second))
	query := makeQuery("outside.example")
	_, _ = client.Write(query)
	packet := make([]byte, 4096)
	n, err := client.Read(packet)
	client.Close()
	dns.Close()
	if err != nil {
		t.Fatal("per-link local DNS looped into TUN", err)
	}
	if err = validateDNSReply(query, packet[:n]); err != nil {
		t.Fatal(err)
	}
	if err = h.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err = h.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	for _, family := range []int{4, 6} {
		after, e := h.ip(ctx, family, "rule", "show")
		if e != nil || !reflect.DeepEqual(after, before[family]) {
			t.Fatal("CN cleanup changed original rules", after, e)
		}
		routes, e := h.ip(ctx, family, "route", "show", "table", fmt.Sprint(cnTable))
		if e != nil || len(routes) != 0 {
			t.Fatal("CN table was not cleaned", routes, e)
		}
	}
}
