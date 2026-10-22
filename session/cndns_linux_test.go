//go:build linux

package session

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func makeQuery(host string) []byte {
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query, 42)
	binary.BigEndian.PutUint16(query[2:], 0x100)
	binary.BigEndian.PutUint16(query[4:], 1)
	for _, part := range strings.Split(host, ".") {
		query = append(query, byte(len(part)))
		query = append(query, part...)
	}
	return append(query, 0, 0, 1, 0, 1)
}
func nameWire(host string) []byte {
	var out []byte
	for _, part := range strings.Split(host, ".") {
		out = append(out, byte(len(part)))
		out = append(out, part...)
	}
	return append(out, 0)
}
func dnsRR(name string, kind uint16, ttl uint32, data []byte) []byte {
	out := nameWire(name)
	out = binary.BigEndian.AppendUint16(out, kind)
	out = binary.BigEndian.AppendUint16(out, 1)
	out = binary.BigEndian.AppendUint32(out, ttl)
	out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
	return append(out, data...)
}
func makeReply(query []byte, answers ...[]byte) []byte {
	q, _ := question(query, false)
	out := append([]byte{}, query[:q.end]...)
	binary.BigEndian.PutUint16(out[2:], 0x8180)
	binary.BigEndian.PutUint16(out[6:], uint16(len(answers)))
	for _, a := range answers {
		out = append(out, a...)
	}
	return out
}

func routerFixture() *cnRouter {
	return &cnRouter{data: &CNData{}, physical: map[bool]physicalRoute{false: {index: 2, device: "wlan0", source: netip.MustParseAddr("192.0.2.2"), gateway: netip.MustParseAddr("192.0.2.1")}}, learned: map[netip.Addr]time.Time{}, permanent: map[netip.Addr]bool{}, add: func(*netlink.Route) error { return nil }, remove: func(*netlink.Route) error { return nil }}
}

func TestCNLearnValidatesCNAMEAndIgnoresUnrelatedAddresses(t *testing.T) {
	query := makeQuery("www.baidu.com")
	reply := makeReply(query, dnsRR("www.baidu.com", 5, 30, nameWire("foreign.cdn.example")), dnsRR("foreign.cdn.example", 1, 300, []byte{104, 16, 1, 2}), dnsRR("unrelated.example", 1, 300, []byte{8, 8, 8, 8}))
	got, err := learnedAddresses(query, reply)
	if err != nil || len(got) != 1 || got[netip.MustParseAddr("104.16.1.2")] != 30*time.Second {
		t.Fatal(got, err)
	}
	reply[1]++
	if _, err = learnedAddresses(query, reply); err == nil {
		t.Fatal("accepted mismatched transaction")
	}
	reply = makeReply(query, dnsRR("www.baidu.com", 5, 30, nameWire("www.baidu.com")))
	if _, err = learnedAddresses(query, reply); err == nil {
		t.Fatal("accepted CNAME loop")
	}
	reply = makeReply(query, dnsRR("www.baidu.com", 1, 0, []byte{104, 16, 1, 2}))
	got, err = learnedAddresses(query, reply)
	if err != nil || len(got) != 1 || got[netip.MustParseAddr("104.16.1.2")] != 0 {
		t.Fatal("zero-TTL answer lost its immediate route", got, err)
	}
}

func TestCNRouteTTLAndPhysicalSource(t *testing.T) {
	r := routerFixture()
	var adds, deletes int
	r.add = func(route *netlink.Route) error {
		adds++
		if route.Table != cnTable || route.Src.String() != "192.0.2.2" || route.Gw.String() != "192.0.2.1" {
			t.Fatal("wrong bypass source/gateway", route)
		}
		return nil
	}
	r.remove = func(*netlink.Route) error { deletes++; return nil }
	ip := netip.MustParseAddr("104.16.1.2")
	if err := r.Learn(context.Background(), map[netip.Addr]time.Duration{ip: 20 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if err := r.Learn(context.Background(), map[netip.Addr]time.Duration{ip: 5 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if adds != 1 {
		t.Fatal("duplicated learned route")
	}
	if err := r.expire(time.Now().Add(time.Second)); err != nil || deletes != 0 {
		t.Fatal(err, deletes)
	}
	if err := r.expire(time.Now().Add(time.Minute)); err != nil || deletes != 1 {
		t.Fatal(err, deletes)
	}
	r.permanent[ip] = true
	if err := r.Learn(context.Background(), map[netip.Addr]time.Duration{ip: time.Second}); err != nil || len(r.learned) != 0 {
		t.Fatal("static route became expiring", err)
	}
	delete(r.permanent, ip)
	if err := r.Learn(context.Background(), map[netip.Addr]time.Duration{ip: 0}); err != nil || len(r.learned) != 1 {
		t.Fatal("zero-TTL answer cannot choose a physical source", err)
	}
	if err := r.expire(time.Now().Add(2 * time.Second)); err != nil || len(r.learned) != 0 {
		t.Fatal("zero-TTL idle route retained", err)
	}
}

func TestSplitDNSUDPAndTCPInstallBeforeReply(t *testing.T) {
	r := routerFixture()
	var installed, cnQueries, tunnelQueries atomic.Int32
	r.add = func(*netlink.Route) error { installed.Add(1); return nil }
	d := &CNData{Suffix: map[string]bool{"baidu.com": true}}
	exchange := func(_ context.Context, q []byte, cn, tcp bool) ([]byte, error) {
		name, _ := question(q, false)
		if cn {
			cnQueries.Add(1)
		} else {
			tunnelQueries.Add(1)
		}
		return makeReply(q, dnsRR(name.name, 1, 60, []byte{104, 16, 1, 2})), nil
	}
	s, err := startSplitDNSAt(context.Background(), netip.MustParseAddr("127.0.0.1"), 0, r, d, nil, exchange)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	udp, err := net.Dial("udp4", s.Server())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(time.Second))
	q := makeQuery("www.baidu.com")
	_, _ = udp.Write(q)
	buf := make([]byte, 4096)
	n, err := udp.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateDNSReply(q, buf[:n]); err != nil || installed.Load() != 1 {
		t.Fatal("DNS reply preceded route installation", err, installed.Load())
	}
	tcp, err := net.Dial("tcp4", s.Server())
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	_ = tcp.SetDeadline(time.Now().Add(time.Second))
	q = makeQuery("outside.example")
	packet := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
	packet = append(packet, q...)
	_, _ = tcp.Write(packet)
	var header [2]byte
	if _, err = io.ReadFull(tcp, header[:]); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, binary.BigEndian.Uint16(header[:]))
	if _, err = io.ReadFull(tcp, reply); err != nil {
		t.Fatal(err)
	}
	if err = validateDNSReply(q, reply); err != nil || cnQueries.Load() != 1 || tunnelQueries.Load() != 1 || installed.Load() != 1 {
		t.Fatal(err, cnQueries.Load(), tunnelQueries.Load(), installed.Load())
	}
}

func TestCNRouteFailureReturnsDNSFailure(t *testing.T) {
	r := routerFixture()
	r.add = func(*netlink.Route) error { return errors.New("cannot add route") }
	s := &splitDNS{router: r, data: &CNData{Suffix: map[string]bool{"baidu.com": true}}, exchange: func(_ context.Context, q []byte, _, _ bool) ([]byte, error) {
		return makeReply(q, dnsRR("baidu.com", 1, 60, []byte{104, 16, 1, 2})), nil
	}}
	reply := s.answer(context.Background(), makeQuery("baidu.com"), false)
	if len(reply) < 12 || binary.BigEndian.Uint16(reply[2:])&15 != 2 {
		t.Fatal("returned an unrouteable CN answer")
	}
}
