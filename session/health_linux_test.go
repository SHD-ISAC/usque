//go:build linux

package session

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func dnsFixture() []byte {
	data := make([]byte, 12)
	binary.BigEndian.PutUint16(data, 42)
	binary.BigEndian.PutUint16(data[2:], 0x8180)
	binary.BigEndian.PutUint16(data[4:], 1)
	binary.BigEndian.PutUint16(data[6:], 1)
	for _, p := range strings.Split(traceHost, ".") {
		data = append(data, byte(len(p)))
		data = append(data, p...)
	}
	return append(data, 0, 0, 1, 0, 1, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 104, 16, 123, 96)
}

func TestDNSChecksTransactionAndCompression(t *testing.T) {
	data := dnsFixture()
	ips, err := parseDNS(data, 42, traceHost, 1)
	if err != nil || len(ips) != 1 || ips[0] != netip.MustParseAddr("104.16.123.96") {
		t.Fatalf("%v %v", ips, err)
	}
	if _, err = parseDNS(data, 43, traceHost, 1); err == nil {
		t.Fatal("accepted wrong transaction")
	}
	if _, err = parseDNS(data, 42, "evil.invalid", 1); err == nil {
		t.Fatal("accepted wrong DNS name")
	}
	if _, err = parseDNS(data, 42, traceHost, 28); err == nil {
		t.Fatal("accepted wrong family")
	}
	data[2] |= 2
	if _, err = parseDNS(data, 42, traceHost, 1); err == nil {
		t.Fatal("accepted truncated response")
	}
	if _, _, err = dnsName([]byte{0xc0, 0}, 0); err == nil {
		t.Fatal("accepted compression cycle")
	}
}

func TestTraceRequiresWarpFamilyAndDoesNotKeepIP(t *testing.T) {
	good := []byte("ip=104.16.1.2\nwarp=plus\ncolo=LAX\n")
	h, err := parseTrace(good, 4)
	if err != nil || h.Warp != "plus" {
		t.Fatal(h, err)
	}
	for _, bad := range []string{string(good) + "warp=on\n", strings.ReplaceAll(string(good), "plus", "off"), strings.ReplaceAll(string(good), "LAX", "xx")} {
		if _, err := parseTrace([]byte(bad), 4); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if _, err = parseTrace(good, 6); err == nil {
		t.Fatal("accepted wrong address family")
	}
	encoded, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "104.16.1.2") {
		t.Fatal("health record retained client address")
	}
}
