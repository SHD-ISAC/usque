//go:build linux

package session

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func pbBytes(n uint64, b []byte) []byte {
	out := binary.AppendUvarint(nil, n<<3|2)
	out = binary.AppendUvarint(out, uint64(len(b)))
	return append(out, b...)
}
func pbInt(n, value uint64) []byte {
	return binary.AppendUvarint(binary.AppendUvarint(nil, n<<3), value)
}
func geoEntry(code string, values ...[]byte) []byte {
	entry := pbBytes(1, []byte(code))
	for _, v := range values {
		entry = append(entry, pbBytes(2, v)...)
	}
	return pbBytes(1, entry)
}
func domainRule(kind uint64, value string) []byte {
	return append(pbInt(1, kind), pbBytes(2, []byte(value))...)
}
func cidrRule(prefix string) []byte {
	p := netip.MustParsePrefix(prefix)
	return append(pbBytes(1, p.Addr().AsSlice()), pbInt(2, uint64(p.Bits()))...)
}

func TestCNGeoDataWireCompatibility(t *testing.T) {
	d := &CNData{}
	ip := append(geoEntry("us", cidrRule("8.8.8.0/24")), geoEntry("CN", cidrRule("223.5.0.0/16"), cidrRule("240e::/16"), cidrRule("223.5.0.0/16"))...)
	if err := parseGeoIP(ip, d); err != nil {
		t.Fatal(err)
	}
	if len(d.Prefixes) != 2 || !d.Contains(netip.MustParseAddr("240e::1")) || d.Contains(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal(d.Prefixes)
	}
	site := geoEntry("cn", domainRule(2, "baidu.com"), domainRule(3, "only.example.cn"), domainRule(0, "keyword-cn"), domainRule(1, `(^|\.)example[0-9]+\.cn$`))
	if err := parseGeoSite(site, d); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"BAIDU.COM.", "www.baidu.com", "only.example.cn", "some-keyword-cn.invalid", "www.example42.cn"} {
		if !d.Domain(name) {
			t.Error("did not match", name)
		}
	}
	for _, name := range []string{"baidu.com.evil.invalid", "notbaidu.com", "www.only.example.cn", "example-no.cn"} {
		if d.Domain(name) {
			t.Error("matched unrelated name", name)
		}
	}
}

func TestCNGeoDataRejectsMalformedAndBroadInputs(t *testing.T) {
	for _, data := range [][]byte{{0xff}, geoEntry("us", cidrRule("8.8.8.0/24")), geoEntry("cn", cidrRule("0.0.0.0/0")), geoEntry("cn", cidrRule("127.0.0.0/8"))} {
		if err := parseGeoIP(data, &CNData{}); err == nil {
			t.Errorf("accepted invalid GeoIP %x", data)
		}
	}
	for _, data := range [][]byte{geoEntry("cn", domainRule(4, "baidu.com")), geoEntry("cn", domainRule(1, "[")), geoEntry("cn", domainRule(2, ""))} {
		if err := parseGeoSite(data, &CNData{}); err == nil {
			t.Fatal("accepted invalid geosite")
		}
	}
	entry := append(pbBytes(1, []byte("cn")), pbInt(3, 1)...)
	entry = append(entry, pbBytes(2, cidrRule("223.5.5.0/24"))...)
	if err := parseGeoIP(pbBytes(1, entry), &CNData{}); err == nil {
		t.Fatal("accepted reversed CN match")
	}
}

func TestExplicitGeoDataPathsAndOffMode(t *testing.T) {
	if d, err := LoadCNData("off", "missing", "missing"); err != nil || d != nil {
		t.Fatal(d, err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "geoip.dat")
	if err := os.WriteFile(path, geoEntry("cn", cidrRule("223.5.0.0/16")), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := FindGeoData("geoip.dat", path, dir)
	if err != nil || got != path {
		t.Fatal(got, err)
	}
	d, err := LoadCNData("ip", got, "")
	if err != nil || len(d.Prefixes) != 1 {
		t.Fatal(d, err)
	}
	if _, err = FindGeoData("geoip.dat", filepath.Join(dir, "missing"), dir); err == nil {
		t.Fatal("explicit missing path silently ignored")
	}
}
