//go:build linux

package session

// Read the public GeoIPList/GeoSiteList wire format directly. No Xray process,
// protobuf runtime, downloader or bundled third-party database is needed.
// Schema: XTLS/Xray-core/common/geodata/geodat.proto.
import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

type CNData struct {
	Prefixes     []netip.Prefix
	Suffix, Full map[string]bool
	Substrings   []string
	Regex        []*regexp.Regexp
	prefixSet    map[netip.Prefix]bool
}

func (d *CNData) Domain(name string) bool {
	if d == nil {
		return false
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if d.Full[name] {
		return true
	}
	for suffix := name; suffix != ""; {
		if d.Suffix[suffix] {
			return true
		}
		_, next, ok := strings.Cut(suffix, ".")
		if !ok {
			break
		}
		suffix = next
	}
	for _, part := range d.Substrings {
		if strings.Contains(name, part) {
			return true
		}
	}
	for _, re := range d.Regex {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

func (d *CNData) Contains(ip netip.Addr) bool {
	if d == nil {
		return false
	}
	for bits := ip.BitLen(); bits >= 1; bits-- {
		if d.prefixSet[netip.PrefixFrom(ip, bits).Masked()] {
			return true
		}
	}
	return false
}

func (d *CNData) DomainCount() int {
	return len(d.Suffix) + len(d.Full) + len(d.Substrings) + len(d.Regex)
}

type protoField struct {
	number, wire int
	value        uint64
	bytes        []byte
}

func fields(data []byte, fn func(protoField) error) error {
	for len(data) > 0 {
		tag, n := binary.Uvarint(data)
		if n <= 0 || tag>>3 == 0 {
			return fmt.Errorf("invalid geodata protobuf tag")
		}
		data = data[n:]
		f := protoField{number: int(tag >> 3), wire: int(tag & 7)}
		switch f.wire {
		case 0:
			v, n := binary.Uvarint(data)
			if n <= 0 {
				return fmt.Errorf("invalid geodata varint")
			}
			f.value = v
			data = data[n:]
		case 1:
			if len(data) < 8 {
				return io.ErrUnexpectedEOF
			}
			data = data[8:]
		case 2:
			size, n := binary.Uvarint(data)
			if n <= 0 || size > uint64(len(data)-n) {
				return io.ErrUnexpectedEOF
			}
			f.bytes = data[n : n+int(size)]
			data = data[n+int(size):]
		case 5:
			if len(data) < 4 {
				return io.ErrUnexpectedEOF
			}
			data = data[4:]
		default:
			return fmt.Errorf("unsupported geodata wire type")
		}
		if err := fn(f); err != nil {
			return err
		}
	}
	return nil
}

func cnEntries(data []byte, fn func([][]byte) error) error {
	found := false
	err := fields(data, func(f protoField) error {
		if f.number != 1 || f.wire != 2 {
			return nil
		}
		var code string
		var entries [][]byte
		reverse := false
		if err := fields(f.bytes, func(v protoField) error {
			switch {
			case v.number == 1 && v.wire == 2:
				code = string(v.bytes)
			case v.number == 2 && v.wire == 2:
				entries = append(entries, v.bytes)
			case v.number == 3 && v.wire == 0:
				reverse = v.value != 0
			}
			return nil
		}); err != nil {
			return err
		}
		if !strings.EqualFold(code, "cn") {
			return nil
		}
		if reverse {
			return fmt.Errorf("inverted CN geodata is unsupported")
		}
		found = true
		return fn(entries)
	})
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("geodata has no CN entry")
	}
	return nil
}

func parseGeoIP(data []byte, d *CNData) error {
	d.prefixSet = map[netip.Prefix]bool{}
	err := cnEntries(data, func(entries [][]byte) error {
		for _, entry := range entries {
			var raw []byte
			var bits uint64
			if err := fields(entry, func(f protoField) error {
				if f.number == 1 && f.wire == 2 {
					raw = f.bytes
				}
				if f.number == 2 && f.wire == 0 {
					bits = f.value
				}
				return nil
			}); err != nil {
				return err
			}
			ip, ok := netip.AddrFromSlice(raw)
			if !ok || ip.Is4In6() || bits < 1 || bits > uint64(ip.BitLen()) {
				return fmt.Errorf("invalid CN CIDR")
			}
			p := netip.PrefixFrom(ip, int(bits)).Masked()
			if !publicIP(p.Addr()) {
				continue
			}
			if !d.prefixSet[p] {
				d.prefixSet[p] = true
				d.Prefixes = append(d.Prefixes, p)
			}
			if len(d.Prefixes) > 200000 {
				return fmt.Errorf("CN CIDR count exceeds limit")
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(d.Prefixes) == 0 {
		return fmt.Errorf("CN GeoIP entry is empty")
	}
	slices.SortFunc(d.Prefixes, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return nil
}

func parseGeoSite(data []byte, d *CNData) error {
	d.Suffix = map[string]bool{}
	d.Full = map[string]bool{}
	err := cnEntries(data, func(entries [][]byte) error {
		for _, entry := range entries {
			kind := uint64(0)
			value := ""
			if err := fields(entry, func(f protoField) error {
				if f.number == 1 && f.wire == 0 {
					kind = f.value
				}
				if f.number == 2 && f.wire == 2 {
					value = string(f.bytes)
				}
				return nil
			}); err != nil {
				return err
			}
			if value == "" || len(value) > 4096 || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\n\r") {
				return fmt.Errorf("invalid CN domain rule")
			}
			switch kind {
			case 0:
				d.Substrings = append(d.Substrings, strings.ToLower(value))
			case 1:
				re, err := regexp.Compile(value)
				if err != nil {
					return fmt.Errorf("invalid CN domain regex: %w", err)
				}
				d.Regex = append(d.Regex, re)
			case 2:
				d.Suffix[strings.ToLower(strings.TrimSuffix(value, "."))] = true
			case 3:
				d.Full[strings.ToLower(strings.TrimSuffix(value, "."))] = true
			default:
				return fmt.Errorf("unsupported CN domain match type")
			}
			if d.DomainCount() > 1000000 {
				return fmt.Errorf("CN domain count exceeds limit")
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if d.DomainCount() == 0 {
		return fmt.Errorf("CN GeoSite entry is empty")
	}
	return nil
}

func readGeoData(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("geodata is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, 128<<20))
	if err != nil {
		return nil, err
	}
	if len(data) >= 128<<20 {
		return nil, fmt.Errorf("geodata exceeds 128 MiB")
	}
	return data, nil
}

func cnMode(mode string) (ip, domain bool, err error) {
	switch mode {
	case "", "off":
	case "ip":
		ip = true
	case "domain":
		domain = true
	case "both":
		ip, domain = true, true
	default:
		err = fmt.Errorf("bypass-cn must be off, ip, domain or both")
	}
	return
}

func LoadCNData(mode, geoip, geosite string) (*CNData, error) {
	ip, domain, err := cnMode(mode)
	if err != nil {
		return nil, err
	}
	if !ip && !domain {
		return nil, nil
	}
	d := &CNData{}
	if ip {
		data, err := readGeoData(geoip)
		if err != nil {
			return nil, fmt.Errorf("read geoip.dat: %w", err)
		}
		if err = parseGeoIP(data, d); err != nil {
			return nil, err
		}
	}
	if domain {
		data, err := readGeoData(geosite)
		if err != nil {
			return nil, fmt.Errorf("read geosite.dat: %w", err)
		}
		if err = parseGeoSite(data, d); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// Reuse installed, public Xray data; never silently download or update it.
func FindGeoData(name, explicit, home string) (string, error) {
	paths := []string{explicit}
	if explicit == "" {
		for _, dir := range []string{os.Getenv("XRAY_LOCATION_ASSET"), "/usr/local/share/xray", "/usr/share/xray", "/var/lib/xray", "/etc/xray", "/usr/local/etc/xray", filepath.Join(home, ".config/xray"), filepath.Join(home, ".local/share/xray")} {
			if dir != "" {
				paths = append(paths, filepath.Join(dir, name))
			}
		}
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return "", err
		}
		if strings.ContainsAny(absolute, "\n\r%$") {
			return "", fmt.Errorf("geodata path contains unsupported systemd expansion characters")
		}
		if info, err := os.Stat(absolute); err == nil && info.Mode().IsRegular() {
			return absolute, nil
		}
	}
	return "", fmt.Errorf("%s not found; specify its existing Xray path with --%s-file", name, strings.TrimSuffix(name, ".dat"))
}
