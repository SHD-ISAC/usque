// Package scout adapts warpscout's authenticated MASQUE endpoint probing for
// existing Usque registrations. See THIRD_PARTY_NOTICES.md for attribution.
package scout

import (
	"fmt"
	"net/netip"
	"slices"
)

type Transport string

const (
	QUIC         Transport = "quic"
	HTTP2        Transport = "http2"
	MaxAddresses           = 256
	MaxTargets             = 4096
)

type Target struct {
	Endpoint  netip.AddrPort `json:"endpoint"`
	Transport Transport      `json:"transport"`
}

// The Team ranges and QUIC ports come from Cloudflare's firewall documentation.
// Consumer candidates are from warpscout b49ef5e8a466. A range is an allowlist,
// not a claim that every address in it serves CONNECT-IP.
var teamRanges = []netip.Prefix{
	netip.MustParsePrefix("162.159.197.0/24"),
	netip.MustParsePrefix("2606:4700:102::/48"),
}
var consumerRanges = []netip.Prefix{
	netip.MustParsePrefix("162.159.198.0/24"),
	netip.MustParsePrefix("162.159.199.0/24"),
	netip.MustParsePrefix("2606:4700:103::/48"),
	netip.MustParsePrefix("2606:4700:104::/48"),
}
var quicPorts = []uint16{443, 500, 1701, 4500, 4443, 8443, 8095}

type TargetOptions struct {
	Profile    string
	Family     string
	Transport  string
	Endpoints  []string
	Ports      []int // nil: published QUIC ports and TCP 443 only
	Configured []string
}

func DefaultSNI(profile string) string {
	if profile == "team" {
		return "zt-masque.cloudflareclient.com"
	}
	return "consumer-masque.cloudflareclient.com"
}

func BuildTargets(o TargetOptions) ([]Target, error) {
	var ranges []netip.Prefix
	var defaults []string
	switch o.Profile {
	case "team":
		ranges = teamRanges
		defaults = []string{"162.159.197.1", "162.159.197.2", "2606:4700:102::1", "2606:4700:102::2"}
	case "consumer":
		ranges = consumerRanges
		defaults = []string{"162.159.198.1", "162.159.198.2", "2606:4700:103::1", "2606:4700:103::2", "2606:4700:104::1", "2606:4700:104::2"}
	default:
		return nil, fmt.Errorf("profile must be team or consumer")
	}
	if o.Family != "4" && o.Family != "6" && o.Family != "both" {
		return nil, fmt.Errorf("family must be 4, 6 or both")
	}
	if o.Transport != "quic" && o.Transport != "http2" && o.Transport != "both" {
		return nil, fmt.Errorf("transport must be quic, http2 or both")
	}
	allowed := func(ip netip.Addr) bool {
		return slices.ContainsFunc(ranges, func(p netip.Prefix) bool { return p.Contains(ip) })
	}
	var ips []netip.Addr
	seen := make(map[netip.Addr]bool)
	add := func(ip netip.Addr) error {
		if ip.Zone() != "" || ip.Is4In6() || !allowed(ip) {
			return fmt.Errorf("endpoint %s is outside the %s MASQUE ranges", ip, o.Profile)
		}
		if (o.Family == "4" && !ip.Is4()) || (o.Family == "6" && !ip.Is6()) || seen[ip] {
			return nil
		}
		if len(ips) >= MaxAddresses {
			return fmt.Errorf("at most %d distinct endpoint addresses are allowed", MaxAddresses)
		}
		seen[ip] = true
		ips = append(ips, ip)
		return nil
	}
	entries := o.Endpoints
	if len(entries) == 0 {
		// Ignore legacy consumer HTTP/2 defaults in a Team configuration. Never
		// send this registration's client certificate to the other profile.
		for _, s := range o.Configured {
			if ip, err := netip.ParseAddr(s); err == nil && allowed(ip) {
				if err := add(ip); err != nil {
					return nil, err
				}
			}
		}
		entries = defaults
	}
	for _, s := range entries {
		if ip, err := netip.ParseAddr(s); err == nil {
			if err := add(ip); err != nil {
				return nil, err
			}
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("endpoint %q must be a literal IP or CIDR", s)
		}
		if p.Addr().BitLen()-p.Bits() > 8 {
			return nil, fmt.Errorf("CIDR %s is too large; use at most %d addresses", p, MaxAddresses)
		}
		p = p.Masked()
		for ip := p.Addr(); p.Contains(ip); ip = ip.Next() {
			if err := add(ip); err != nil {
				return nil, err
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no endpoints match the selected address family")
	}
	var ports []uint16
	for _, p := range o.Ports {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port %d is outside 1..65535", p)
		}
		if !slices.Contains(ports, uint16(p)) {
			ports = append(ports, uint16(p))
		}
	}
	var targets []Target
	for _, ip := range ips {
		for _, transport := range []Transport{QUIC, HTTP2} {
			if o.Transport != "both" && o.Transport != string(transport) {
				continue
			}
			ps := ports
			if len(ps) == 0 {
				ps = quicPorts
				if transport == HTTP2 {
					ps = []uint16{443}
				}
			}
			for _, p := range ps {
				targets = append(targets, Target{netip.AddrPortFrom(ip, p), transport})
				if len(targets) > MaxTargets {
					return nil, fmt.Errorf("at most %d endpoint/transport/port combinations are allowed", MaxTargets)
				}
			}
		}
	}
	return targets, nil
}
