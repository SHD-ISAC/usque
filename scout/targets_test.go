package scout

import (
	"net/netip"
	"testing"
)

func TestTeamTargetsKeepProfilesSeparate(t *testing.T) {
	ts, err := BuildTargets(TargetOptions{Profile: "team", Family: "both", Transport: "both", Configured: []string{"162.159.197.2", "162.159.198.2", "2606:4700:102::2"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 32 {
		t.Fatalf("got %d targets, want 4 addresses * 8 transports/ports", len(ts))
	}
	seen := make(map[Target]bool)
	for _, target := range ts {
		if seen[target] {
			t.Fatalf("duplicate: %v", target)
		}
		seen[target] = true
		if target.Endpoint.Addr() == netip.MustParseAddr("162.159.198.2") {
			t.Fatal("consumer H2 default entered Team scan")
		}
		if target.Transport == HTTP2 && target.Endpoint.Port() != 443 {
			t.Fatalf("undocumented default TCP port: %v", target)
		}
	}
	if DefaultSNI("team") != "zt-masque.cloudflareclient.com" {
		t.Fatal("wrong Team SNI")
	}
}

func TestExplicitTargetsAndPorts(t *testing.T) {
	ts, err := BuildTargets(TargetOptions{Profile: "team", Family: "6", Transport: "http2", Endpoints: []string{"2606:4700:102::/127", "2606:4700:102::1"}, Ports: []int{443, 8443, 443}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 4 {
		t.Fatalf("got %d, want 2 addresses * 2 unique ports", len(ts))
	}
	for _, target := range ts {
		if !target.Endpoint.Addr().Is6() || target.Transport != HTTP2 {
			t.Fatal(target)
		}
	}
}

func TestTargetValidationAndBounds(t *testing.T) {
	cases := []TargetOptions{
		{Profile: "team", Family: "4", Transport: "quic", Endpoints: []string{"127.0.0.1"}},
		{Profile: "team", Family: "4", Transport: "quic", Endpoints: []string{"162.159.198.2"}},
		{Profile: "team", Family: "both", Transport: "quic", Endpoints: []string{"2606:4700:102::/48"}},
		{Profile: "team", Family: "both", Transport: "quic", Endpoints: []string{"162.159.197.0/24", "2606:4700:102::1"}},
		{Profile: "team", Family: "6", Transport: "quic", Endpoints: []string{"2606:4700:102::2%wlan0"}},
		{Profile: "team", Family: "4", Transport: "quic", Endpoints: []string{"zt-masque.cloudflareclient.com"}},
		{Profile: "team", Family: "4", Transport: "quic", Ports: []int{0}},
		{Profile: "team", Family: "4", Transport: "quic", Ports: []int{65536}},
		{Profile: "team", Family: "4", Transport: "bogus"},
		{Profile: "team", Family: "bogus", Transport: "quic"},
		{Profile: "bogus", Family: "4", Transport: "quic"},
	}
	for i, c := range cases {
		if _, err := BuildTargets(c); err == nil {
			t.Errorf("case %d accepted invalid scan", i)
		}
	}
	ts, err := BuildTargets(TargetOptions{Profile: "team", Family: "4", Transport: "both", Endpoints: []string{"162.159.197.0/24"}})
	if err != nil || len(ts) != 2048 {
		t.Fatalf("bounded /24: count=%d, err=%v", len(ts), err)
	}
}
