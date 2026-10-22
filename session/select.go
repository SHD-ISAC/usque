// Package session implements the optional manually started Linux system tunnel.
// Endpoint selection is separate from registration: it never writes credentials.
package session

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"
)

type Target struct {
	IP   netip.Addr `json:"ip"`
	Port uint16     `json:"port"`
}

func (t Target) String() string           { return netip.AddrPortFrom(t.IP, t.Port).String() }
func (t Target) AddrPort() netip.AddrPort { return netip.AddrPortFrom(t.IP, t.Port) }

var team4 = netip.MustParsePrefix("162.159.197.0/24")
var team6 = netip.MustParsePrefix("2606:4700:102::/48")

func (t Target) Valid() bool {
	return t.Port != 0 && t.IP.Zone() == "" && !t.IP.Is4In6() && (team4.Contains(t.IP) || team6.Contains(t.IP))
}

type Probe func(context.Context, Target) error

var ErrProbeStalled = errors.New("endpoint probe did not stop after cancellation; ending session")
var ErrNoEndpoint = errors.New("no reachable endpoint passed original-key CONNECT-IP and tunneled HTTPS")

type Selector struct {
	Family          string
	Timeout, Budget time.Duration
	Workers         int
	Targets         []Target
	Probe           Probe
	Reachable       func(context.Context, netip.Addr) bool
	Log             func(string, ...any)
	Last            Target
	Bad             map[Target]time.Time
	cursor          map[bool]int
}

// BuildTargets keeps a small allowlisted set, configured IPs first. Ports are
// independent runtime parameters; no config.json fields are overwritten.
func BuildTargets(v4, v6 string, ports []int) ([]Target, error) {
	ips := []netip.Addr{}
	for _, s := range []string{v6, "2606:4700:102::2", "2606:4700:102::1", v4, "162.159.197.2", "162.159.197.1"} {
		ip, err := netip.ParseAddr(s)
		if s == "" {
			continue
		}
		if err != nil || !(Target{ip, 1}).Valid() {
			return nil, fmt.Errorf("endpoint is outside the Team MASQUE ranges")
		}
		if !slices.Contains(ips, ip) {
			ips = append(ips, ip)
		}
	}
	if len(ports) == 0 || len(ports) > 16 {
		return nil, fmt.Errorf("supply 1..16 endpoint ports")
	}
	var out []Target
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid endpoint port %d", port)
		}
		for _, ip := range ips {
			t := Target{ip, uint16(port)}
			if !slices.Contains(out, t) {
				out = append(out, t)
			}
		}
	}
	return out, nil
}

func (s *Selector) Select(ctx context.Context, only6 bool) (Target, error) {
	if s.Timeout < time.Second || s.Budget < s.Timeout || s.Workers < 1 || s.Workers > 4 || s.Probe == nil {
		return Target{}, fmt.Errorf("invalid automatic endpoint selector settings")
	}
	families := []bool{true, false}
	if s.Family == "4" {
		families = []bool{false}
	} else if s.Family == "6" || only6 {
		families = []bool{true}
	} else if s.Family != "prefer6" {
		return Target{}, fmt.Errorf("family must be prefer6, 4 or 6")
	}
	for _, v6 := range families {
		var candidates []Target
		reachable := make(map[netip.Addr]bool)
		for _, t := range s.Targets {
			if !t.Valid() || t.IP.Is6() != v6 || time.Now().Before(s.Bad[t]) {
				continue
			}
			ok, seen := reachable[t.IP]
			if !seen {
				ok = s.Reachable == nil || s.Reachable(ctx, t.IP)
				reachable[t.IP] = ok
			}
			if ok {
				candidates = append(candidates, t)
			}
		}
		if len(candidates) == 0 {
			continue
		}
		if s.cursor == nil {
			s.cursor = map[bool]int{}
		}
		offset := s.cursor[v6] % len(candidates)
		candidates = append(append([]Target{}, candidates[offset:]...), candidates[:offset]...)
		if i := slices.Index(candidates, s.Last); i > 0 {
			candidates = append([]Target{s.Last}, append(candidates[:i:i], candidates[i+1:]...)...)
		}
		familyCtx, cancel := context.WithTimeout(ctx, s.Budget)
		best, tried, err := s.firstSuccess(familyCtx, candidates)
		cancel()
		if err == nil {
			return best, nil
		}
		s.cursor[v6] = (offset + tried) % len(candidates)
		if errors.Is(err, ErrProbeStalled) || ctx.Err() != nil {
			return Target{}, err
		}
	}
	return Target{}, ErrNoEndpoint
}

func (s *Selector) firstSuccess(ctx context.Context, targets []Target) (Target, int, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan Target)
	type result struct {
		target Target
		err    error
	}
	results := make(chan result, s.Workers)
	var workers sync.WaitGroup
	for range min(s.Workers, len(targets)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for t := range jobs {
				if ctx.Err() != nil {
					return
				}
				attempt, stop := context.WithTimeout(ctx, s.Timeout)
				done := make(chan error, 1)
				go func() { done <- s.Probe(attempt, t) }()
				var err error
				select {
				case err = <-done:
					if err == nil {
						err = attempt.Err()
					}
				case <-attempt.Done():
					err = attempt.Err()
					select {
					case <-done:
					case <-time.After(time.Second):
						err = ErrProbeStalled
					}
				}
				stop()
				results <- result{t, err}
				if errors.Is(err, ErrProbeStalled) {
					cancel()
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, t := range targets {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()
	var selected Target
	var fatal error
	tried := 0
	for r := range results {
		tried++
		if errors.Is(r.err, ErrProbeStalled) {
			fatal = r.err
		}
		if r.err == nil && !selected.IP.IsValid() {
			selected = r.target
			cancel()
		}
		if s.Log != nil && !errors.Is(r.err, context.Canceled) {
			s.Log("Probe %s: %v", r.target, r.err)
		}
	}
	if fatal != nil {
		return Target{}, tried, fatal
	}
	if selected.IP.IsValid() {
		return selected, tried, nil
	}
	return Target{}, tried, ErrNoEndpoint
}
