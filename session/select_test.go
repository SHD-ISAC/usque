package session

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func target(ip string, port uint16) Target { return Target{netip.MustParseAddr(ip), port} }

func selectorFixture() *Selector {
	ts, _ := BuildTargets("162.159.197.2", "2606:4700:102::2", []int{500, 4500})
	return &Selector{Family: "prefer6", Timeout: time.Second, Budget: time.Second, Workers: 2, Targets: ts, Bad: map[Target]time.Time{}}
}

func TestPreferIPv6EvenWithCachedIPv4(t *testing.T) {
	s := selectorFixture()
	s.Last = target("162.159.197.2", 500)
	s.Probe = func(_ context.Context, tg Target) error {
		if tg.IP.Is4() {
			t.Error("IPv4 was probed before usable IPv6")
		}
		return nil
	}
	got, err := s.Select(context.Background(), false)
	if err != nil || !got.IP.Is6() {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestFallbackSkipsUnavailablePhysicalIPv6(t *testing.T) {
	s := selectorFixture()
	s.Reachable = func(_ context.Context, ip netip.Addr) bool { return ip.Is4() }
	s.Probe = func(_ context.Context, tg Target) error {
		if tg.IP.Is6() {
			t.Error("unreachable IPv6 probe")
		}
		return nil
	}
	got, err := s.Select(context.Background(), false)
	if err != nil || !got.IP.Is4() {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestPortFallbackAndStrictFamily(t *testing.T) {
	s := selectorFixture()
	s.Family = "6"
	s.Probe = func(_ context.Context, tg Target) error {
		if tg.IP.Is4() {
			t.Error("strict IPv6 fell back to IPv4")
		}
		if tg.Port == 4500 {
			return nil
		}
		return errors.New("blocked port")
	}
	got, err := s.Select(context.Background(), false)
	if err != nil || got.Port != 4500 || !got.IP.Is6() {
		t.Fatalf("got %v, %v", got, err)
	}
	s.Probe = func(context.Context, Target) error { return errors.New("pin mismatch") }
	if _, err = s.Select(context.Background(), false); !errors.Is(err, ErrNoEndpoint) {
		t.Fatal(err)
	}
}

func TestCachedTargetFirstAndFailedTargetCooldown(t *testing.T) {
	s := selectorFixture()
	s.Family = "4"
	s.Workers = 1
	s.Last = target("162.159.197.1", 4500)
	var got []Target
	s.Probe = func(_ context.Context, tg Target) error { got = append(got, tg); return nil }
	best, err := s.Select(context.Background(), false)
	if err != nil || best != s.Last || got[0] != s.Last {
		t.Fatalf("cached endpoint not tried first: %v %v", got, err)
	}
	s.Bad[s.Last] = time.Now().Add(time.Minute)
	got = nil
	best, err = s.Select(context.Background(), false)
	if err != nil || best == s.Last {
		t.Fatalf("failed endpoint not cooled down: %v %v", best, err)
	}
}

func TestBoundedProbeCancellationAndConcurrency(t *testing.T) {
	s := selectorFixture()
	var running, maximum atomic.Int32
	s.Probe = func(ctx context.Context, _ Target) error {
		n := running.Add(1)
		defer running.Add(-1)
		for {
			old := maximum.Load()
			if n <= old || maximum.CompareAndSwap(old, n) {
				break
			}
		}
		<-ctx.Done()
		return ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := s.Select(ctx, false); err == nil {
		t.Fatal("cancelled selection succeeded")
	}
	if time.Since(start) > 500*time.Millisecond || maximum.Load() > 2 || running.Load() != 0 {
		t.Fatalf("unbounded cleanup or concurrency: max=%d active=%d", maximum.Load(), running.Load())
	}
}

func TestStuckProbeAbortsInsteadOfFallingBack(t *testing.T) {
	s := selectorFixture()
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	exited := make(chan struct{}, 2)
	s.Probe = func(context.Context, Target) error {
		started <- struct{}{}
		<-release
		exited <- struct{}{}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := s.Select(ctx, false); done <- err }()
	for range 2 {
		<-started
	}
	cancel()
	err := <-done
	close(release)
	for range 2 {
		<-exited
	}
	if !errors.Is(err, ErrProbeStalled) {
		t.Fatalf("got %v", err)
	}
}

func TestTeamAllowlistAndPortValidation(t *testing.T) {
	for _, tc := range []struct {
		ip    string
		ports []int
	}{{"162.159.199.2", []int{500}}, {"::ffff:162.159.197.2", []int{500}}, {"2606:4700:102::2%wlan0", []int{500}}, {"162.159.197.2", []int{0}}, {"162.159.197.2", []int{65536}}} {
		if _, err := BuildTargets(tc.ip, "", tc.ports); err == nil {
			t.Errorf("accepted invalid target %v", tc)
		}
	}
}
