package scout

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestScanRanksReliabilityBeforeLatency(t *testing.T) {
	fast := Target{netip.MustParseAddrPort("162.159.197.1:443"), QUIC}
	slow := Target{netip.MustParseAddrPort("162.159.197.2:443"), QUIC}
	dead := Target{netip.MustParseAddrPort("162.159.197.2:500"), QUIC}
	var active, peak atomic.Int32
	var fastCalls atomic.Int32
	probe := func(ctx context.Context, target Target) (Measurement, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		select {
		case <-time.After(time.Millisecond):
		case <-ctx.Done():
			return Measurement{}, ctx.Err()
		}
		if target == dead {
			return Measurement{}, ErrPinMismatch
		}
		if target == fast && fastCalls.Add(1) == 1 {
			return Measurement{}, context.DeadlineExceeded
		}
		latency := 50.0
		if target == fast {
			latency = 1
		}
		return Measurement{TotalMS: latency, Country: "US", Colo: "SJC"}, nil
	}
	progressCalls := 0
	results, err := Scan(context.Background(), []Target{fast, slow, dead}, Options{Workers: 2, Attempts: 3, Timeout: time.Second}, probe, func(Result) { progressCalls++ })
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 || progressCalls != 3 || peak.Load() > 2 {
		t.Fatalf("results=%d progress=%d peak=%d", len(results), progressCalls, peak.Load())
	}
	if results[0].Target != slow || results[0].Successes != 3 || results[0].MedianMS != 50 {
		t.Fatalf("unstable fast target won: %+v", results[0])
	}
	if results[1].Successes != 2 || results[1].MedianMS != 1 {
		t.Fatal(results[1])
	}
	if results[2].Attempts[0].Status != "pin-mismatch" {
		t.Fatal(results[2])
	}
}

func TestScanCancelsWorkersAndScheduling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	targets := make([]Target, 100)
	probe := func(ctx context.Context, _ Target) (Measurement, error) {
		if calls.Add(1) == 2 {
			cancel()
		}
		<-ctx.Done()
		return Measurement{}, ctx.Err()
	}
	_, err := Scan(ctx, targets, Options{Workers: 2, Attempts: 3, Timeout: time.Second}, probe, nil)
	if !errors.Is(err, context.Canceled) || calls.Load() != 2 {
		t.Fatalf("err=%v calls=%d", err, calls.Load())
	}
}

func TestProbeStageIsRetainedForTimeouts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := failedAttempt(ctx, &stageError{"probe", context.DeadlineExceeded})
	if a.Status != "timeout" || a.Stage != "probe" {
		t.Fatal(a)
	}
}
