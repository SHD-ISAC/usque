package scout

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

var ErrPinMismatch = errors.New("endpoint public key does not match the original configuration")

var ErrProbeStalled = errors.New("probe did not stop within 1s after cancellation; scan aborted to avoid accumulating stuck probes")

const probeCleanupGrace = time.Second

type Measurement struct {
	Country   string  `json:"country"`
	Colo      string  `json:"colo"`
	ColoCity  string  `json:"colo_city,omitempty"`
	ConnectMS float64 `json:"connect_ms"`
	HTTPSMS   float64 `json:"https_ms"`
	TotalMS   float64 `json:"total_ms"`
}

type Attempt struct {
	Status      string       `json:"status"`
	Stage       string       `json:"stage,omitempty"`
	Error       string       `json:"error,omitempty"`
	Measurement *Measurement `json:"measurement,omitempty"`
}

type Result struct {
	Target    Target    `json:"target"`
	Attempts  []Attempt `json:"attempts"`
	Successes int       `json:"successes"`
	MedianMS  float64   `json:"median_total_ms,omitempty"`
	// Location is from the fastest successful request, not an IP geolocation DB.
	Location *Measurement `json:"location,omitempty"`
}

type Options struct {
	Workers  int
	Attempts int
	Timeout  time.Duration // complete attempt: CONNECT-IP, tunneled DNS and HTTPS
}

func (o Options) Validate() error {
	if o.Workers < 1 || o.Workers > 8 {
		return fmt.Errorf("workers must be between 1 and 8")
	}
	if o.Attempts < 1 || o.Attempts > 10 {
		return fmt.Errorf("attempts must be between 1 and 10")
	}
	if o.Timeout < time.Second || o.Timeout > time.Minute {
		return fmt.Errorf("timeout must be between 1s and 1m")
	}
	return nil
}

type ProbeFunc func(context.Context, Target) (Measurement, error)

type stageError struct {
	stage string
	err   error
}

func (e *stageError) Error() string { return e.err.Error() }
func (e *stageError) Unwrap() error { return e.err }

func failedAttempt(ctx context.Context, err error) Attempt {
	a := Attempt{Status: "connect-error", Stage: "connect", Error: err.Error()}
	var stage *stageError
	if errors.As(err, &stage) {
		a.Stage = stage.stage
		a.Status = stage.stage + "-error"
	}
	var ne net.Error
	switch {
	case errors.Is(err, ErrProbeStalled):
		a.Status, a.Stage = "cleanup-timeout", "cleanup"
	case errors.Is(err, ErrPinMismatch):
		a.Status = "pin-mismatch"
	case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		a.Status = "timeout"
	case errors.Is(ctx.Err(), context.Canceled):
		a.Status = "cancelled"
	case errors.As(err, &ne) && ne.Timeout():
		a.Status = "timeout"
	case strings.Contains(err.Error(), "server responded with"):
		a.Status = "http-error"
	case strings.Contains(err.Error(), "access denied"):
		a.Status = "auth-error"
	}
	return a
}

// A network-stack or transport cleanup bug must not defeat the command's
// timeout. Give the probe a short cleanup grace, then abort the entire scan.
// Never keep scheduling probes over blocked goroutines: process exit releases
// any remaining resources, and at most one in-flight probe per worker exists.
func runProbe(ctx context.Context, t Target, probe ProbeFunc) (Measurement, error) {
	type reply struct {
		m   Measurement
		err error
	}
	done := make(chan reply, 1)
	go func() { m, err := probe(ctx, t); done <- reply{m, err} }()
	select {
	case r := <-done:
		return r.m, r.err
	case <-ctx.Done():
	}
	timer := time.NewTimer(probeCleanupGrace)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.m, r.err
	case <-timer.C:
		return Measurement{}, ErrProbeStalled
	}
}

// Scan bounds concurrency and retries every candidate independently, as MASQUE
// endpoints can fail intermittently. Ranking favours success rate, then median
// end-to-end latency; a fast failed handshake never becomes a usable result.
func Scan(ctx context.Context, targets []Target, o Options, probe ProbeFunc, progress func(Result)) ([]Result, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	if len(targets) == 0 || len(targets) > MaxTargets {
		return nil, fmt.Errorf("target count must be between 1 and %d", MaxTargets)
	}
	if probe == nil {
		return nil, fmt.Errorf("missing probe function")
	}
	scanCtx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	jobs := make(chan Target)
	results := make(chan Result)
	var wg sync.WaitGroup
	for range min(o.Workers, len(targets)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				if scanCtx.Err() != nil {
					return
				}
				r := Result{Target: t}
				var latencies []float64
				for range o.Attempts {
					if scanCtx.Err() != nil {
						break
					}
					attemptCtx, cancel := context.WithTimeout(scanCtx, o.Timeout)
					m, err := runProbe(attemptCtx, t, probe)
					if err == nil && attemptCtx.Err() != nil {
						err = attemptCtx.Err()
					}
					if err != nil {
						r.Attempts = append(r.Attempts, failedAttempt(attemptCtx, err))
					} else {
						r.Attempts = append(r.Attempts, Attempt{Status: "ok", Measurement: &m})
						r.Successes++
						latencies = append(latencies, m.TotalMS)
						if r.Location == nil || m.TotalMS < r.Location.TotalMS {
							r.Location = &m
						}
					}
					cancel()
					if errors.Is(err, ErrProbeStalled) {
						stop(ErrProbeStalled)
						break
					}
				}
				if len(latencies) > 0 {
					slices.Sort(latencies)
					n := len(latencies)
					r.MedianMS = latencies[n/2]
					if n%2 == 0 {
						r.MedianMS = (latencies[n/2-1] + latencies[n/2]) / 2
					}
				}
				results <- r
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, t := range targets {
			select {
			case jobs <- t:
			case <-scanCtx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	var out []Result
	for r := range results {
		out = append(out, r)
		if progress != nil {
			progress(r)
		}
	}
	slices.SortStableFunc(out, func(a, b Result) int {
		// Cross multiplication compares rates without rounding.
		aRate, bRate := a.Successes*len(b.Attempts), b.Successes*len(a.Attempts)
		if aRate > bRate {
			return -1
		}
		if aRate < bRate {
			return 1
		}
		if a.MedianMS < b.MedianMS {
			return -1
		}
		if a.MedianMS > b.MedianMS {
			return 1
		}
		if c := strings.Compare(string(a.Target.Transport), string(b.Target.Transport)); c != 0 {
			return c
		}
		return a.Target.Endpoint.Compare(b.Target.Endpoint)
	})
	return out, context.Cause(scanCtx)
}
