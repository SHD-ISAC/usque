package scout

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const validTrace = "fl=test\nip=198.51.100.10\ncolo=SJC\nloc=US\nwarp=on\n"

func TestConnectivityUsesVerifiedTraceWhenMetadataUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"forbidden", 403, "forbidden"},
		{"challenge", 200, "<html>challenge</html>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var urls []string
			client := &http.Client{Transport: metaTransport(func(r *http.Request) (*http.Response, error) {
				urls = append(urls, r.URL.String())
				if r.URL.Scheme != "https" || r.Header.Get("Authorization") != "" {
					t.Fatal("unexpected probe request")
				}
				status, body := tc.status, tc.body
				if r.URL.String() == traceURL {
					status, body = 200, validTrace
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			m, err := fetchConnectivity(context.Background(), client)
			if err != nil {
				t.Fatal(err)
			}
			if len(urls) != 2 || urls[0] != metaURL || urls[1] != traceURL {
				t.Fatal(urls)
			}
			if m.Source != traceURL || m.Warp != "on" || m.Country != "US" || m.Colo != "SJC" || m.MetadataError == "" {
				t.Fatalf("lost fallback diagnostic: %+v", m)
			}
			body, _ := json.Marshal(m)
			if strings.Contains(string(body), "198.51.100.10") {
				t.Fatal("trace client IP should not be retained in report")
			}
		})
	}
}

func TestConnectivityKeepsSuccessfulMetadata(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: metaTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != metaURL {
			t.Fatal("unnecessary fallback")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"country":"US","colo":{"iata":"SJC"}}`))}, nil
	})}
	m, err := fetchConnectivity(context.Background(), client)
	if err != nil || calls != 1 || m.Source != metaURL || m.MetadataError != "" {
		t.Fatalf("m=%+v err=%v calls=%d", m, err, calls)
	}
}

func TestTraceRequiresWARPAndValidMetadata(t *testing.T) {
	for _, body := range []string{
		strings.Replace(validTrace, "warp=on", "warp=off", 1),
		strings.Replace(validTrace, "warp=on\n", "", 1),
		strings.Replace(validTrace, "ip=198.51.100.10", "ip=invalid", 1),
		strings.Replace(validTrace, "colo=SJC", "colo=invalid", 1),
		validTrace + "warp=off\n",
		"<html>denied</html>",
	} {
		if _, err := parseTrace([]byte(body)); err == nil {
			t.Fatalf("accepted invalid trace: %q", body)
		}
	}
	if _, err := parseTrace([]byte(strings.ReplaceAll(validTrace, "\n", "\r\n"))); err != nil {
		t.Fatal(err)
	}
}

func TestFallbackErrorReportsFinalProbeFailure(t *testing.T) {
	for _, tc := range []struct {
		status     int
		body, want string
	}{
		{403, "forbidden", "http-error"},
		{200, strings.Replace(validTrace, "warp=on", "warp=off", 1), "probe-error"},
	} {
		client := &http.Client{Transport: metaTransport(func(r *http.Request) (*http.Response, error) {
			status, body := 403, "forbidden"
			if r.URL.String() == traceURL {
				status, body = tc.status, tc.body
			}
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		_, err := fetchConnectivity(context.Background(), client)
		if err == nil {
			t.Fatal("unverified fallback reported success")
		}
		a := failedAttempt(context.Background(), &stageError{"probe", err})
		if a.Status != tc.want || !a.TunnelEstablished {
			t.Fatalf("wrong stage/classification: %+v", a)
		}
	}
}

func TestFallbackSharesAttemptDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	client := &http.Client{Transport: metaTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == metaURL {
			return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader("denied"))}, nil
		}
		if r.Context() != ctx {
			t.Fatal("fallback replaced original attempt context")
		}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	_, err := fetchConnectivity(ctx, client)
	if err == nil || failedAttempt(ctx, &stageError{"probe", err}).Status != "timeout" {
		t.Fatal(err)
	}
}
