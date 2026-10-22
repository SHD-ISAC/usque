package scout

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/config"
	"github.com/quic-go/quic-go/http3"
)

func testRegistration(t *testing.T) (config.Config, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return config.Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(der),
		EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})),
		IPv4:           "172.16.0.2", IPv6: "2606:4700:110::2",
	}, tls.Certificate{Certificate: [][]byte{cert}, PrivateKey: key}
}

func TestEngineAlwaysEnforcesOriginalPin(t *testing.T) {
	cfg, cert := testRegistration(t)
	engine, err := NewEngine(cfg, DefaultSNI("team"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if engine.tls.VerifyPeerCertificate == nil {
		t.Fatal("pin verification is missing")
	}
	if err := engine.tls.VerifyPeerCertificate(cert.Certificate, nil); err != nil {
		t.Fatalf("original pin rejected: %v", err)
	}
	_, other := testRegistration(t)
	for _, raw := range [][][]byte{nil, other.Certificate, {{0, 1, 2}}} {
		if err := engine.tls.VerifyPeerCertificate(raw, nil); !errors.Is(err, ErrPinMismatch) {
			t.Fatalf("untrusted peer accepted: %v", err)
		}
	}
	if cfg.EndpointPubKey == "" {
		t.Fatal("configuration changed")
	}
}

func h2TestServer(t *testing.T, handler http.Handler) (*Engine, Target) {
	t.Helper()
	cfg, cert := testRegistration(t)
	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	engine, err := NewEngine(cfg, DefaultSNI("team"), 0)
	if err != nil {
		t.Fatal(err)
	}
	return engine, Target{netip.MustParseAddrPort(srv.Listener.Addr().String()), HTTP2}
}

func TestHTTP2ProbeDialsSelectedIPAndReports400(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	requestOK := make(chan bool, 1)
	engine, target := h2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestOK <- r.Method == http.MethodConnect && r.Host == "cloudflareaccess.com:443" && r.ProtoMajor == 2 && r.Header.Get("cf-connect-proto") == "cf-connect-ip" && r.Header.Get("pq-enabled") == "false" && r.Header.Get("Authorization") == "" && len(r.TLS.PeerCertificates) == 1
		w.WriteHeader(http.StatusBadRequest)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := engine.Probe(ctx, target)
	if err == nil || failedAttempt(ctx, err).Status != "http-error" {
		t.Fatalf("expected 400, got %v", err)
	}
	if !<-requestOK {
		t.Fatal("unexpected CONNECT-IP request or missing client certificate")
	}
}

func TestHTTP2RejectsDifferentEndpointKey(t *testing.T) {
	engine, target := h2TestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted peer reached CONNECT") }))
	other, _ := testRegistration(t)
	engine, err := NewEngine(other, DefaultSNI("team"), 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = engine.Probe(ctx, target)
	if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("key mismatch was not enforced: %v", err)
	}
}

func TestHTTP2HandshakeAloneIsNotUsable(t *testing.T) {
	engine, target := h2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		// Accept CONNECT but drop all encapsulated traffic, modelling an edge
		// that authenticates successfully and never forwards DNS/HTTPS.
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := engine.Probe(ctx, target)
	a := failedAttempt(ctx, err)
	if err == nil || a.Status != "timeout" || a.Stage != "probe" {
		t.Fatalf("handshake-only result: err=%v attempt=%+v", err, a)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("probe cleanup did not honour deadline")
	}
}

func TestHTTP3ConnectAndCancellation(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusOK} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			cfg, cert := testRegistration(t)
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			srv := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, EnableDatagrams: true, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				if status == http.StatusOK {
					_ = http.NewResponseController(w).Flush()
					<-r.Context().Done()
				}
			})}
			done := make(chan struct{})
			go func() { defer close(done); _ = srv.Serve(udp) }()
			t.Cleanup(func() { _ = srv.Close(); _ = udp.Close(); <-done })
			engine, err := NewEngine(cfg, DefaultSNI("team"), 1200)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, err = engine.Probe(ctx, Target{netip.MustParseAddrPort(udp.LocalAddr().String()), QUIC})
			if err == nil {
				t.Fatal("unverified tunnel reported as usable")
			}
			a := failedAttempt(ctx, err)
			if status == http.StatusBadRequest && a.Status != "http-error" {
				t.Fatalf("expected HTTP error: %+v", a)
			}
			if status == http.StatusOK && a.Status != "timeout" {
				t.Fatalf("expected timeout: %+v", a)
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("QUIC request/cleanup exceeded timeout")
			}
		})
	}
}

func TestHTTP3KeyMismatchClassification(t *testing.T) {
	cfg, _ := testRegistration(t)
	_, cert := testRegistration(t)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, EnableDatagrams: true}
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(udp) }()
	t.Cleanup(func() { _ = srv.Close(); _ = udp.Close(); <-done })
	engine, err := NewEngine(cfg, DefaultSNI("team"), 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = engine.Probe(ctx, Target{netip.MustParseAddrPort(udp.LocalAddr().String()), QUIC})
	if err == nil {
		t.Fatal("different peer key was accepted")
	}
	if a := failedAttempt(ctx, err); a.Status != "pin-mismatch" {
		t.Fatalf("lost pin failure in QUIC error: %+v", a)
	}
}

func TestAuthenticatedPacketRoundTrip(t *testing.T) {
	for _, transport := range []Transport{HTTP2, QUIC} {
		t.Run(string(transport), func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_ = http.NewResponseController(w).Flush()
				if transport == HTTP2 {
					// One DATAGRAM capsule: type 0, length 20, IPv4 header.
					frame := make([]byte, 22)
					if _, err := io.ReadFull(r.Body, frame); err != nil {
						return
					}
					_, _ = w.Write(frame)
					_ = http.NewResponseController(w).Flush()
					<-r.Context().Done()
					return
				}
				stream := w.(http3.HTTPStreamer).HTTPStream()
				frame, err := stream.ReceiveDatagram(r.Context())
				if err != nil {
					return
				}
				_ = stream.SendDatagram(frame)
				<-r.Context().Done()
			})
			var engine *Engine
			var target Target
			if transport == HTTP2 {
				engine, target = h2TestServer(t, handler)
			} else {
				cfg, cert := testRegistration(t)
				udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				srv := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, EnableDatagrams: true, Handler: handler}
				done := make(chan struct{})
				go func() { defer close(done); _ = srv.Serve(udp) }()
				t.Cleanup(func() { _ = srv.Close(); _ = udp.Close(); <-done })
				engine, err = NewEngine(cfg, DefaultSNI("team"), 0)
				if err != nil {
					t.Fatal(err)
				}
				target = Target{netip.MustParseAddrPort(udp.LocalAddr().String()), QUIC}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			s, err := dialSession(ctx, target, engine.tls, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			packet := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 172, 16, 0, 2, 1, 1, 1, 1}
			if _, err := s.packets.WritePacket(packet); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 1280)
			n, err := s.packets.ReadPacket(buf, true)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf[:n], packet) {
				t.Fatalf("packet changed in %s transport: %x != %x", transport, buf[:n], packet)
			}
		})
	}
}

type metaTransport func(*http.Request) (*http.Response, error)

func (f metaTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMetadataValidation(t *testing.T) {
	for _, tc := range []struct {
		body   string
		status int
		good   bool
	}{
		{`{"country":"US","colo":{"iata":"SJC","city":"San Jose"}}`, 200, true},
		{`{"country":"US"}`, 200, false},
		{`{"country":"XX","colo":{"iata":"SJC"}} trailing`, 200, false},
		{`<html>blocked</html>`, 200, false},
		{strings.Repeat("x", maxMetaBytes+1), 200, false},
		{`{"country":"US","colo":{"iata":"SJC"}}`, 403, false},
	} {
		client := &http.Client{Transport: metaTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != metaURL || r.Header.Get("Authorization") != "" {
				t.Error("unexpected metadata request")
			}
			return &http.Response{StatusCode: tc.status, Body: io.NopCloser(bytes.NewBufferString(tc.body))}, nil
		})}
		_, err := fetchMeta(context.Background(), client)
		if (err == nil) != tc.good {
			t.Fatalf("expected valid=%v, err=%v", tc.good, err)
		}
	}
}
