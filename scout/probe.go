// MASQUE packet forwarding and metadata parsing are adapted from warpscout's
// masque.go, tunnel.go and meta.go, with per-attempt isolation and strict pinning.
package scout

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const metaURL = "https://speed.cloudflare.com/meta"
const traceURL = "https://www.cloudflare.com/cdn-cgi/trace"
const maxMetaBytes = 16 << 10

type Engine struct {
	tls         *tls.Config
	local       []netip.Addr
	dns         []netip.Addr
	initialSize uint16
}

// NewEngine reads only the registered device key, peer pin and interface IPs.
// There is no registration, account API, relay, token refresh or insecure mode.
func NewEngine(cfg config.Config, sni string, initialSize uint16) (*Engine, error) {
	if initialSize != 0 && initialSize < 1200 {
		return nil, fmt.Errorf("initial packet size must be 0 (automatic) or at least 1200")
	}
	if sni == "" {
		return nil, fmt.Errorf("SNI must not be empty")
	}
	private, err := cfg.GetEcPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("invalid device private key: %w", err)
	}
	peer, err := cfg.GetEcEndpointPublicKey()
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint public key: %w", err)
	}
	cert, err := internal.GenerateCert(private, &private.PublicKey)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := api.PrepareTlsConfig(private, peer, cert, sni, false)
	if err != nil {
		return nil, err
	}
	verify := tlsCfg.VerifyPeerCertificate
	tlsCfg.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return ErrPinMismatch
		}
		if err := verify(raw, chains); err != nil {
			return fmt.Errorf("%w: %w", ErrPinMismatch, err)
		}
		return nil
	}
	e := &Engine{tls: tlsCfg, initialSize: initialSize}
	for _, s := range []string{cfg.IPv4, cfg.IPv6} {
		if s == "" {
			continue
		}
		ip, err := netip.ParseAddr(s)
		if err != nil || ip.Is4In6() || ip.Zone() != "" {
			return nil, fmt.Errorf("invalid tunnel interface address")
		}
		e.local = append(e.local, ip)
	}
	if len(e.local) == 0 {
		return nil, fmt.Errorf("configuration has no tunnel interface addresses")
	}
	for _, ip := range e.local {
		if ip.Is4() {
			e.dns = append(e.dns, netip.MustParseAddr("1.1.1.1"))
		} else {
			e.dns = append(e.dns, netip.MustParseAddr("2606:4700:4700::1111"))
		}
	}
	return e, nil
}

func (e *Engine) Probe(ctx context.Context, target Target) (Measurement, error) {
	start := time.Now()
	s, err := dialSession(ctx, target, e.tls, e.initialSize)
	if err != nil {
		return Measurement{}, &stageError{"connect", err}
	}
	defer s.Close()
	connected := time.Now()
	dev, tnet, err := netstack.CreateNetTUN(e.local, e.dns, 1280)
	if err != nil {
		return Measurement{}, &stageError{"probe", err}
	}
	bridge := startPacketBridge(ctx, s, api.NewNetstackAdapter(dev), dev.Close)
	stop := context.AfterFunc(bridge.ctx, bridge.Close)
	defer func() { stop(); bridge.Close() }()
	// Both DNS and the HTTPS connection use the isolated userspace tunnel. No
	// host resolver, native TUN, routing changes or environment proxy is used.
	tr := &http.Transport{DialContext: tnet.DialContext, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("metadata redirects are not accepted") }}
	requestStart := time.Now()
	m, err := fetchConnectivity(bridge.ctx, client)
	if err != nil {
		if cause := context.Cause(bridge.ctx); cause != nil {
			err = cause
		}
		return Measurement{}, &stageError{"probe", err}
	}
	m.ConnectMS = float64(connected.Sub(start).Microseconds()) / 1000
	m.HTTPSMS = float64(time.Since(requestStart).Microseconds()) / 1000
	m.TotalMS = float64(time.Since(start).Microseconds()) / 1000
	return m, nil
}

type probeHTTPError struct {
	check  string
	status int
}

func (e *probeHTTPError) Error() string {
	return fmt.Sprintf("%s server responded with %d", e.check, e.status)
}

// An error from the optional metadata site must not by itself reject an
// otherwise working tunnel. Both requests stay inside the same pinned session,
// share the full attempt deadline, and retain normal HTTPS verification.
func fetchConnectivity(ctx context.Context, client *http.Client) (Measurement, error) {
	m, metaErr := fetchMeta(ctx, client)
	if metaErr == nil {
		return m, nil
	}
	if ctx.Err() != nil {
		return Measurement{}, metaErr
	}
	body, err := fetchProbeBody(ctx, client, traceURL, "trace")
	if err == nil {
		m, err = parseTrace(body)
	}
	if err != nil {
		return Measurement{}, fmt.Errorf("metadata check failed (%v); trace check failed: %w", metaErr, err)
	}
	m.Source, m.MetadataError = traceURL, metaErr.Error()
	return m, nil
}

func fetchMeta(ctx context.Context, client *http.Client) (Measurement, error) {
	body, err := fetchProbeBody(ctx, client, metaURL, "metadata")
	if err != nil {
		return Measurement{}, err
	}
	m, err := parseMeta(body)
	if err != nil {
		return Measurement{}, err
	}
	m.Source = metaURL
	return m, nil
}

func fetchProbeBody(ctx context.Context, client *http.Client, url, check string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	rsp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		return nil, &probeHTTPError{check, rsp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(rsp.Body, maxMetaBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxMetaBytes {
		return nil, fmt.Errorf("%s response exceeds %d bytes", check, maxMetaBytes)
	}
	return body, nil
}

func upperCode(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}

func parseTrace(body []byte) (Measurement, error) {
	fields := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		key, value, ok := strings.Cut(strings.TrimSuffix(line, "\r"), "=")
		if !ok {
			return Measurement{}, fmt.Errorf("invalid Cloudflare trace response")
		}
		if _, exists := fields[key]; exists {
			return Measurement{}, fmt.Errorf("duplicate Cloudflare trace field")
		}
		fields[key] = value
	}
	if _, err := netip.ParseAddr(fields["ip"]); err != nil {
		return Measurement{}, fmt.Errorf("trace has no valid client IP")
	}
	if !upperCode(fields["loc"], 2) || !upperCode(fields["colo"], 3) {
		return Measurement{}, fmt.Errorf("trace has no valid country or colo")
	}
	if fields["warp"] != "on" && fields["warp"] != "plus" {
		return Measurement{}, fmt.Errorf("trace does not confirm WARP (warp=%q)", fields["warp"])
	}
	return Measurement{Country: fields["loc"], Colo: fields["colo"], Warp: fields["warp"]}, nil
}

func parseMeta(body []byte) (Measurement, error) {
	var m struct {
		Country string `json:"country"`
		Colo    struct {
			IATA string `json:"iata"`
			City string `json:"city"`
		} `json:"colo"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return Measurement{}, fmt.Errorf("invalid Cloudflare metadata JSON")
	}
	if !upperCode(m.Country, 2) || !upperCode(m.Colo.IATA, 3) {
		return Measurement{}, fmt.Errorf("metadata is missing a valid country or colo")
	}
	return Measurement{Country: m.Country, Colo: m.Colo.IATA, ColoCity: m.Colo.City}, nil
}
