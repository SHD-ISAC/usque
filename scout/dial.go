package scout

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/internal"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

type packetConn interface {
	ReadPacket([]byte, bool) (int, error)
	WritePacket([]byte) ([]byte, error)
	Close() error
}

type session struct {
	packets packetConn
	close   func()
	once    sync.Once
}

func (s *session) Close() { s.once.Do(s.close) }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// dialSession uses Usque's CONNECT-IP protocol, with explicitly owned resources.
// Unlike a general proxy client, it always dials the selected IP directly and
// never reads HTTP(S)_PROXY. Cancellation also closes the underlying connection:
// connect-ip-go's HTTP/3 ReadResponse does not itself watch the dial context.
func dialSession(ctx context.Context, target Target, baseTLS *tls.Config, initialSize uint16) (*session, error) {
	if target.Transport == HTTP2 {
		return dialHTTP2(ctx, target, baseTLS)
	}
	if target.Transport != QUIC {
		return nil, fmt.Errorf("unsupported transport %q", target.Transport)
	}
	remote := net.UDPAddrFromAddrPort(target.Endpoint)
	network := "udp4"
	if target.Endpoint.Addr().Is6() {
		network = "udp6"
	}
	udp, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}
	qtr := &quic.Transport{Conn: udp, ConnectionIDLength: 20}
	qcfg := internal.DefaultQuicConfig(30*time.Second, initialSize)
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			_ = qtr.Close()
			_ = udp.Close()
			return nil, context.DeadlineExceeded
		}
		qcfg.HandshakeIdleTimeout = remaining
		qcfg.MaxIdleTimeout = remaining
	}
	conn, err := qtr.Dial(ctx, remote, baseTLS.Clone(), qcfg)
	if err != nil {
		_ = qtr.Close()
		_ = udp.Close()
		return nil, err
	}
	tr := &http3.Transport{
		EnableDatagrams:    true,
		AdditionalSettings: map[uint64]uint64{0x276: 1},
		DisableCompression: true,
	}
	var closeOnce sync.Once
	closeTransport := func() {
		closeOnce.Do(func() {
			_ = conn.CloseWithError(0, "scout probe ended")
			_ = tr.Close()
			_ = qtr.Close()
			_ = udp.Close()
		})
	}
	stop := context.AfterFunc(ctx, closeTransport)
	hconn := tr.NewClientConn(conn)
	ip, rsp, err := connectip.Dial(ctx, hconn, uritemplate.MustNew(internal.ConnectURI), "cf-connect-ip", http.Header{"User-Agent": []string{""}}, true)
	if err != nil {
		stop()
		closeTransport()
		if rsp != nil && rsp.Body != nil {
			_ = rsp.Body.Close()
		}
		return nil, err
	}
	return &session{packets: ip, close: func() {
		stop()
		// Closing the transport first also unblocks a pending packet write.
		closeTransport()
		_ = ip.Close()
	}}, nil
}

func dialHTTP2(ctx context.Context, target Target, baseTLS *tls.Config) (*session, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", target.Endpoint.String())
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	tlsCfg := baseTLS.Clone()
	tlsCfg.NextProtos = []string{"h2"}
	tlsConn := tls.Client(raw, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		stop()
		_ = raw.Close()
		return nil, err
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		stop()
		_ = raw.Close()
		return nil, fmt.Errorf("endpoint did not negotiate h2")
	}
	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(tlsConn)
	if err != nil {
		stop()
		_ = raw.Close()
		return nil, err
	}
	client := &http.Client{Transport: roundTripFunc(cc.RoundTrip)}
	headers := http.Header{"User-Agent": []string{""}, "Cf-Connect-Proto": []string{"cf-connect-ip"}, "Pq-Enabled": []string{"false"}}
	ip, rsp, err := connectip.DialH2(ctx, client, uritemplate.MustNew(internal.ConnectURI), headers)
	if err != nil {
		stop()
		_ = cc.Close()
		_ = raw.Close()
		if rsp != nil && rsp.Body != nil {
			_ = rsp.Body.Close()
		}
		return nil, err
	}
	return &session{packets: ip, close: func() {
		stop()
		_ = raw.Close()
		_ = ip.Close()
		_ = cc.Close()
	}}, nil
}
