package scout

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/dns/dnsmessage"
)

// Answer the tunneled DNS query but drop the subsequent TCP SYN. A DNS-only
// blackhole does not exercise gonet's TCP abort path during context cancellation.
func dnsReply(packet []byte) []byte {
	if len(packet) < 28 || packet[0]>>4 != 4 || packet[9] != 17 {
		return nil
	}
	ipLen := int(packet[0]&15) * 4
	if ipLen < 20 || len(packet) < ipLen+8 {
		return nil
	}
	var parser dnsmessage.Parser
	hdr, err := parser.Start(packet[ipLen+8:])
	if err != nil {
		return nil
	}
	q, err := parser.Question()
	if err != nil {
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, Response: true, RecursionDesired: hdr.RecursionDesired, RecursionAvailable: true})
	if b.StartQuestions() != nil || b.Question(q) != nil || b.StartAnswers() != nil {
		return nil
	}
	if q.Type == dnsmessage.TypeA {
		if b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}) != nil {
			return nil
		}
	}
	body, err := b.Finish()
	if err != nil {
		return nil
	}
	reply := make([]byte, 28+len(body))
	reply[0], reply[8], reply[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(reply[2:4], uint16(len(reply)))
	copy(reply[12:16], packet[16:20])
	copy(reply[16:20], packet[12:16])
	copy(reply[20:22], packet[ipLen+2:ipLen+4])
	copy(reply[22:24], packet[ipLen:ipLen+2])
	binary.BigEndian.PutUint16(reply[24:26], uint16(8+len(body)))
	copy(reply[28:], body)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(reply[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(reply[10:12], ^uint16(sum))
	return reply
}

func synAck(packet []byte) []byte {
	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return nil
	}
	ipLen := int(packet[0]&15) * 4
	if len(packet) < ipLen+20 || packet[ipLen+13]&2 == 0 {
		return nil
	}
	reply := make([]byte, 40)
	reply[0], reply[8], reply[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(reply[2:4], 40)
	copy(reply[12:16], packet[16:20])
	copy(reply[16:20], packet[12:16])
	copy(reply[20:22], packet[ipLen+2:ipLen+4])
	copy(reply[22:24], packet[ipLen:ipLen+2])
	binary.BigEndian.PutUint32(reply[24:28], 9000)
	binary.BigEndian.PutUint32(reply[28:32], binary.BigEndian.Uint32(packet[ipLen+4:ipLen+8])+1)
	reply[32], reply[33], reply[34], reply[35] = 0x50, 0x12, 0xff, 0xff
	checksum := func(b []byte) uint16 {
		var sum uint32
		for len(b) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(b))
			b = b[2:]
		}
		if len(b) > 0 {
			sum += uint32(b[0]) << 8
		}
		for sum > 0xffff {
			sum = (sum & 0xffff) + (sum >> 16)
		}
		return ^uint16(sum)
	}
	binary.BigEndian.PutUint16(reply[10:12], checksum(reply[:20]))
	pseudo := append([]byte{}, reply[12:20]...)
	pseudo = append(pseudo, 0, 6, 0, 20)
	pseudo = append(pseudo, reply[20:]...)
	binary.BigEndian.PutUint16(reply[36:38], checksum(pseudo))
	return reply
}

func TestCancelDuringTunneledTCPDial(t *testing.T) {
	for _, transport := range []Transport{HTTP2, QUIC} {
		for _, phase := range []string{"tcp-connect", "tls-handshake"} {
			t.Run(string(transport)+"/"+phase, func(t *testing.T) { testCancelTCPPhase(t, phase, transport) })
		}
	}
}

func testCancelTCPPhase(t *testing.T, phase string, transport Transport) {
	tcpStarted := make(chan struct{})
	var once sync.Once
	packetReply := func(packet []byte) []byte {
		if len(packet) > 40 && packet[0]>>4 == 4 && packet[9] == 6 {
			ipLen := int(packet[0]&15) * 4
			if phase == "tcp-connect" || len(packet) > ipLen+int(packet[ipLen+12]>>4)*4 {
				once.Do(func() { close(tcpStarted) })
			}
		}
		reply := dnsReply(packet)
		if phase == "tls-handshake" && reply == nil {
			reply = synAck(packet)
		}
		return reply
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		if transport == QUIC {
			stream := w.(http3.HTTPStreamer).HTTPStream()
			for {
				frame, err := stream.ReceiveDatagram(r.Context())
				if err != nil {
					return
				}
				id, n, err := quicvarint.Parse(frame)
				if err != nil || id != 0 {
					continue
				}
				if reply := packetReply(frame[n:]); reply != nil {
					if err := stream.SendDatagram(append([]byte{0}, reply...)); err != nil {
						return
					}
				}
			}
		}
		reader := quicvarint.NewReader(r.Body)
		for {
			typ, err := quicvarint.Read(reader)
			if err != nil {
				return
			}
			n, err := quicvarint.Read(reader)
			if err != nil || n > 65535 {
				return
			}
			packet := make([]byte, n)
			if _, err := io.ReadFull(reader, packet); err != nil {
				return
			}
			if typ != 0 {
				continue
			}
			reply := packetReply(packet)
			if reply != nil {
				frame := quicvarint.Append(nil, 0)
				frame = quicvarint.Append(frame, uint64(len(reply)))
				frame = append(frame, reply...)
				if _, err := w.Write(frame); err != nil {
					return
				}
				_ = http.NewResponseController(w).Flush()
			}
		}
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := engine.Probe(ctx, target); done <- err }()
	select {
	case <-tcpStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("test peer did not receive a TCP SYN")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled probe reported success")
		}
	case <-time.After(time.Second):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("probe stuck after cancellation:\n%s", buf[:n])
	}
}
