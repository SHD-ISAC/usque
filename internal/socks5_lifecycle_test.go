package internal

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/txthinking/socks5"
)

// This peer never replies. Control association closure must release the relay
// even with UDPTimeout=0; shortened idle deadlines are not the fix under test.
type silentUDPConn struct {
	closed      chan struct{}
	once        sync.Once
	writes      atomic.Int64
	readExit    <-chan struct{}
	readEntered chan struct{}
	readOnce    sync.Once
}

func newSilentUDPConn() *silentUDPConn {
	return &silentUDPConn{closed: make(chan struct{}), readEntered: make(chan struct{})}
}
func (c *silentUDPConn) Read([]byte) (int, error) {
	c.readOnce.Do(func() { close(c.readEntered) })
	<-c.closed
	if c.readExit != nil {
		<-c.readExit
	}
	return 0, net.ErrClosed
}
func (c *silentUDPConn) Write(p []byte) (int, error) { c.writes.Add(1); return len(p), nil }
func (c *silentUDPConn) Close() error                { c.once.Do(func() { close(c.closed) }); return nil }
func (c *silentUDPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
}
func (c *silentUDPConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 443}
}
func (c *silentUDPConn) SetDeadline(time.Time) error      { return nil }
func (c *silentUDPConn) SetReadDeadline(time.Time) error  { return nil }
func (c *silentUDPConn) SetWriteDeadline(time.Time) error { return nil }

func lifecycleServer(t *testing.T) *SOCKS5Server {
	t.Helper()
	originalTCP, originalUDP := socks5.DialTCP, socks5.DialUDP
	t.Cleanup(func() { socks5.DialTCP, socks5.DialUDP = originalTCP, originalUDP })
	s, err := NewSOCKS5Server(SOCKS5Config{Addr: "127.0.0.1:0", UDPTimeout: 0,
		Logger:  log.New(io.Discard, "", 0),
		DialTCP: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unused") },
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func waitLifecycle(t *testing.T, what string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(time.Millisecond)
	}
}

func lifecycleDatagram(port int) *socks5.Datagram {
	return socks5.NewDatagram(socks5.ATYPIPv4, []byte{203, 0, 113, 1}, []byte{byte(port >> 8), byte(port)}, []byte("client-initial"))
}

func controlAssociation(t *testing.T, s *SOCKS5Server) (net.Conn, *net.UDPAddr, <-chan error) {
	t.Helper()
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := l.AcceptTCP()
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		done <- s.TCPHandle(s.server, server, &socks5.Request{Ver: 5, Cmd: socks5.CmdUDP, Atyp: socks5.ATYPIPv4, DstAddr: []byte{0, 0, 0, 0}, DstPort: []byte{0, 0}})
	}()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	header := make([]byte, 10)
	if _, err := io.ReadFull(c, header); err != nil {
		c.Close()
		t.Fatal(err)
	}
	if header[0] != 5 || header[1] != 0 {
		c.Close()
		t.Fatalf("bad reply: %x", header)
	}
	a := c.LocalAddr().(*net.TCPAddr)
	src := &net.UDPAddr{IP: a.IP, Port: a.Port}
	waitLifecycle(t, "association not registered", func() bool { _, ok := s.server.AssociatedUDP.Get(src.String()); return ok })
	return c, src, done
}

func TestSOCKSUDPAssociationCloseReclaimsSilentRelays(t *testing.T) {
	s := lifecycleServer(t)
	var dials atomic.Int64
	socks5.DialUDP = func(string, string, string) (net.Conn, error) { dials.Add(1); return newSilentUDPConn(), nil }
	for cycle := 0; cycle < 5; cycle++ {
		c, src, done := controlAssociation(t, s)
		for n := 0; n < 64; n++ {
			if err := s.UDPHandle(s.server, src, lifecycleDatagram(10000+n)); err != nil {
				c.Close()
				t.Fatal(err)
			}
		}
		if len(udpRelaySem) != 64 {
			c.Close()
			t.Fatalf("slots=%d", len(udpRelaySem))
		}
		c.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("control closure blocked")
		}
		waitLifecycle(t, "silent relay slots were not released", func() bool { return len(udpRelaySem) == 0 })
		if s.server.UDPExchanges.ItemCount() != 0 {
			t.Fatal("closed association retained exchanges")
		}
		if err := s.UDPHandle(s.server, src, lifecycleDatagram(443)); err == nil {
			t.Fatal("closed source accepted")
		}
	}
	if dials.Load() != 320 {
		t.Fatalf("dials=%d", dials.Load())
	}
}

func TestSOCKSUDPBurstCreatesOneRelayPerDestination(t *testing.T) {
	s := lifecycleServer(t)
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40100}
	ch := make(chan byte)
	s.server.AssociatedUDP.Set(src.String(), ch, -1)
	gate, entered := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var dials atomic.Int64
	conn := newSilentUDPConn()
	socks5.DialUDP = func(string, string, string) (net.Conn, error) {
		dials.Add(1)
		once.Do(func() { close(entered) })
		<-gate
		return conn, nil
	}
	results := make(chan error, 64)
	for i := 0; i < 64; i++ {
		go func() { results <- s.UDPHandle(s.server, src, lifecycleDatagram(443)) }()
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("dial not entered")
	}
	time.Sleep(20 * time.Millisecond)
	close(gate)
	for i := 0; i < 64; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("burst blocked")
		}
	}
	if dials.Load() != 1 || conn.writes.Load() != 64 || len(udpRelaySem) != 1 {
		t.Fatalf("dials=%d writes=%d slots=%d", dials.Load(), conn.writes.Load(), len(udpRelaySem))
	}
	s.closeUDPAssociation(s.server, src.String(), ch)
	waitLifecycle(t, "burst slot not freed", func() bool { return len(udpRelaySem) == 0 })
}

func TestSOCKSUDPOldReaderCannotDeleteReplacement(t *testing.T) {
	s := lifecycleServer(t)
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40200}
	old, newer := newSilentUDPConn(), newSilentUDPConn()
	gate := make(chan struct{})
	old.readExit = gate
	var dials atomic.Int64
	socks5.DialUDP = func(string, string, string) (net.Conn, error) {
		if dials.Add(1) == 1 {
			return old, nil
		}
		return newer, nil
	}
	ch := make(chan byte)
	s.server.AssociatedUDP.Set(src.String(), ch, -1)
	if err := s.UDPHandle(s.server, src, lifecycleDatagram(443)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-old.readEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("old reader never entered Read")
	}
	s.closeUDPAssociation(s.server, src.String(), ch)
	ch2 := make(chan byte)
	s.server.AssociatedUDP.Set(src.String(), ch2, -1)
	if err := s.UDPHandle(s.server, src, lifecycleDatagram(443)); err != nil {
		t.Fatal(err)
	}
	close(gate)
	waitLifecycle(t, "old reader failed to exit", func() bool { return len(udpRelaySem) == 1 })
	value, ok := s.server.UDPExchanges.Get(src.String() + lifecycleDatagram(443).Address())
	if !ok || value.(*socks5.UDPExchange).RemoteConn != newer {
		t.Fatal("old reader removed new exchange")
	}
	s.closeUDPAssociation(s.server, src.String(), ch2)
	waitLifecycle(t, "replacement slot not freed", func() bool { return len(udpRelaySem) == 0 })
}
