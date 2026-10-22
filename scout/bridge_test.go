package scout

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type drainDevice struct {
	packets chan []byte
	closed  chan struct{}
}

func (d *drainDevice) ReadPacket(buf []byte) (int, error) {
	p, ok := <-d.packets
	if !ok {
		return 0, io.EOF
	}
	return copy(buf, p), nil
}

func (d *drainDevice) WritePacket([]byte) error {
	// Incoming ICMP/TCP can synchronously cause another outgoing packet.
	d.packets <- []byte("ack")
	return nil
}

func (d *drainDevice) Close() error {
	// Model a stack shutdown that emits final packets before it releases
	// the locks needed to finish closing the NIC. A cancelled reader that
	// exits early would leave this Close parked on its very first send.
	for range 32 {
		d.packets <- []byte("final packet")
	}
	close(d.packets)
	close(d.closed)
	return nil
}

type testPackets struct {
	closed  chan struct{}
	once    sync.Once
	writes  atomic.Int32
	onWrite func(int32) ([]byte, error)
}

func (p *testPackets) ReadPacket([]byte, bool) (int, error) { <-p.closed; return 0, io.EOF }
func (p *testPackets) WritePacket([]byte) ([]byte, error) {
	n := p.writes.Add(1)
	if p.onWrite != nil {
		return p.onWrite(n)
	}
	return nil, nil
}
func (p *testPackets) Close() error { p.once.Do(func() { close(p.closed) }); return nil }

func TestBridgeDrainsDeviceDuringClose(t *testing.T) {
	d := &drainDevice{packets: make(chan []byte), closed: make(chan struct{})}
	p := &testPackets{closed: make(chan struct{})}
	s := &session{packets: p, close: func() { _ = p.Close() }}
	b := startPacketBridge(context.Background(), s, d, d.Close)
	b.cancel(context.Canceled)
	done := make(chan struct{})
	go func() { b.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closing stack blocked after its outgoing reader stopped")
	}
	select {
	case <-d.closed:
	default:
		t.Fatal("device was not closed")
	}
	if n := p.writes.Load(); n != 0 {
		t.Fatalf("forwarded %d packets after cancellation", n)
	}
}

func TestBridgeCanDrainWhileNetworkWriterIsBlocked(t *testing.T) {
	d := &drainDevice{packets: make(chan []byte), closed: make(chan struct{})}
	p := &testPackets{closed: make(chan struct{})}
	started := make(chan struct{})
	p.onWrite = func(int32) ([]byte, error) { close(started); <-p.closed; return nil, io.EOF }
	s := &session{packets: p, close: func() { _ = p.Close() }}
	b := startPacketBridge(context.Background(), s, d, d.Close)
	d.packets <- []byte("request")
	<-started
	done := make(chan struct{})
	go func() { b.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("network writer prevented device drain during close")
	}
}

func TestBridgeKeepsReaderIndependentOfICMPInjection(t *testing.T) {
	d := &drainDevice{packets: make(chan []byte), closed: make(chan struct{})}
	p := &testPackets{closed: make(chan struct{})}
	ack := make(chan struct{})
	p.onWrite = func(n int32) ([]byte, error) {
		if n == 1 {
			return []byte("icmp too large"), nil
		}
		if n == 2 {
			close(ack)
		}
		return nil, nil
	}
	s := &session{packets: p, close: func() { _ = p.Close() }}
	b := startPacketBridge(context.Background(), s, d, d.Close)
	defer b.Close()
	d.packets <- []byte("request")
	select {
	case <-ack:
	case <-time.After(time.Second):
		t.Fatal("ICMP injection blocked waiting for its own outgoing reader")
	}
}
