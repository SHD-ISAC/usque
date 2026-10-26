package api

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// Like wireguard/netstack, a write can synchronously produce output on an
// unbuffered channel. A reader must remain alive during feedback injection.
type feedbackDevice struct {
	output    chan []byte
	closed    chan struct{}
	events    chan tun.Event
	once      sync.Once
	active    atomic.Int32
	maxActive atomic.Int32
	mtu       int
}

func newFeedbackDevice(t *testing.T) *feedbackDevice {
	t.Helper()
	d := &feedbackDevice{output: make(chan []byte), closed: make(chan struct{}), events: make(chan tun.Event), mtu: 1280}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func (d *feedbackDevice) File() *os.File            { return nil }
func (d *feedbackDevice) Name() (string, error)    { return "feedback-test", nil }
func (d *feedbackDevice) MTU() (int, error)        { return d.mtu, nil }
func (d *feedbackDevice) Events() <-chan tun.Event { return d.events }
func (d *feedbackDevice) BatchSize() int          { return 1 }
func (d *feedbackDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

func (d *feedbackDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	active := d.active.Add(1)
	defer d.active.Add(-1)
	for old := d.maxActive.Load(); active > old; old = d.maxActive.Load() {
		if d.maxActive.CompareAndSwap(old, active) {
			break
		}
	}
	select {
	case <-d.closed:
		return 0, io.EOF
	case packet := <-d.output:
		sizes[0] = copy(bufs[0][offset:], packet)
		return 1, nil
	}
}

func (d *feedbackDevice) Write(bufs [][]byte, offset int) (int, error) {
	for i, buf := range bufs {
		// Feedback causes a synchronous retransmission, as a TCP stack can do
		// while processing an ICMP Packet Too Big response.
		packet := append([]byte("retransmit:"), buf[offset:]...)
		select {
		case d.output <- packet:
		case <-d.closed:
			return i, io.EOF
		}
	}
	return len(bufs), nil
}

func waitFeedbackTest(t *testing.T, done <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal(message)
	}
}

func TestNetstackAdapterDrainsDuringFeedback(t *testing.T) {
	d := newFeedbackDevice(t)
	a := NewNetstackAdapter(d)
	first := make(chan struct{})
	go func() {
		_, _ = a.ReadPacket(make([]byte, 1280))
		close(first)
	}()
	d.output <- []byte("initial oversized TCP packet")
	waitFeedbackTest(t, first, "initial device read blocked")

	feedback := make(chan struct{})
	go func() {
		_ = a.WritePacket([]byte("packet-too-big"))
		close(feedback)
	}()
	// There is deliberately no consumer ReadPacket call during this wait.
	// The old adapter stalls here: its sole reader is injecting this feedback.
	waitFeedbackTest(t, feedback, "feedback injection blocked without an independent device reader")
	buf := make([]byte, 1280)
	n, err := a.ReadPacket(buf)
	if err != nil || string(buf[:n]) != "retransmit:packet-too-big" {
		t.Fatalf("retransmission = %q, error = %v", buf[:n], err)
	}
}

func TestNetstackAdapterDrainsWithNoConsumerAndFullQueue(t *testing.T) {
	d := newFeedbackDevice(t)
	a := NewNetstackAdapter(d)
	first := make(chan struct{})
	go func() {
		_, _ = a.ReadPacket(make([]byte, 1280))
		close(first)
	}()
	d.output <- []byte("start")
	waitFeedbackTest(t, first, "initial device read blocked")
	emitted := make(chan struct{})
	go func() {
		defer close(emitted)
		for i := 0; i < 512; i++ {
			select {
			case d.output <- []byte{byte(i)}:
			case <-d.closed:
				return
			}
		}
	}()
	waitFeedbackTest(t, emitted, "full queue parked a device writer")
}

func TestNetstackAdapterOwnsQueuedPacketsAndResetsPooledBufferSize(t *testing.T) {
	d := newFeedbackDevice(t)
	a := NewNetstackAdapter(d)
	for _, size := range []int{1000, 24, 1100, 32, 1200} {
		want := bytes.Repeat([]byte{byte(size)}, size)
		sent := make(chan struct{})
		go func() {
			d.output <- want
			close(sent)
		}()
		buf := make([]byte, 1280)
		n, err := a.ReadPacket(buf)
		if err != nil || !bytes.Equal(buf[:n], want) {
			t.Fatalf("size %d: got %d bytes, error %v", size, n, err)
		}
		waitFeedbackTest(t, sent, "device sender did not finish")
	}
	queued := make(chan struct{})
	go func() {
		defer close(queued)
		for i := 0; i < 32; i++ {
			d.output <- bytes.Repeat([]byte{byte(i)}, 64)
		}
	}()
	waitFeedbackTest(t, queued, "small packet burst did not queue")
	for i := 0; i < 32; i++ {
		buf := make([]byte, 1280)
		n, err := a.ReadPacket(buf)
		if err != nil || !bytes.Equal(buf[:n], bytes.Repeat([]byte{byte(i)}, 64)) {
			t.Fatalf("queued packet %d reused or reordered: size=%d error=%v", i, n, err)
		}
	}
}

func TestNetstackAdapterHasOneDeviceReaderAcrossConcurrentConsumers(t *testing.T) {
	d := newFeedbackDevice(t)
	a := NewNetstackAdapter(d)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = a.ReadPacket(make([]byte, 1280))
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for d.active.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	_ = d.Close()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	waitFeedbackTest(t, done, "device close did not release all consumers")
	if d.maxActive.Load() != 1 {
		t.Fatalf("concurrent device readers = %d, want 1", d.maxActive.Load())
	}
}

func TestNetstackAdapterRejectsShortBuffersAndPropagatesDeviceClose(t *testing.T) {
	d := newFeedbackDevice(t)
	a := NewNetstackAdapter(d)
	go func() { d.output <- bytes.Repeat([]byte{1}, 128) }()
	if _, err := a.ReadPacket(make([]byte, 4)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short read error = %v", err)
	}
	_ = d.Close()
	if _, err := a.ReadPacket(make([]byte, 1280)); !errors.Is(err, io.EOF) {
		t.Fatalf("closed device error = %v", err)
	}
}

func TestNetstackAdapterRejectsInvalidMTU(t *testing.T) {
	d := newFeedbackDevice(t)
	d.mtu = 0
	a := NewNetstackAdapter(d)
	if _, err := a.ReadPacket(make([]byte, 1280)); err == nil {
		t.Fatal("invalid device MTU was accepted")
	}
}
