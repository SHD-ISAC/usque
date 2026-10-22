package scout

import (
	"context"
	"fmt"
	"sync"

	"github.com/Diniboy1123/usque/api"
)

// packetBridge keeps the userspace device's outbound reader alive until the
// device is closed. wireguard/netstack's WriteNotify sends to an unbuffered
// channel: stopping that reader on cancellation can park a final TCP ACK/FIN
// writer while device.Close waits for that writer's network-stack locks.
type packetBridge struct {
	ctx             context.Context
	cancel          context.CancelCauseFunc
	session         *session
	device          api.TunnelDevice
	closeDevice     func() error
	readDone        chan struct{}
	outDone         chan struct{}
	inDone          chan struct{}
	outboundPackets chan []byte
	writes          sync.Mutex
	once            sync.Once
}

func startPacketBridge(parent context.Context, s *session, device api.TunnelDevice, closeDevice func() error) *packetBridge {
	ctx, cancel := context.WithCancelCause(parent)
	b := &packetBridge{ctx: ctx, cancel: cancel, session: s, device: device, closeDevice: closeDevice, readDone: make(chan struct{}), outDone: make(chan struct{}), inDone: make(chan struct{}), outboundPackets: make(chan []byte, 8)}
	go b.readDevice()
	go b.outbound()
	go b.inbound()
	return b
}

func (b *packetBridge) writeDevice(packet []byte) error {
	b.writes.Lock()
	defer b.writes.Unlock()
	if b.ctx.Err() != nil {
		return b.ctx.Err()
	}
	return b.device.WritePacket(packet)
}

func (b *packetBridge) readDevice() {
	defer close(b.readDone)
	defer close(b.outboundPackets)
	buf := make([]byte, 65535)
	for {
		n, err := b.device.ReadPacket(buf)
		if err != nil {
			b.cancel(fmt.Errorf("read userspace interface: %w", err))
			return
		}
		// Continue draining even after a network error or cancellation. Discard
		// packets until device.Close closes its output channel, rather than
		// abandoning a stack writer that is still trying to emit a packet.
		if b.ctx.Err() != nil {
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		select {
		case b.outboundPackets <- packet:
		case <-b.ctx.Done():
		}
	}
}

func (b *packetBridge) outbound() {
	defer close(b.outDone)
	for {
		var packet []byte
		select {
		case <-b.ctx.Done():
			return
		case p, ok := <-b.outboundPackets:
			if !ok {
				return
			}
			packet = p
		}
		if b.ctx.Err() != nil {
			return
		}
		icmp, err := b.session.packets.WritePacket(packet)
		if err != nil {
			b.cancel(fmt.Errorf("write tunnel packet: %w", err))
			continue
		}
		if len(icmp) > 0 {
			if err := b.writeDevice(icmp); err != nil {
				b.cancel(err)
			}
		}
	}
}

func (b *packetBridge) inbound() {
	defer close(b.inDone)
	buf := make([]byte, 65535)
	for b.ctx.Err() == nil {
		n, err := b.session.packets.ReadPacket(buf, true)
		if err != nil {
			b.cancel(fmt.Errorf("read tunnel packet: %w", err))
			return
		}
		if err := b.writeDevice(buf[:n]); err != nil {
			b.cancel(err)
			return
		}
	}
}

func (b *packetBridge) Close() {
	b.once.Do(func() {
		b.cancel(context.Canceled)
		b.session.Close() // release any blocked network read/write first
		<-b.inDone        // no incoming injection may race with device.Close
		<-b.outDone       // likewise for ICMP feedback from the network writer
		b.writes.Lock()
		_ = b.closeDevice() // outbound keeps draining until this has returned
		b.writes.Unlock()
		<-b.readDone
	})
}
