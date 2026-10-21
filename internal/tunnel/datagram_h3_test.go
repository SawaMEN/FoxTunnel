package tunnel

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestStage4H3UDPNetworkChangePreservesExistingSession(t *testing.T) {
	c, _ := datagramFixture(t, "h3-post", "go")
	gate := startUDPGate(t, c.ServerURL.Host)
	defer gate.close()
	usePrimary(t, c, "https://"+gate.front.LocalAddr().String())
	if err := c.SetTLSBackend("go"); err != nil {
		t.Fatal(err)
	}
	target := startUDPEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	old, err := c.OpenUDP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	exchange := func(flow *UDPConn, text string) {
		t.Helper()
		if err := flow.Send(ctx, Datagram{Address: target.LocalAddr().String(), Payload: []byte(text)}); err != nil {
			t.Fatal(err)
		}
		if d, err := flow.Receive(ctx); err != nil || string(d.Payload) != text {
			t.Fatal("UDP path", text, err)
		}
	}
	exchange(old, "before")
	pool := c.transport.(*identityPool).base.(postTransport).tlsTransport.(*h3RecoveryTransport)
	pool.mu.Lock()
	generation := pool.current
	pool.mu.Unlock()
	gate.blockExisting()
	c.NotifyNetworkChange()
	pool.mu.Lock()
	retired := generation.retired && generation.refs > 0 && pool.current == nil
	pool.mu.Unlock()
	if !retired {
		t.Fatal("network signal did not retire old generation while keeping live body")
	}
	fresh, err := c.OpenUDP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	exchange(fresh, "new path")
	gate.unblock()
	exchange(old, "preserved")
	old.Close()
	pool.mu.Lock()
	_, held := pool.generations[generation]
	pool.mu.Unlock()
	if held {
		t.Fatal("closed UDP body retained old QUIC generation")
	}
}

type stage4LossyPacketConn struct {
	net.PacketConn
	reads   atomic.Uint64
	writes  atomic.Uint64
	dropped atomic.Uint64
}

func (c *stage4LossyPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, a, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, a, err
		}
		if c.reads.Add(1)%11 == 0 {
			c.dropped.Add(1)
			continue
		}
		return n, a, nil
	}
}
func (c *stage4LossyPacketConn) WriteTo(p []byte, a net.Addr) (int, error) {
	if c.writes.Add(1)%11 == 0 {
		c.dropped.Add(1)
		return len(p), nil
	}
	time.Sleep(2 * time.Millisecond)
	return c.PacketConn.WriteTo(p, a)
}

func TestStage4H3UDPLossAndDelay(t *testing.T) {
	c, s := datagramFixture(t, "h2-connect", "go")
	node := setupEndpoint(t, c, s)
	socket, err := net.ListenPacket("udp4", node.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	lossy := &stage4LossyPacketConn{PacketConn: socket}
	serverCtx, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan error, 1)
	go func() { done <- s.ServeHTTP3(serverCtx, lossy, node.TLS, 32) }()
	defer func() {
		stop()
		socket.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("lossy H3 server did not stop")
		}
	}()
	usePrimary(t, c, node.URL)
	if err = c.SetTransport("h3-post"); err != nil {
		t.Fatal(err)
	}
	c.ConnectTimeout = 4 * time.Second
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	var packets atomic.Int32
	go func() {
		var b [1500]byte
		for {
			n, peer, err := target.ReadFromUDP(b[:])
			if err != nil {
				return
			}
			packets.Add(1)
			_, _ = target.WriteToUDP(b[:n], peer)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	flow, err := c.OpenUDP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	for i := range 16 {
		payload := []byte{byte(i), 0xa5, 0x5a}
		if err = flow.Send(ctx, Datagram{Address: target.LocalAddr().String(), Payload: payload}); err != nil {
			t.Fatal(err)
		}
		reply, err := flow.Receive(ctx)
		if err != nil || len(reply.Payload) != 3 || reply.Payload[0] != byte(i) {
			t.Fatal("lossy H3 datagram", i, err)
		}
	}
	if lossy.dropped.Load() == 0 || packets.Load() != 16 {
		t.Fatal("loss not exercised or application packet replayed", lossy.dropped.Load(), packets.Load())
	}
}
