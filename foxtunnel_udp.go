package foxtunnel

import (
	"context"
	"net"
	"sync"

	"github.com/SawaMEN/FoxTunnel/internal/enginestatus"
	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
)

type Datagram = tunnel.Datagram

const MaxUDPDatagram = tunnel.MaxUDPDatagram

var ErrUDPDisabled = tunnel.ErrUDPDisabled
var ErrUDPNoResponse = tunnel.ErrUDPNoResponse

// UDPConn provides streaming v2 Send/Receive without a local SOCKS process.
// Close it after use. Client.Close also closes it and cancels pending setup.
type UDPConn struct {
	core   *tunnel.UDPConn
	owner  *Client
	cancel context.CancelFunc
	stop   func() bool
	once   sync.Once
}

func (c *Client) reserveUDP() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if c.pending+len(c.conns)+len(c.udpConns) >= c.limit {
		c.core.RecordRejection(enginestatus.SDKCapacity)
		return ErrCapacity
	}
	c.pending++
	return nil
}

// ExchangeUDP uses one-shot v1. EnableUDP is required. Addresses are resolved
// by the exit, not locally. No automatic resend occurs on timeout or failure.
func (c *Client) ExchangeUDP(ctx context.Context, d Datagram) (Datagram, error) {
	if err := c.reserveUDP(); err != nil {
		return Datagram{}, err
	}
	call, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	reply, err := c.core.ExchangeUDP(call, d)
	stop()
	cancel()
	c.mu.Lock()
	c.pending--
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return Datagram{}, net.ErrClosed
	}
	return reply, err
}

// OpenUDP explicitly selects a streaming v2 association. EnableUDP is required;
// UDPStreaming controls the SOCKS adapter only. ctx owns the association lifetime.
func (c *Client) OpenUDP(ctx context.Context) (*UDPConn, error) {
	if err := c.reserveUDP(); err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	raw, err := c.core.OpenUDP(lifetime)
	c.mu.Lock()
	c.pending--
	closed := c.closed
	if err == nil && !closed {
		conn := &UDPConn{core: raw, owner: c, cancel: cancel, stop: stop}
		c.udpConns[conn] = struct{}{}
		c.mu.Unlock()
		return conn, nil
	}
	c.mu.Unlock()
	stop()
	cancel()
	if raw != nil {
		raw.Close()
	}
	if closed {
		return nil, net.ErrClosed
	}
	return nil, err
}

func (u *UDPConn) Send(ctx context.Context, d Datagram) error    { return u.core.Send(ctx, d) }
func (u *UDPConn) Receive(ctx context.Context) (Datagram, error) { return u.core.Receive(ctx) }
func (u *UDPConn) Close() error {
	u.once.Do(func() {
		u.stop()
		u.cancel()
		u.core.Close()
		u.owner.mu.Lock()
		delete(u.owner.udpConns, u)
		u.owner.mu.Unlock()
	})
	return nil
}
