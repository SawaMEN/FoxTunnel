package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type ManagedTransport interface {
	Ready(context.Context) error
	DialContext(context.Context, string, string) (net.Conn, error)
	Close() error
}

type managedTransport struct {
	sync.Mutex
	factory   func() (ManagedTransport, error)
	transport ManagedTransport
	closed    bool
}

// SetManagedTransport installs an owned native engine before concurrent use.
func (c *Client) SetManagedTransport(transport string, factory func() (ManagedTransport, error)) {
	c.nativeTransport = transport
	c.managed = &managedTransport{factory: factory}
}

func (c *Client) validateManaged() error {
	if c.managed == nil {
		return nil
	}
	if c.ConnectTimeout > 0 && c.ConnectTimeout < 100*time.Millisecond {
		return errors.New("Necko setup timeout must be at least 100ms")
	}
	if c.Padding || c.EnableUDP || c.UDPStreaming || c.UDPMultiNode || c.RequireProtocolNegotiation || len(c.fallbackServers) > 0 || c.bondClient != nil || c.bondDiscovery != nil || (c.balance != "" && c.balance != "failover") {
		return errors.New("Necko supports TCP CONNECT without padding, UDP, bond, balancing, fallback servers or draft negotiation")
	}
	return nil
}

// Prepare starts the owned native process and waits for readiness. Legacy
// transports need no process. Invoke after configuration, before serving.
func (c *Client) Prepare(ctx context.Context) error {
	if err := c.validateManaged(); err != nil {
		return err
	}
	if c.managed == nil {
		return nil
	}
	m := c.managed
	m.Lock()
	if m.closed {
		m.Unlock()
		return net.ErrClosed
	}
	if m.transport == nil {
		tr, err := m.factory()
		if err != nil {
			m.Unlock()
			return err
		}
		m.transport = tr
	}
	tr := m.transport
	m.Unlock()
	return tr.Ready(ctx)
}

func (c *Client) dialManaged(ctx context.Context, address string) (net.Conn, error) {
	if err := c.Prepare(ctx); err != nil {
		return nil, err
	}
	m := c.managed
	m.Lock()
	tr := m.transport
	closed := m.closed
	m.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	route := "h2"
	if c.nativeTransport == "h3-connect" {
		route = "h3"
	}
	c.status.Route(route, "explicit")
	return tr.DialContext(ctx, "tcp", address)
}

func (c *Client) relayManaged(ctx context.Context, local net.Conn, target string) {
	remote, err := c.dialManaged(ctx, target)
	if err != nil {
		socks5Reply(local, 5)
		return
	}
	defer remote.Close()
	if socks5Reply(local, 0) != nil {
		return
	}
	stop := context.AfterFunc(ctx, func() { local.Close(); remote.Close() })
	defer stop()
	done := make(chan struct{})
	abort := func() {
		if tcp, ok := local.(interface{ SetLinger(int) error }); ok {
			tcp.SetLinger(0)
		}
		local.Close()
		remote.Close()
	}
	copyHalf := func(dst, src net.Conn) {
		if _, err := io.Copy(dst, src); err != nil {
			abort()
			return
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			if cw.CloseWrite() != nil {
				abort()
			}
		} else {
			abort()
		}
	}
	go func() { defer close(done); copyHalf(remote, local) }()
	copyHalf(local, remote)
	<-done
}
