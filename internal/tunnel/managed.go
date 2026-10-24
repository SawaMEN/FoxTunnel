package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
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
	http      bool
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
	if c.fullManagedHTTP() {
		connect := c.nativeTransport == "h2-connect" || c.nativeTransport == "h3-connect"
		if connect && (c.Padding || c.RequireProtocolNegotiation) {
			return errors.New("Necko CONNECT does not forward extension headers; use h2-post or XHTTP for padding/strict negotiation")
		}
		return nil
	}
	if c.Padding || c.UDPStreaming || c.UDPMultiNode || c.RequireProtocolNegotiation || len(c.fallbackServers) > 0 || c.bondClient != nil || c.bondDiscovery != nil || (c.balance != "" && c.balance != "failover") {
		return errors.New("Necko supports TCP CONNECT and bounded UDP v1 without padding, UDP streaming, bond, balancing, fallback servers or draft negotiation")
	}
	if c.EnableUDP && c.nativeTransport != "h2-connect" {
		return errors.New("Necko native UDP v1 requires h2-connect; h3-connect UDP is not implemented")
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

// exchangeManagedUDP requires an authenticated Mozilla HTTP/2 IPC adapter.
// Absence of the feature is an error; never send credentials or packets
// through the legacy Go transport as an implicit fallback.
func (c *Client) exchangeManagedUDP(ctx context.Context, wire []byte) ([]byte, error) {
	if err := c.Prepare(ctx); err != nil {
		return nil, err
	}
	c.managed.Lock()
	transport, closed := c.managed.transport, c.managed.closed
	c.managed.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	exchange, ok := transport.(interface {
		ExchangeUDP(context.Context, []byte) ([]byte, error)
	})
	if !ok {
		return nil, errors.New("managed Necko transport cannot exchange UDP")
	}
	return exchange.ExchangeUDP(ctx, wire)
}

// managedUDPStream is the future Gecko streaming extension boundary.
// It does not introduce a Go HTTP fallback, and is intentionally inaccessible
// through normal UDPStreaming configuration until native Gecko implements it.
type managedUDPStream interface {
	OpenUDPStream(context.Context) (io.ReadWriteCloser, error)
}

func (c *Client) openManagedUDPStream(ctx context.Context, endpoint *url.URL) (*udpStream, error) {
	if c.managed == nil || endpoint == nil || endpoint.Scheme != "https" ||
		endpoint.Host != c.ServerURL.Host || c.nativeTransport != "h2-connect" {
		return nil, errors.New("Necko native UDP stream requires the configured H2 HTTPS origin")
	}
	if err := c.Prepare(ctx); err != nil {
		return nil, err
	}
	c.managed.Lock()
	tr, closed := c.managed.transport, c.managed.closed
	c.managed.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	bridge, ok := tr.(managedUDPStream)
	if !ok {
		return nil, errors.New("Necko does not yet provide a native UDP streaming channel")
	}
	stream, err := bridge.OpenUDPStream(ctx)
	if err != nil {
		return nil, err
	}
	if stream == nil {
		return nil, errors.New("native Necko UDP streaming channel is absent")
	}
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	return &udpStream{
		response: stream,
		writer:   stream,
		cancel: func() {
			stop()
			_ = stream.Close()
		},
	}, nil
}
