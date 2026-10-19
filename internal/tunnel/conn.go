package tunnel

import (
	"context"
	"errors"
	"github.com/SawaMEN/FoxTunnel/internal/ippacket"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DialContext opens a virtual TCP connection. ctx controls setup only; the
// caller owns the returned connection and must close it. Only network tcp is
// supported because address-family selection is performed at the remote exit.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, net.UnknownNetworkError(network)
	}
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 || host == "" || strings.ContainsAny(host, "/\\\r\n\t @?#") {
		return nil, errors.New("invalid TCP destination")
	}
	return c.dialMode(ctx, address, "")
}

// DialIP opens an explicitly negotiated, framed IP session. No TCP target dial.
func (c *Client) DialIP(ctx context.Context) (net.Conn, error) {
	if c.Padding || c.bondClient != nil || c.bondDiscovery != nil {
		return nil, errors.New("IP tunnel cannot use padding or bond")
	}
	return c.dialMode(ctx, ippacket.Authority, ippacket.Version)
}
func (c *Client) dialMode(ctx context.Context, address, mode string) (net.Conn, error) {
	lifetime, cancel := context.WithCancel(context.Background())
	stop := context.AfterFunc(ctx, cancel)
	stream, e := c.openTunnelMode(lifetime, address, mode)
	stopped := stop()
	if e != nil || !stopped || ctx.Err() != nil {
		if stream != nil {
			stream.close()
		}
		cancel()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, e
	}
	up, upPeer := net.Pipe()
	down, downPeer := net.Pipe()
	conn := &streamConn{up: up, down: down, upPeer: upPeer, downPeer: downPeer, stream: stream, cancel: cancel, remote: virtualAddr(address)}
	var upload io.Writer = stream.writer
	var download io.Reader = stream.response.Body
	if c.Padding {
		upload = newPaddingWriter(upload)
		download = newPaddingReader(download)
	}
	go func() {
		_, err := io.Copy(upload, upPeer)
		_ = stream.writer.CloseWithError(err)
		_ = upPeer.Close()
		conn.finished(err)
	}()
	go func() { _, err := io.Copy(downPeer, download); _ = downPeer.Close(); conn.finished(err) }()
	return conn, nil
}

type virtualAddr string

func (a virtualAddr) Network() string { return "foxtunnel" }
func (a virtualAddr) String() string  { return string(a) }

type streamConn struct {
	up, down, upPeer, downPeer net.Conn
	stream                     *openStream
	cancel                     context.CancelFunc
	remote                     net.Addr
	once                       sync.Once
	pumps                      atomic.Int32
}

func (c *streamConn) Read(b []byte) (int, error)         { return c.down.Read(b) }
func (c *streamConn) Write(b []byte) (int, error)        { return c.up.Write(b) }
func (c *streamConn) LocalAddr() net.Addr                { return virtualAddr("client") }
func (c *streamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.down.SetReadDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.up.SetWriteDeadline(t) }
func (c *streamConn) SetDeadline(t time.Time) error {
	a := c.SetReadDeadline(t)
	b := c.SetWriteDeadline(t)
	return errors.Join(a, b)
}
func (c *streamConn) CloseWrite() error { return c.up.Close() }
func (c *streamConn) Close() error {
	c.once.Do(func() {
		c.cancel()
		c.up.Close()
		c.down.Close()
		c.upPeer.Close()
		c.downPeer.Close()
		c.stream.close()
	})
	return nil
}
func (c *streamConn) finished(err error) {
	if err != nil {
		_ = c.Close()
		return
	}
	if c.pumps.Add(1) == 2 {
		c.cancel()
		c.stream.close()
	}
}
