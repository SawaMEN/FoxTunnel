package tunnel

import (
	"context"
	"errors"
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
	if c.managed != nil {
		return c.dialManaged(ctx, address)
	}
	lifetime, cancel := context.WithCancel(context.Background())
	stop := context.AfterFunc(ctx, cancel)
	stream, e := c.openTunnel(lifetime, address)
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
		_, err := fastCopy(upload, upPeer)
		if err != nil {
			conn.finished(err)
			return
		}
		_ = stream.writer.Close()
		_ = upPeer.Close()
		conn.finished(nil)
	}()
	go func() {
		_, err := fastCopy(downPeer, download)
		if err != nil {
			conn.finished(err)
			return
		}
		_ = downPeer.Close()
		conn.finished(nil)
	}()
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

	failureMu sync.Mutex
	failure   error
}

func (c *streamConn) Read(b []byte) (int, error) {
	n, err := c.down.Read(b)
	return n, c.streamError(err)
}
func (c *streamConn) Write(b []byte) (int, error) {
	n, err := c.up.Write(b)
	return n, c.streamError(err)
}
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
		// Publish the cause before closing either net.Pipe endpoint. Otherwise
		// a pending application Read can observe EOF instead of stream reset.
		c.failureMu.Lock()
		if c.failure == nil {
			c.failure = err
		}
		c.failureMu.Unlock()
		_ = c.Close()
		return
	}
	if c.pumps.Add(1) == 2 {
		c.cancel()
		c.stream.close()
	}
}

// Preserve application deadlines, but replace teardown-induced pipe errors
// with the original transport/decoder failure. A clean EOF stays a clean EOF.
func (c *streamConn) streamError(err error) error {
	if err == nil {
		return nil
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		return err
	}
	c.failureMu.Lock()
	defer c.failureMu.Unlock()
	if c.failure != nil {
		return c.failure
	}
	return err
}
