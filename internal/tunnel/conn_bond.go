package tunnel

import (
    "context"
    "errors"
    "io"
    "net"
    "sync"
    "time"

    "github.com/SawaMEN/VetroffProxy/internal/bond"
)

// dialBond exposes the same stream semantics to direct SDK callers as SOCKS
// users. In particular, selecting Bond must never silently use the single-path
// HTTP transport. Ownership and cancellation mirror dialTunnel connections.
func (c *Client) dialBond(ctx context.Context, address string) (net.Conn, error) {
    lifetime, cancel := context.WithCancel(context.Background())
    stop := context.AfterFunc(ctx, cancel)
    carrier := c.bondClient
    var err error
    if c.bondDiscovery != nil {
        carrier, err = c.discoveredBond(ctx)
        if err != nil {
            stop()
            cancel()
            return nil, err
        }
    }
    stream, err := carrier.Open(lifetime, address)
    stopped := stop()
    if err != nil || !stopped || ctx.Err() != nil {
        if stream != nil { _ = stream.Close() }
        cancel()
        if ctx.Err() != nil { return nil, ctx.Err() }
        return nil, err
    }

    up, upPeer := net.Pipe()
    down, downPeer := net.Pipe()
    conn := &bondNetConn{
        up: up, down: down, upPeer: upPeer, downPeer: downPeer,
        stream: stream, cancel: cancel, remote: virtualAddr(address),
    }
    go func() {
        _, err := io.Copy(stream, upPeer)
        if err == nil {
            _ = stream.CloseWrite()
            _ = upPeer.Close()
        }
        conn.finished(err)
    }()
    go func() {
        _, err := io.Copy(downPeer, stream)
        if err == nil { _ = downPeer.Close() }
        conn.finished(err)
    }()
    return conn, nil
}

type bondNetConn struct {
    up, down, upPeer, downPeer net.Conn
    stream *bond.Stream
    cancel context.CancelFunc
    remote net.Addr
    once sync.Once
    finishedPumps int
    finishMutex sync.Mutex
    failure error
}

func (c *bondNetConn) Read(p []byte) (int, error) {
    n, err := c.down.Read(p)
    return n, c.transferError(err)
}
func (c *bondNetConn) Write(p []byte) (int, error) {
    n, err := c.up.Write(p)
    return n, c.transferError(err)
}
func (c *bondNetConn) LocalAddr() net.Addr { return virtualAddr("client") }
func (c *bondNetConn) RemoteAddr() net.Addr { return c.remote }
func (c *bondNetConn) SetReadDeadline(t time.Time) error { return c.down.SetReadDeadline(t) }
func (c *bondNetConn) SetWriteDeadline(t time.Time) error { return c.up.SetWriteDeadline(t) }
func (c *bondNetConn) SetDeadline(t time.Time) error {
    return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}
func (c *bondNetConn) CloseWrite() error { return c.up.Close() }
func (c *bondNetConn) Close() error {
    c.once.Do(func() {
        c.cancel()
        _ = c.up.Close()
        _ = c.down.Close()
        _ = c.upPeer.Close()
        _ = c.downPeer.Close()
        _ = c.stream.Close()
    })
    return nil
}
func (c *bondNetConn) finished(err error) {
    c.finishMutex.Lock()
    if err != nil && c.failure == nil { c.failure = err }
    c.finishedPumps++
    done := c.finishedPumps == 2
    c.finishMutex.Unlock()
    if err != nil {
        _ = c.Close()
    } else if done {
        _ = c.Close()
    }
}
func (c *bondNetConn) transferError(err error) error {
    if err == nil { return nil }
    if timeout, ok := err.(net.Error); ok && timeout.Timeout() { return err }
    c.finishMutex.Lock()
    defer c.finishMutex.Unlock()
    if c.failure != nil { return c.failure }
    return err
}
