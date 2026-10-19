package access

import (
	"context"
	"io"
	"net"
	"sync"
)

// Dial counts destination sockets (including DNS/dial time), not HTTP carriers.
// The callback returns a raw socket; this wrapper preserves TCP half-close.
func Dial(ctx context.Context, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	g := from(ctx)
	if g == nil {
		return dial(ctx)
	}
	release, err := Hold(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := dial(ctx)
	if err != nil {
		release()
		return nil, err
	}
	w := &meteredConn{Conn: conn, g: g, release: release}
	stop := context.AfterFunc(g.ctx, func() { w.Close() })
	w.stopMu.Lock()
	if w.closed {
		stop()
	} else {
		w.stop = stop
	}
	w.stopMu.Unlock()
	// Install stop before publishing: cancellation may run immediately.
	return w, nil
}

type meteredConn struct {
	net.Conn
	g                       *grant
	release                 func()
	once                    sync.Once
	stop                    func() bool
	readMu, writeMu, stopMu sync.Mutex
	closed                  bool
}

func (w *meteredConn) Close() error {
	err := w.Conn.Close()
	w.once.Do(func() {
		w.stopMu.Lock()
		w.closed = true
		stop := w.stop
		w.stopMu.Unlock()
		if stop != nil {
			stop()
		}
		w.release()
	})
	return err
}
func (w *meteredConn) CloseWrite() error {
	if c, ok := w.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return nil
}
func (g *grant) reserve(n int) (int, error) {
	c := g.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	a := g.account
	if c.closed || c.failed || g.ctx.Err() != nil {
		return 0, ErrDenied
	}
	if n > 32<<10 {
		n = 32 << 10
	}
	if n == 0 {
		return 0, nil
	}
	quota := g.config.QuotaBytes
	remaining := int64(1<<62) - a.charged
	if quota > 0 {
		remaining = quota - a.charged
	}
	if a.available < int64(n) && remaining > 0 {
		add := min(reservation-a.available, remaining)
		a.charged += add
		if err := c.persist(); err != nil {
			return 0, err
		}
		a.available += add
	}
	allowed := a.available
	if quota > 0 {
		allowed = min(allowed, max(0, quota-(a.charged-a.available)))
	}
	n = int(min(int64(n), allowed))
	if n == 0 {
		if a.inflight == 0 {
			g.cancel()
		}
		return 0, ErrQuota
	}
	a.available -= int64(n)
	a.inflight += int64(n)
	return n, nil
}
func (g *grant) settle(reserved, n int) {
	c := g.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	a := g.account
	a.inflight -= int64(reserved)
	a.available += int64(reserved - n)
	a.used += int64(n)
	if g.config.QuotaBytes > 0 && a.charged-a.available >= g.config.QuotaBytes && a.inflight == 0 {
		g.cancel()
	}
}
func (w *meteredConn) Read(p []byte) (int, error) {
	w.readMu.Lock()
	defer w.readMu.Unlock()
	n, err := w.g.reserve(len(p))
	if err != nil {
		return 0, err
	}
	got, err := w.Conn.Read(p[:n])
	w.g.settle(n, got)
	return got, err
}
func (w *meteredConn) Write(p []byte) (int, error) {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		n, err := w.g.reserve(len(p))
		if err != nil {
			return total, err
		}
		sent, err := w.Conn.Write(p[:n])
		w.g.settle(n, sent)
		total += sent
		p = p[sent:]
		if err != nil {
			return total, err
		}
		if sent != n {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

// Hold reserves one output session, including setup. Call release exactly once.
func Hold(ctx context.Context) (func(), error) {
	g := from(ctx)
	if g == nil {
		return func() {}, nil
	}
	c := g.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.failed || g.ctx.Err() != nil {
		return nil, ErrDenied
	}
	if g.account.tunnels >= g.config.MaxTunnels {
		return nil, ErrLimited
	}
	g.account.tunnels++
	var once sync.Once
	return func() { once.Do(func() { c.mu.Lock(); g.account.tunnels--; c.mu.Unlock() }) }, nil
}

// ChargePacket atomically charges a complete IP envelope before TUN injection
// or stream delivery. IP mode meters headers as well as payload, without replay.
func ChargePacket(ctx context.Context, n int) error {
	if n < 20 || n > 1280 {
		return ErrQuota
	}
	g := from(ctx)
	if g == nil {
		return nil
	}
	allowed, err := g.reserve(n)
	if err != nil {
		return err
	}
	if allowed != n {
		g.settle(allowed, 0)
		return ErrQuota
	}
	g.settle(n, n)
	return nil
}
