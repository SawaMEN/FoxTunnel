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
	return dialMetered(ctx, dial, false)
}

// DialDatagram preserves packet boundaries when quota is nearly exhausted.
// A packet that does not fit is rejected in full, never forwarded as a prefix.
func DialDatagram(ctx context.Context, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	return dialMetered(ctx, dial, true)
}

func dialMetered(ctx context.Context, dial func(context.Context) (net.Conn, error), datagram bool) (net.Conn, error) {
	// A dial context often has a shorter deadline than the established
	// connection. Check it at admission and at hand-off; do not attach it as
	// a lifetime cancellation hook after a successful dial.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	g := from(ctx)
	if g == nil {
		return dial(ctx)
	}
	c := g.owner
	c.mu.Lock()
	a := g.account
	if c.closed || c.failed || g.ctx.Err() != nil {
		c.mu.Unlock()
		return nil, ErrDenied
	}
	if a.tunnels >= g.config.MaxTunnels {
		c.mu.Unlock()
		return nil, ErrLimited
	}
	a.tunnels++
	c.mu.Unlock()
	release := func() { c.mu.Lock(); a.tunnels--; c.mu.Unlock() }
	conn, err := dial(ctx)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		release()
		return nil, err
	}
	if conn == nil {
		release()
		return nil, ErrDenied
	}
	// A custom dialer may return a socket even after ctx cancellation or
	// a credential rotation. Never hand such a socket to the caller.
	c.mu.Lock()
	revoked := c.closed || c.failed || g.ctx.Err() != nil
	c.mu.Unlock()
	if revoked {
		_ = conn.Close()
		release()
		return nil, ErrDenied
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		release()
		return nil, err
	}
	w := &meteredConn{Conn: conn, g: g, release: release, datagram: datagram}
	stop := context.AfterFunc(g.ctx, func() { w.Close() })
	w.stopMu.Lock()
	if w.closed {
		stop()
	} else {
		w.stop = stop
	}
	w.stopMu.Unlock()
	// A revocation during installation can race the AfterFunc callback.
	// Explicit rejection prevents publishing a revoked socket in that gap.
	if g.ctx.Err() != nil {
		_ = w.Close()
		return nil, ErrDenied
	}
	if err := ctx.Err(); err != nil {
		_ = w.Close()
		return nil, err
	}
	return w, nil
}

type meteredConn struct {
	net.Conn
	datagram                bool
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
	return g.reserveBytes(n, false)
}

func (g *grant) reserveBytes(n int, exact bool) (int, error) {
	c := g.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	a := g.account
	if c.closed || c.failed || g.ctx.Err() != nil {
		return 0, ErrDenied
	}
	if !exact && n > 32<<10 {
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
	if exact && int64(n) > allowed {
		if allowed == 0 && a.inflight == 0 {
			g.cancel()
		}
		return 0, ErrQuota
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
	if w.datagram {
		// Read a complete packet before accounting its actual size. Reserving
		// the receive buffer size would reject small packets unnecessarily;
		// shrinking the buffer to remaining quota would silently truncate them.
		got, readErr := w.Conn.Read(p)
		n, err := w.g.reserveBytes(got, true)
		if err != nil {
			return 0, err
		}
		w.g.settle(n, got)
		return got, readErr
	}
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
	if w.datagram {
		n, err := w.g.reserveBytes(len(p), true)
		if err != nil {
			return 0, err
		}
		sent, err := w.Conn.Write(p)
		w.g.settle(n, sent)
		if err == nil && sent != len(p) {
			err = io.ErrShortWrite
		}
		return sent, err
	}
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
