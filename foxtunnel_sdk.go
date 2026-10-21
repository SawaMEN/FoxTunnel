package foxtunnel

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/buildinfo"
)

// SDKSchema versions the exported integration semantics, independently of the
// wire draft and release tag. Schema 1 is experimental: pin a tested commit.
const SDKSchema = buildinfo.SDKSchema

// BuildInfo identifies the actual linked backends; it does not probe a server.
type BuildInfo = buildinfo.Info

func RuntimeInfo() BuildInfo { return buildinfo.Current() }

// ClientSnapshot contains local aggregate counts only, without target addresses,
// credentials, node hostnames, request contents or arbitrary error messages.
type ClientSnapshot struct {
	Schema         int             `json:"schema"`
	Closed         bool            `json:"closed"`
	Pending        int             `json:"pending"`
	TCPConnections int             `json:"tcp_connections"`
	UDPConnections int             `json:"udp_connections"`
	SOCKSListeners int             `json:"socks_listeners"`
	Limit          int             `json:"limit"`
	Transport      TransportStatus `json:"transport"`
}

func (c *Client) Snapshot() ClientSnapshot {
	c.mu.Lock()
	s := ClientSnapshot{Schema: SDKSchema, Closed: c.closed, Pending: c.pending,
		TCPConnections: len(c.conns), UDPConnections: len(c.udpConns),
		SOCKSListeners: len(c.listeners), Limit: c.limit}
	c.mu.Unlock()
	s.Transport = c.Status()
	return s
}

// StatusEvent is a sampled state, not a reliable operation or traffic log.
// Sequence gaps mean an unread sample was replaced. The final closed snapshot
// may still contain operations which are unwinding after Close started.
type StatusEvent struct {
	Schema   int            `json:"schema"`
	Sequence uint64         `json:"sequence"`
	Snapshot ClientSnapshot `json:"snapshot"`
}

// WatchStatus emits an initial snapshot, then samples at interval (100ms–1h).
// One buffered value per watcher bounds memory; slow readers never block traffic.
// Cancel ctx to release a watcher. Client.Close publishes a closed snapshot and
// closes the channel. Caller cancellation just closes the channel.
func (c *Client) WatchStatus(ctx context.Context, interval time.Duration) (<-chan StatusEvent, error) {
	if interval < 100*time.Millisecond || interval > time.Hour {
		return nil, errors.New("status interval must be 100ms through 1h")
	}
	out := make(chan StatusEvent, 1)
	go func() {
		defer close(out)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		var seq uint64
		publish := func() bool {
			s := c.Snapshot()
			seq++
			event := StatusEvent{Schema: SDKSchema, Sequence: seq, Snapshot: s}
			select {
			case <-out:
			default:
			}
			out <- event // sole sender; channel always has one free slot
			return s.Closed
		}
		if ctx.Err() != nil {
			return
		}
		if publish() {
			return
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.ctx.Done():
				publish()
				return
			case <-ticker.C:
				if publish() {
					return
				}
			}
		}
	}()
	return out, nil
}

// ServeSOCKSContext takes ownership of listener. Canceling ctx stops this SOCKS
// service and its accepted connections; other SDK connections remain usable.
// Canceling a DialContext only cancels setup, not an established TCP stream.
func (c *Client) ServeSOCKSContext(ctx context.Context, listener net.Listener) error {
	return c.serveSOCKS(ctx, listener)
}
