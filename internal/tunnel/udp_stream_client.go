package tunnel

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/enginestatus"
	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

// udpStream is exactly one authenticated, full-duplex HTTP/2 or HTTP/3
// request per SOCKS5 UDP association. Closing its context terminates the
// server session. Neither redirects nor single-shot fallback are attempted.
type udpStream struct {
	response io.ReadCloser
	reader   *io.PipeReader
	once     sync.Once
	writer   *io.PipeWriter
	cancel   context.CancelFunc
}

func (s *udpStream) close() {
	s.once.Do(func() {
		s.cancel()
		_ = s.writer.Close()
		if s.reader != nil {
			_ = s.reader.Close()
		}
		_ = s.response.Close()
	})
}

func (c *Client) openUDPStream(parent context.Context) (*udpStream, error) {
	return c.openUDPStreamTo(parent, c.ServerURL)
}

// openUDPStreamTo never retries an established flow on a different exit.
// The caller supplies an explicitly trusted HTTPS origin.
func (c *Client) openUDPStreamTo(parent context.Context, endpoint *url.URL) (stream *udpStream, err error) {
	ticket := c.status.BeginOperation(enginestatus.UDPStreamSetup)
	defer func() { c.status.FinishOperation(ticket, operationReason(err)) }()
	if err := parent.Err(); err != nil {
		return nil, err
	}
	ctx, abort := context.WithCancelCause(parent)
	cancel := func() { abort(context.Canceled) }
	reader, writer := io.Pipe()
	var response *http.Response
	keep := false
	defer func() {
		if !keep {
			cancel()
			_ = writer.Close()
			_ = reader.Close()
			if response != nil && response.Body != nil {
				_ = response.Body.Close()
			}
		}
	}()
	u := *endpoint
	u.Path, u.RawPath, u.RawQuery, u.Fragment = udpStreamPath, "", "", ""
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Proxy-Authorization", basicAuth(c.Username, c.Password))
	req.Header.Set("Content-Type", "application/octet-stream")
	c.requestProtocol(req, "udp-stream-v2")
	budget := c.ConnectTimeout
	if budget <= 0 {
		budget = 15 * time.Second
	}
	timer := time.AfterFunc(budget, func() { abort(context.DeadlineExceeded) })
	response, err = c.transport.RoundTrip(req)
	timedOut := !timer.Stop()
	if timedOut || ctx.Err() != nil {
		if cause := context.Cause(ctx); cause != nil {
			return nil, cause
		}
		return nil, context.DeadlineExceeded
	}
	if err != nil {
		return nil, err
	}
	if (response.ProtoMajor != 2 && response.ProtoMajor != 3) || response.StatusCode != http.StatusOK {
		return nil, &UDPResponseError{HTTPStatus: response.StatusCode, Streaming: true}
	}
	if err := c.verifyProtocol(response, "udp-stream-v2"); err != nil {
		return nil, err
	}
	keep = true
	return &udpStream{response: response.Body, reader: reader, writer: writer, cancel: cancel}, nil
}

func (c *Client) handleUDPStream(parent context.Context, control net.Conn, socket *net.UDPConn, peer *net.TCPAddr) {
	if c.UDPMultiNode {
		c.handleUDPMultiNodeStream(parent, control, socket, peer)
		return
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = socket.Close(); _ = control.Close() })
	defer stop()
	go func() {
		_, _ = io.Copy(io.Discard, control)
		cancel()
	}()

	stream, err := c.openUDPStream(ctx)
	if err != nil {
		return // Fail closed. Never silently retry using an older wire contract.
	}
	defer stream.close()

	peerIP, ok := netip.AddrFromSlice(peer.IP)
	if !ok {
		return
	}
	peerIP = peerIP.Unmap()
	var source atomic.Pointer[net.UDPAddr]
	var permitted udpReplyGuard
	downloadDone := make(chan struct{})
	go func() {
		defer close(downloadDone)
		for {
			wire, err := udpproto.ReadFrame(stream.response)
			if err != nil {
				cancel()
				return
			}
			if !permitted.matches(wire) {
				continue // Never emit an unsolicited UDP destination.
			}
			dst := source.Load()
			if dst == nil || ctx.Err() != nil {
				continue
			}
			_ = socket.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if _, err := socket.WriteToUDP(wire, dst); err != nil {
				cancel()
				return
			}
		}
	}()
	defer func() {
		cancel()
		_ = socket.Close()
		stream.close()
		<-downloadDone
	}()

	buf := make([]byte, udpproto.MaxDatagram+1)
	for {
		n, src, err := socket.ReadFromUDP(buf)
		if err != nil {
			return
		}
		ip, ok := netip.AddrFromSlice(src.IP)
		if !ok || ip.Unmap() != peerIP || n > udpproto.MaxDatagram {
			continue
		}
		packet, err := udpproto.Parse(buf[:n])
		if err != nil {
			continue
		}
		pinned := source.Load()
		if pinned == nil {
			s := *src
			source.CompareAndSwap(nil, &s)
			pinned = source.Load()
		}
		if pinned.Port != src.Port || !pinned.IP.Equal(src.IP) {
			continue
		}
		permitted.remember(packet)
		if err := udpproto.WriteFrame(stream.writer, buf[:n]); err != nil {
			return
		}
	}
}
