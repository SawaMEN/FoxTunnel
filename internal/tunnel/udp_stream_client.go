package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

// udpStream is exactly one authenticated, full-duplex HTTP/2 or HTTP/3
// request per SOCKS5 UDP association. Closing its context terminates the
// server session. Neither redirects nor single-shot fallback are attempted.
type udpStream struct {
	response io.ReadCloser
	writer   *io.PipeWriter
	cancel   context.CancelFunc
}

func (s *udpStream) close() {
	s.cancel()
	_ = s.writer.Close()
	_ = s.response.Close()
}

func (c *Client) openUDPStream(parent context.Context) (*udpStream, error) {
	ctx, cancel := context.WithCancel(parent)
	reader, writer := io.Pipe()
	u := *c.ServerURL
	u.Path, u.RawPath, u.RawQuery, u.Fragment = udpStreamPath, "", "", ""
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), reader)
	if err != nil {
		reader.Close()
		writer.Close()
		cancel()
		return nil, err
	}
	req.Header.Set("Proxy-Authorization", basicAuth(c.Username, c.Password))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		reader.Close()
		writer.Close()
		cancel()
		return nil, err
	}
	if (resp.ProtoMajor != 2 && resp.ProtoMajor != 3) || resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		reader.Close()
		writer.Close()
		cancel()
		return nil, errors.New("UDP streaming endpoint refused (no downgrade to one-shot)")
	}
	return &udpStream{response: resp.Body, writer: writer, cancel: cancel}, nil
}

func (c *Client) handleUDPStream(parent context.Context, control net.Conn, socket *net.UDPConn, peer *net.TCPAddr) {
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
	if !ok { return }
	peerIP = peerIP.Unmap()
	var source atomic.Pointer[net.UDPAddr]
	downloadDone := make(chan struct{})
	go func() {
		defer close(downloadDone)
		for {
			wire, err := udpproto.ReadFrame(stream.response)
			if err != nil {
				cancel()
				return
			}
			dst := source.Load()
			if dst == nil || ctx.Err() != nil { continue }
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
		if err != nil { return }
		ip, ok := netip.AddrFromSlice(src.IP)
		if !ok || ip.Unmap() != peerIP || n > udpproto.MaxDatagram { continue }
		if _, err := udpproto.Parse(buf[:n]); err != nil { continue }
		pinned := source.Load()
		if pinned == nil {
			s := *src
			source.CompareAndSwap(nil, &s)
			pinned = source.Load()
		}
		if pinned.Port != src.Port || !pinned.IP.Equal(src.IP) { continue }
		if err := udpproto.WriteFrame(stream.writer, buf[:n]); err != nil {
			return
		}
	}
}
