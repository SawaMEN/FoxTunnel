package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/enginestatus"
	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

// handleUDPAssociate is opt-in, single-client UDP ASSOCIATE (RFC 1928).
// It is a bounded request/response relay, not general real-time UDP streaming.
func (c *Client) handleUDPAssociate(parent context.Context, control net.Conn) {
	if !c.EnableUDP || (c.UDPMultiNode && (!c.UDPStreaming || len(c.fallbackServers) < 1)) || c.bondClient != nil || c.bondDiscovery != nil {
		_ = socks5Reply(control, 7)
		return
	}
	local, ok := control.LocalAddr().(*net.TCPAddr)
	if !ok {
		_ = socks5Reply(control, 1)
		return
	}
	peer, ok := control.RemoteAddr().(*net.TCPAddr)
	if !ok {
		_ = socks5Reply(control, 1)
		return
	}
	family := "udp4"
	if local.IP.To4() == nil {
		family = "udp6"
	}
	socket, err := net.ListenUDP(family, &net.UDPAddr{IP: local.IP, Port: 0, Zone: local.Zone})
	if err != nil {
		_ = socks5Reply(control, 1)
		return
	}
	defer socket.Close()

	if err := replyUDPAssociate(control, socket.LocalAddr().(*net.UDPAddr)); err != nil {
		return
	}
	if c.UDPStreaming {
		c.handleUDPStream(parent, control, socket, peer)
		return
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = socket.Close(); _ = control.Close() })
	defer stop()
	go func() {
		_, _ = io.Copy(io.Discard, control) // RFC: lifetime is the TCP control connection
		cancel()
		_ = socket.Close()
	}()

	allowed, ok := netip.AddrFromSlice(peer.IP)
	if !ok {
		return
	}
	allowed = allowed.Unmap()
	var port int // First valid UDP datagram pins source port.
	slots := make(chan struct{}, 8)
	buf := make([]byte, udpproto.MaxDatagram+1)
	for {
		n, src, err := socket.ReadFromUDP(buf)
		if err != nil {
			return
		}
		ip, ok := netip.AddrFromSlice(src.IP)
		if !ok || ip.Unmap() != allowed || n > udpproto.MaxDatagram {
			continue
		}
		datagram, err := udpproto.Parse(buf[:n])
		if err != nil {
			continue
		}
		if port == 0 {
			port = src.Port
		}
		if src.Port != port {
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			c.status.Reject(enginestatus.UDPPendingCapacity)
			continue // Capacity bound: fail closed instead of unlimited goroutines.
		}
		owned := append([]byte(nil), buf[:n]...)
		source := *src
		go func() {
			defer func() { <-slots }()
			callCtx, done := context.WithTimeout(ctx, 5*time.Second)
			defer done()
			response, err := c.exchangeUDP(callCtx, owned)
			if err != nil || len(response) == 0 || ctx.Err() != nil {
				return
			}
			if reply, err := udpproto.Parse(response); err != nil || !udpReplyMatchesRequest(datagram, reply) {
				return
			}
			_, _ = socket.WriteToUDP(response, &source)
		}()
	}
}

// udpReplyMatchesRequest rejects a reply claiming an unrelated destination.
// The remote exit resolves DNS hostnames; DNS lookups must never run on the
// local UDP client. For a hostname request, the server's reply must name a
// numeric resolved address; for a literal address, it must match exactly
// (including IPv4-mapped IPv6 normalization).
func udpReplyMatchesRequest(request, reply udpproto.Packet) bool {
	if reply.Port != request.Port {
		return false
	}
	origin, err := netip.ParseAddr(reply.Host)
	if err != nil || origin.Zone() != "" || !origin.IsValid() {
		return false
	}
	if dest, err := netip.ParseAddr(request.Host); err == nil {
		return dest.Zone() == "" && dest.Unmap() == origin.Unmap()
	}
	return true // A DNS hostname is resolved by the authenticated exit.
}

func replyUDPAssociate(w net.Conn, a *net.UDPAddr) error {
	if a.Port < 1 || a.Port > 65535 {
		return errors.New("invalid UDP bind")
	}
	ip, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		return errors.New("invalid UDP bind IP")
	}
	ip = ip.Unmap()
	b := []byte{5, 0, 0}
	if ip.Is4() {
		b = append(b, 1)
	} else {
		b = append(b, 4)
	}
	b = append(b, ip.AsSlice()...)
	b = binary.BigEndian.AppendUint16(b, uint16(a.Port))
	_ = w.SetWriteDeadline(time.Now().Add(time.Second))
	_, err := w.Write(b)
	_ = w.SetWriteDeadline(time.Time{})
	return err
}

func (c *Client) exchangeUDP(ctx context.Context, wire []byte) (reply []byte, err error) {
	ticket := c.status.BeginOperation(enginestatus.UDPExchange)
	defer func() {
		reason := operationReason(err)
		if err == nil && len(reply) == 0 {
			reason = enginestatus.NoResponse
		}
		c.status.FinishOperation(ticket, reason)
	}()
	if c.managed != nil && !c.fullManagedHTTP() {
		reply, err = c.exchangeManagedUDP(ctx, wire)
		if err != nil || len(reply) == 0 {
			return reply, err
		}
		if _, err := udpproto.Parse(reply); err != nil {
			return nil, err
		}
		return reply, nil
	}
	u := *c.ServerURL
	u.Path = udpPath
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Proxy-Authorization", basicAuth(c.Username, c.Password))
	req.Header.Set("Content-Type", "application/octet-stream")
	c.requestProtocol(req, "udp-v1")
	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 && resp.ProtoMajor != 3 {
		return nil, errors.New("UDP relay requires H2/H3")
	}
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		if err := c.verifyProtocol(resp, "udp-v1"); err != nil {
			return nil, err
		}
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &UDPResponseError{HTTPStatus: resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, udpproto.MaxDatagram+1))
	if err != nil {
		return nil, err
	}
	if _, err := udpproto.Parse(data); err != nil {
		return nil, err
	}
	return data, nil
}
