package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/access"
	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

// A deliberately bounded one-request/one-response UDP relay. It does not
// claim connectionless streaming semantics, NAT mapping, or UDP-over-QUIC.
const udpPath = "/.well-known/foxtunnel-udp-v1"

func (s *Server) serveUDP(w http.ResponseWriter, r *http.Request) {
	if !s.acquireTunnel() {
		http.Error(w, "server busy", http.StatusServiceUnavailable)
		return
	}
	defer s.activeTunnels.Add(-1)

	data, err := io.ReadAll(io.LimitReader(r.Body, udpproto.MaxDatagram+1))
	if err != nil { http.Error(w, "invalid datagram", http.StatusBadRequest); return }
	if len(data) > udpproto.MaxDatagram {
		http.Error(w, "datagram too large", http.StatusRequestEntityTooLarge)
		return
	}
	packet, err := udpproto.Parse(data)
	if err != nil {
		http.Error(w, "invalid datagram", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), min(s.timeout(), 3*time.Second))
	defer cancel()
	ip, err := s.resolveUDP(ctx, packet.Host)
	if err != nil {
		http.Error(w, "destination unavailable", http.StatusBadGateway)
		return
	}
	dest := net.JoinHostPort(ip.String(), strconv.Itoa(int(packet.Port)))
	conn, err := access.Dial(ctx, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", dest)
	})
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, access.ErrLimited) || errors.Is(err, access.ErrQuota) { status = http.StatusTooManyRequests }
		http.Error(w, "destination unavailable", status)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(min(s.timeout(), 3*time.Second)))
	if _, err := conn.Write(packet.Data); err != nil {
		http.Error(w, "datagram send failed", http.StatusBadGateway)
		return
	}
	response := make([]byte, udpproto.MaxDatagram)
	n, err := conn.Read(response)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "datagram read failed", http.StatusBadGateway)
		return
	}
	payload, err := udpproto.Encode(udpproto.Packet{Host:ip.String(),Port:packet.Port,Data:response[:n]})
	if err != nil {
		http.Error(w, "datagram response too large", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func (s *Server) resolveUDP(ctx context.Context, host string) (netip.Addr, error) {
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		if host == "" || strings.ContainsAny(host, "/\\\x00\r\n\t @?#") {
			return netip.Addr{}, errors.New("invalid UDP target")
		}
		resolver := s.Resolver
		if resolver == nil { resolver = net.DefaultResolver }
		var err error
		addrs, err = resolver.LookupNetIP(ctx, "ip", host)
		if err != nil { return netip.Addr{}, err }
	}
	for _, ip := range addrs {
		ip = ip.Unmap()
		if s.AllowPrivate || safePublicIP(ip) { return ip, nil }
	}
	return netip.Addr{}, errors.New("UDP destination prohibited")
}
