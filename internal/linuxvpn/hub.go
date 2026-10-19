// Package linuxvpn supplies an experimental kernel TUN VPN. Network policy
// installation is explicit; parsing and packet relay also run without privilege.
package linuxvpn

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"sync"

	"github.com/SawaMEN/FoxTunnel/internal/access"
	"github.com/SawaMEN/FoxTunnel/internal/ippacket"
)

var ErrConfig = errors.New("invalid VPN configuration")
var ErrNetwork = errors.New("VPN network operation failed")

type Device interface{ io.ReadWriteCloser }
type Peer struct {
	ID   string `json:"id"`
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
}

func (p Peer) Addresses() (netip.Addr, netip.Addr, error) {
	a, e := netip.ParseAddr(p.IPv4)
	b, f := netip.ParseAddr(p.IPv6)
	if e != nil || f != nil || !netip.MustParsePrefix("100.96.0.0/24").Contains(a) || a == netip.MustParseAddr("100.96.0.0") || a == netip.MustParseAddr("100.96.0.255") || !netip.MustParsePrefix("fd62:666f:78::/64").Contains(b) || b == netip.MustParseAddr("fd62:666f:78::") {
		return a, b, ErrConfig
	}
	return a, b, nil
}

type Hub struct {
	Peers map[string]Peer // Immutable while serving, bound to managed AccountID.
	Open  func(context.Context, Peer) (Device, error)
	// AllowPrivate is only for explicit private deployments and isolated tests.
	AllowPrivate bool
	mu           sync.Mutex
	active       map[string]bool
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := access.AccountID(r.Context())
	p, ok := h.Peers[id]
	if id == "" || !ok || h.Open == nil {
		http.NotFound(w, r)
		return
	}
	v4, v6, err := p.Addresses()
	if err != nil {
		http.Error(w, "IP service unavailable", 503)
		return
	}
	h.mu.Lock()
	if h.active == nil {
		h.active = map[string]bool{}
	}
	if h.active[id] {
		h.mu.Unlock()
		http.Error(w, "IP session busy", 409)
		return
	}
	h.active[id] = true
	h.mu.Unlock()
	defer func() { h.mu.Lock(); delete(h.active, id); h.mu.Unlock() }()
	release, err := access.Hold(r.Context())
	if err != nil {
		http.Error(w, "access limit reached", 429)
		return
	}
	defer release()
	device, err := h.Open(r.Context(), p)
	if err != nil {
		http.Error(w, "IP service unavailable", 503)
		return
	}
	defer device.Close()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stop := context.AfterFunc(ctx, func() { device.Close(); r.Body.Close() })
	defer stop()
	w.Header().Set(ippacket.Header, ippacket.Version)
	w.WriteHeader(200)
	controller := http.NewResponseController(w)
	if controller.Flush() != nil {
		return
	}
	stream := &ippacket.Stream{Reader: r.Body, Writer: flushWriter{w, controller}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		var packet [ippacket.MTU]byte
		for {
			n, err := stream.ReadPacket(packet[:])
			if err != nil {
				return
			}
			src, dst, err := ippacket.Addresses(packet[:n])
			if err != nil || (src != v4 && src != v6) || (!h.AllowPrivate && !ippacket.Public(dst)) {
				return
			}
			if err = access.ChargePacket(ctx, n); err != nil {
				return
			}
			if wrote, err := device.Write(packet[:n]); err != nil || wrote != n {
				return
			}
		}
	}()
	var packet [ippacket.MTU + 1]byte
	for {
		n, err := device.Read(packet[:])
		if err != nil {
			break
		}
		src, dst, err := ippacket.Addresses(packet[:n])
		if err != nil || (dst != v4 && dst != v6) || (!h.AllowPrivate && !ippacket.Public(src)) {
			break
		}
		if access.ChargePacket(ctx, n) != nil || stream.WritePacket(packet[:n]) != nil {
			break
		}
	}
	cancel()
	device.Close()
	r.Body.Close()
	<-done
}

type flushWriter struct {
	io.Writer
	c *http.ResponseController
}

func (w flushWriter) Write(p []byte) (int, error) {
	n, e := w.Writer.Write(p)
	if e == nil {
		e = w.c.Flush()
	}
	return n, e
}
