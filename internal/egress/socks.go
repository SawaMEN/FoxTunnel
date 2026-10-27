// Package egress provides a fail-closed SOCKS5 exit for server payload traffic.
package egress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"time"
)

var errConfig = errors.New("invalid egress configuration: use socks5://[user:password@]numeric-IP:port and a numeric DNS IP:port")
var errProxy = errors.New("SOCKS5 egress negotiation failed")

// Proxy is immutable and safe for concurrent use. No destination or DNS socket
// falls back to a direct connection when the proxy is unavailable.
type Proxy struct{ address, username, password, dns string }

func numericAddress(s string) bool {
	a, err := netip.ParseAddrPort(s)
	return err == nil && a.Port() != 0 && a.Addr().Zone() == "" && !a.Addr().IsUnspecified() && !a.Addr().IsMulticast()
}

// New accepts an empty proxy to preserve direct mode. Proxy and DNS endpoints
// must be numeric, so bootstrap resolution cannot leak outside the cascade.
// DNS defaults to 1.1.1.1:53 over TCP through SOCKS5, never via the host resolver.
func New(raw, dns string) (*Proxy, error) {
	if raw == "" {
		if dns != "" {
			return nil, errConfig
		}
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "socks5" || u.Opaque != "" || !numericAddress(u.Host) || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errConfig
	}
	p := &Proxy{address: u.Host, dns: dns}
	if u.User != nil {
		var ok bool
		p.username = u.User.Username()
		p.password, ok = u.User.Password()
		if !ok || len(p.username) == 0 || len(p.username) > 255 || len(p.password) == 0 || len(p.password) > 255 {
			return nil, errConfig
		}
	}
	if p.dns == "" {
		p.dns = "1.1.1.1:53"
	}
	if !numericAddress(p.dns) {
		return nil, errConfig
	}
	return p, nil
}

func (p *Proxy) Resolver() *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) { return p.DialContext(ctx, "tcp", p.dns) }}
}

func addressBytes(address string) ([]byte, error) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || ap.Port() == 0 || ap.Addr().Zone() != "" {
		return nil, errProxy
	}
	ip := ap.Addr().Unmap()
	b := []byte{4}
	if ip.Is4() {
		b[0] = 1
	}
	b = append(b, ip.AsSlice()...)
	b = append(b, byte(ap.Port()>>8), byte(ap.Port()))
	return b, nil
}

func readAddress(r io.Reader) (netip.AddrPort, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return netip.AddrPort{}, err
	}
	n := 16
	if atyp[0] == 1 {
		n = 4
	} else if atyp[0] != 4 {
		return netip.AddrPort{}, errProxy
	}
	b := make([]byte, n+2)
	if _, err := io.ReadFull(r, b); err != nil {
		return netip.AddrPort{}, err
	}
	ip, _ := netip.AddrFromSlice(b[:n])
	return netip.AddrPortFrom(ip.Unmap(), uint16(b[n])<<8|uint16(b[n+1])), nil
}

func writeAll(c net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := c.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

// DialContext supports TCP CONNECT and connected UDP via UDP ASSOCIATE. The
// context controls setup; callers own connection lifetime after it returns.
func (p *Proxy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "udp" {
		return nil, errors.New("unsupported egress network")
	}
	target, err := addressBytes(address)
	if err != nil {
		return nil, err
	}
	c, err := (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", p.address)
	if err != nil {
		return nil, errors.New("SOCKS5 egress unavailable")
	}
	success := false
	defer func() {
		if !success {
			c.Close()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	cancelled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { c.Close(); close(cancelled) })
	defer func() {
		if stop != nil && !stop() {
			<-cancelled
		}
	}()
	method := byte(0)
	if p.username != "" {
		method = 2
	}
	if err = writeAll(c, []byte{5, 1, method}); err != nil {
		return nil, errProxy
	}
	var reply [2]byte
	if _, err = io.ReadFull(c, reply[:]); err != nil || reply != [2]byte{5, method} {
		return nil, errProxy
	}
	if method == 2 {
		auth := append([]byte{1, byte(len(p.username))}, []byte(p.username)...)
		auth = append(auth, byte(len(p.password)))
		auth = append(auth, []byte(p.password)...)
		if writeAll(c, auth) != nil {
			return nil, errProxy
		}
		if _, err = io.ReadFull(c, reply[:]); err != nil || reply != [2]byte{1, 0} {
			return nil, errProxy
		}
	}
	command := byte(1)
	requestTarget := target
	if network == "udp" {
		command = 3
		requestTarget = []byte{1, 0, 0, 0, 0, 0, 0}
	}
	if writeAll(c, append([]byte{5, command, 0}, requestTarget...)) != nil {
		return nil, errProxy
	}
	var header [3]byte
	if _, err = io.ReadFull(c, header[:]); err != nil || header != [3]byte{5, 0, 0} {
		return nil, errProxy
	}
	bound, err := readAddress(c)
	if err != nil {
		return nil, errProxy
	}
	if !stop() {
		<-cancelled
		return nil, ctx.Err()
	}
	stop = nil
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	c.SetDeadline(time.Time{})
	if network == "tcp" {
		success = true
		return c, nil
	}
	if bound.Addr().IsUnspecified() {
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		ip, e := netip.ParseAddr(host)
		if e != nil {
			return nil, errProxy
		}
		bound = netip.AddrPortFrom(ip.Unmap(), bound.Port())
	}
	if bound.Port() == 0 || bound.Addr().IsMulticast() {
		return nil, errProxy
	}
	udp, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(bound))
	if err != nil {
		return nil, errProxy
	}
	dest, _ := netip.ParseAddrPort(address)
	conn := &udpConn{UDPConn: udp, control: c, target: dest, header: append([]byte{0, 0, 0}, target...)}
	go func() { var b [1]byte; _, _ = c.Read(b[:]); conn.Close() }()
	success = true
	return conn, nil
}

type udpConn struct {
	*net.UDPConn
	control net.Conn
	target  netip.AddrPort
	header  []byte
	once    sync.Once
}

func (c *udpConn) Close() error {
	var err error
	c.once.Do(func() { err = c.UDPConn.Close(); c.control.Close() })
	return err
}
func (c *udpConn) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(c.target) }
func (c *udpConn) Write(b []byte) (int, error) {
	if len(b)+len(c.header) > 65507 {
		return 0, errors.New("SOCKS5 UDP datagram too large")
	}
	packet := append(append(make([]byte, 0, len(c.header)+len(b)), c.header...), b...)
	n, err := c.UDPConn.Write(packet)
	if err != nil {
		return 0, err
	}
	if n != len(packet) {
		return 0, io.ErrShortWrite
	}
	return len(b), nil
}

var udpReadBuffers = sync.Pool{New: func() any { return new([65535]byte) }}

func (c *udpConn) Read(b []byte) (int, error) {
	buffer := udpReadBuffers.Get().(*[65535]byte)
	defer udpReadBuffers.Put(buffer)
	packet := buffer[:]
	for {
		n, err := c.UDPConn.Read(packet)
		if err != nil {
			return 0, err
		}
		if n < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
			continue
		}
		size := 0
		switch packet[3] {
		case 1:
			size = 10
		case 4:
			size = 22
		default:
			continue
		}
		if n < size {
			continue
		}
		ip, _ := netip.AddrFromSlice(packet[4 : size-2])
		port := uint16(packet[size-2])<<8 | uint16(packet[size-1])
		if ip.Unmap() != c.target.Addr().Unmap() || port != c.target.Port() {
			continue
		}
		return copy(b, packet[size:n]), nil
	}
}
