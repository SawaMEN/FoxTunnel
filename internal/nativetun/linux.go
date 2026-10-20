//go:build linux

// Package nativetun connects a Linux TUN device to the FoxTunnel SOCKS5
// listener using an in-process gVisor TCP/IP stack. It intentionally DOES NOT
// change system routes, resolvers, or firewall policies.
package nativetun

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	tuntap "github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	maxActiveTCP   = 256
	maxActiveUDP   = 128
	udpIdle        = 30 * time.Second
	connectTimeout = 8 * time.Second
)

var interfaceName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$`)

type Options struct {
	Name  string
	MTU   uint32
	SOCKS string
}

func Validate(o Options) error {
	if !interfaceName.MatchString(o.Name) || o.Name == "lo" {
		return errors.New("TUN name must be a safe Linux interface name (<=15 chars, not lo)")
	}
	if o.MTU < 1280 || o.MTU > 9000 {
		return errors.New("TUN MTU must be 1280-9000")
	}
	host, port, err := net.SplitHostPort(o.SOCKS)
	if err != nil {
		return fmt.Errorf("SOCKS listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("SOCKS endpoint must be numeric loopback IP")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("SOCKS port must be 1-65535")
	}
	return nil
}

type Runner struct {
	device  interface{ Close() }
	ip      *stack.Stack
	cancel  context.CancelFunc
	handler *forwarder
	once    sync.Once
}

func (r *Runner) Close() {
	r.once.Do(func() {
		r.cancel()
		r.device.Close()
		r.ip.Close()
		r.ip.Wait()
	})
}

// Start opens /dev/net/tun and installs IPv4, IPv6, TCP and UDP forwarding
// directly in this process. It does NOT execute iproute2 or nftables commands.
func Start(ctx context.Context, o Options) (*Runner, error) {
	if err := Validate(o); err != nil {
		return nil, err
	}
	dev, err := tuntap.Open(o.Name, o.MTU)
	if err != nil {
		return nil, fmt.Errorf("open TUN: %w", err)
	}
	inner, cancel := context.WithCancel(ctx)
	handler := &forwarder{ctx: inner, socks: o.SOCKS, tcpSlots: make(chan struct{}, maxActiveTCP), udpSlots: make(chan struct{}, maxActiveUDP)}
	ip, err := core.CreateStack(&core.Config{LinkEndpoint: dev, TransportHandler: handler})
	if err != nil {
		cancel()
		dev.Close()
		return nil, fmt.Errorf("initialize native TCP/IP stack: %w", err)
	}
	run := &Runner{device: dev, ip: ip, cancel: cancel, handler: handler}
	context.AfterFunc(inner, run.Close)
	return run, nil
}

type forwarder struct {
	ctx      context.Context
	socks    string
	tcpSlots chan struct{}
	udpSlots chan struct{}
}

func acquire(ch chan struct{}) bool {
	select {
	case ch <- struct{}{}:
		return true
	default:
		return false
	}
}
func release(ch chan struct{}) { <-ch }

func (f *forwarder) HandleTCP(conn adapter.TCPConn) {
	if !acquire(f.tcpSlots) {
		conn.Close()
		return
	}
	go func() {
		defer release(f.tcpSlots)
		defer conn.Close()
		id := conn.ID()
		host := net.IP(id.LocalAddress.AsSlice())
		if host == nil {
			return
		}
		dst := net.JoinHostPort(host.String(), strconv.Itoa(int(id.LocalPort)))
		ctx, cancel := context.WithTimeout(f.ctx, connectTimeout)
		remote, err := dialSOCKS(ctx, f.socks, dst)
		cancel()
		if err != nil {
			return
		}
		defer remote.Close()
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(remote, conn)
			_ = remote.CloseWrite()
			close(done)
		}()
		_, _ = io.Copy(conn, remote)
		_ = conn.Close()
		// Closing local connection wakes the opposite copy on normal shutdown.
		remote.Close()
		<-done
	}()
}

// SOCKS handshakes use the caller's cancellation deadline, not merely the
// socket's fixed fallback timeout. Preserve context.Canceled/DeadlineExceeded
// even when cancellation presents as a closed network connection.
func socksHandshakeError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}

// dialSOCKS performs an explicit unauthenticated SOCKS5 CONNECT using numeric
// destinations only. Destination DNS is never resolved by this process.
func dialSOCKS(ctx context.Context, socks, dst string) (*net.TCPConn, error) {
	host, portText, err := net.SplitHostPort(dst)
	if err != nil {
		return nil, socksHandshakeError(ctx, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, errors.New("numeric destination IP required")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("invalid destination port")
	}
	d := &net.Dialer{}
	c, err := d.DialContext(ctx, "tcp", socks)
	if err != nil {
		return nil, socksHandshakeError(ctx, err)
	}
	remote, ok := c.(*net.TCPConn)
	if !ok {
		c.Close()
		return nil, errors.New("SOCKS endpoint is not TCP")
	}
	// DialContext governs only connection establishment. A stalled SOCKS
	// server can otherwise block ReadFull until the full connectTimeout.
	// This callback closes only the in-flight handshake socket.
	stopCancel := context.AfterFunc(ctx, func() { _ = remote.Close() })
	defer stopCancel()
	success := false
	defer func() {
		if !success {
			remote.Close()
		}
	}()
	deadline := time.Now().Add(connectTimeout)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	_ = remote.SetDeadline(deadline)
	if _, err = remote.Write([]byte{5, 1, 0}); err != nil {
		return nil, socksHandshakeError(ctx, err)
	}
	var greeting [2]byte
	if _, err = io.ReadFull(remote, greeting[:]); err != nil {
		return nil, socksHandshakeError(ctx, err)
	}
	if greeting != [2]byte{5, 0} {
		return nil, errors.New("SOCKS authentication method refused")
	}
	request := []byte{5, 1, 0}
	if ip.Is4() {
		request = append(request, 1)
		request = append(request, ip.AsSlice()...)
	} else {
		request = append(request, 4)
		request = append(request, ip.AsSlice()...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err = remote.Write(request); err != nil {
		return nil, socksHandshakeError(ctx, err)
	}
	if err = readReply(remote); err != nil {
		return nil, socksHandshakeError(ctx, err)
	}
	if err = ctx.Err(); err != nil {
		return nil, socksHandshakeError(ctx, err)
	}
	_ = remote.SetDeadline(time.Time{})
	success = true
	return remote, nil
}
func readReply(r io.Reader) error {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return err
	}
	if h[0] != 5 || h[2] != 0 || h[1] != 0 {
		return fmt.Errorf("SOCKS request rejected (code=%d)", h[1])
	}
	var n int
	switch h[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var sz [1]byte
		if _, err := io.ReadFull(r, sz[:]); err != nil {
			return err
		}
		n = int(sz[0])
	default:
		return errors.New("bad SOCKS address type")
	}
	var rest [258]byte
	if _, err := io.ReadFull(r, rest[:n+2]); err != nil {
		return err
	}
	return nil
}
func dialUDPSOCKS(ctx context.Context, socks string) (*net.TCPConn, *net.UDPConn, error) {
	d := &net.Dialer{}
	c, err := d.DialContext(ctx, "tcp", socks)
	if err != nil {
		return nil, nil, err
	}
	ctrl, ok := c.(*net.TCPConn)
	if !ok {
		c.Close()
		return nil, nil, errors.New("SOCKS endpoint must be TCP")
	}
	// As with CONNECT, context cancellation must interrupt a SOCKS server
	// stalled in its UDP ASSOCIATE control-channel handshake.
	stopCancel := context.AfterFunc(ctx, func() { _ = ctrl.Close() })
	defer stopCancel()
	closeOnErr := func(e error) (*net.TCPConn, *net.UDPConn, error) { ctrl.Close(); return nil, nil, e }
	_ = ctrl.SetDeadline(time.Now().Add(connectTimeout))
	if _, err := ctrl.Write([]byte{5, 1, 0}); err != nil {
		return closeOnErr(socksHandshakeError(ctx, err))
	}
	var greet [2]byte
	if _, err := io.ReadFull(ctrl, greet[:]); err != nil {
		return closeOnErr(socksHandshakeError(ctx, err))
	}
	if greet != [2]byte{5, 0} {
		return closeOnErr(errors.New("SOCKS UDP refused"))
	}
	if _, err := ctrl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return closeOnErr(socksHandshakeError(ctx, err))
	}
	var h [4]byte
	if _, err := io.ReadFull(ctrl, h[:]); err != nil {
		return closeOnErr(socksHandshakeError(ctx, err))
	}
	if h[0] != 5 || h[1] != 0 || h[2] != 0 {
		return closeOnErr(errors.New("SOCKS UDP associate rejected"))
	}
	var n int
	switch h[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	default:
		return closeOnErr(errors.New("SOCKS UDP must return numeric address"))
	}
	addr := make([]byte, n+2)
	if _, err := io.ReadFull(ctrl, addr); err != nil {
		return closeOnErr(socksHandshakeError(ctx, err))
	}
	ip := net.IP(addr[:n])
	port := binary.BigEndian.Uint16(addr[n:])
	if port == 0 || !ip.IsLoopback() {
		return closeOnErr(errors.New("UDP relay must bind to loopback"))
	}
	relay, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: int(port)})
	if err != nil {
		return closeOnErr(socksHandshakeError(ctx, err))
	}
	if err := ctx.Err(); err != nil {
		_ = relay.Close()
		return closeOnErr(socksHandshakeError(ctx, err))
	}
	_ = ctrl.SetDeadline(time.Time{})
	return ctrl, relay, nil
}
func (f *forwarder) HandleUDP(conn adapter.UDPConn) {
	if !acquire(f.udpSlots) {
		conn.Close()
		return
	}
	go func() { defer release(f.udpSlots); defer conn.Close(); f.udpFlow(conn) }()
}
func (f *forwarder) udpFlow(conn adapter.UDPConn) {
	id := conn.ID()
	ip, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		return
	}
	ip = ip.Unmap()
	if id.LocalPort == 0 {
		return
	}
	packetDst := udpproto.Packet{Host: ip.String(), Port: id.LocalPort}
	ctx, cancel := context.WithTimeout(f.ctx, connectTimeout)
	ctrl, udp, err := dialUDPSOCKS(ctx, f.socks)
	cancel()
	if err != nil {
		return
	}
	defer ctrl.Close()
	defer udp.Close()
	stop := make(chan struct{})
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	var once sync.Once
	closeAll := func() { once.Do(func() { close(stop); _ = conn.Close(); _ = udp.Close(); _ = ctrl.Close() }) }
	defer closeAll()
	go func() { _, _ = io.Copy(io.Discard, ctrl); closeAll() }()
	go func() {
		var buf [udpproto.MaxDatagram + 1]byte
		for {
			_ = udp.SetReadDeadline(time.Now().Add(time.Second))
			n, err := udp.Read(buf[:])
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					if time.Since(time.Unix(0, last.Load())) > udpIdle {
						closeAll()
						return
					}
					continue
				}
				closeAll()
				return
			}
			p, e := udpproto.Parse(buf[:n])
			if e != nil || p.Host != packetDst.Host || p.Port != packetDst.Port {
				continue
			}
			last.Store(time.Now().UnixNano())
			if _, e = conn.WriteTo(p.Data, nil); e != nil {
				closeAll()
				return
			}
		}
	}()
	var buf [udpproto.MaxDatagram]byte
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := conn.ReadFrom(buf[:])
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if time.Since(time.Unix(0, last.Load())) > udpIdle {
					return
				}
				select {
				case <-f.ctx.Done():
					return
				case <-stop:
					return
				default:
				}
				continue
			}
			return
		}
		if n == 0 {
			continue
		}
		last.Store(time.Now().UnixNano())
		packetDst.Data = buf[:n]
		raw, err := udpproto.Encode(packetDst)
		if err != nil {
			continue
		}
		_ = udp.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := udp.Write(raw); err != nil {
			return
		}
	}
}
