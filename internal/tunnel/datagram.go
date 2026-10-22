package tunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/enginestatus"
	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

// MaxUDPDatagram includes the SOCKS address header, not just Payload.
const MaxUDPDatagram = udpproto.MaxDatagram

var ErrUDPDisabled = errors.New("UDP is disabled")
var ErrUDPNoResponse = errors.New("UDP destination did not respond")

// Datagram keeps hostnames unresolved until they reach the authenticated exit.
// Address is host:port, with brackets for IPv6. Payload may be empty.
type Datagram struct {
	Address string
	Payload []byte
}

func encodeDatagram(d Datagram) (udpproto.Packet, []byte, error) {
	host, port, err := net.SplitHostPort(d.Address)
	if err != nil {
		return udpproto.Packet{}, nil, udpproto.ErrPacket
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return udpproto.Packet{}, nil, udpproto.ErrPacket
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() != "" {
		return udpproto.Packet{}, nil, udpproto.ErrPacket
	}
	p := udpproto.Packet{Host: host, Port: uint16(n), Data: d.Payload}
	wire, err := udpproto.Encode(p)
	return p, wire, err
}

// ExchangeUDP is one-shot v1. A timeout never automatically resends a packet.
func (c *Client) ExchangeUDP(ctx context.Context, d Datagram) (Datagram, error) {
	if !c.EnableUDP {
		return Datagram{}, ErrUDPDisabled
	}
	p, wire, err := encodeDatagram(d)
	if err != nil {
		return Datagram{}, err
	}
	budget := 5 * time.Second
	if c.ConnectTimeout > 0 {
		budget = min(budget, c.ConnectTimeout)
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	reply, err := c.exchangeUDP(ctx, wire)
	if err != nil {
		return Datagram{}, err
	}
	if len(reply) == 0 {
		return Datagram{}, ErrUDPNoResponse
	}
	packet, err := udpproto.Parse(reply)
	if err != nil || !udpReplyMatchesRequest(p, packet) {
		return Datagram{}, udpproto.ErrPacket
	}
	return Datagram{Address: packet.Target(), Payload: packet.Data}, nil
}

// UDPConn is a bounded v2 association. It never reopens or replays a flow.
// One Send and one Receive may progress concurrently; concurrent Sends serialize.
type UDPConn struct {
	status  *enginestatus.Recorder
	stream  *udpStream
	queue   chan Datagram
	closed  chan struct{}
	done    chan struct{}
	sending chan struct{}
	guard   udpReplyGuard
	once    sync.Once
	err     error // Published by closing closed.
}

// OpenUDP's context controls the association lifetime, including after setup.
func (c *Client) OpenUDP(ctx context.Context) (*UDPConn, error) {
	if !c.EnableUDP {
		return nil, ErrUDPDisabled
	}
	stream, err := c.openUDPStream(ctx)
	if err != nil {
		return nil, err
	}
	u := &UDPConn{status: c.status, stream: stream, queue: make(chan Datagram, udpStreamQueued), closed: make(chan struct{}), done: make(chan struct{}), sending: make(chan struct{}, 1)}
	stop := context.AfterFunc(ctx, func() { u.fail(ctx.Err()) })
	go func() {
		defer close(u.done)
		defer stop()
		for {
			wire, err := udpproto.ReadFrame(stream.response)
			if err != nil {
				u.fail(err)
				return
			}
			if !u.guard.matches(wire) {
				continue
			}
			p, _ := udpproto.Parse(wire)
			select {
			case u.queue <- Datagram{Address: p.Target(), Payload: p.Data}:
			case <-u.closed:
				return
			default: // UDP loss is preferable to an unbounded application queue.
				u.status.Reject(enginestatus.UDPReceiveQueue)
			}
		}
	}()
	return u, nil
}

func (u *UDPConn) fail(err error) {
	u.once.Do(func() {
		if err == nil {
			err = net.ErrClosed
		}
		u.err = err
		u.stream.close()
		close(u.closed)
	})
}

// Send cancellation after framing starts terminates the association. Retrying
// a partial frame would corrupt the stream and could duplicate a datagram.
func (u *UDPConn) Send(ctx context.Context, d Datagram) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, wire, err := encodeDatagram(d)
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-u.closed:
		return u.err
	case u.sending <- struct{}{}:
	}
	defer func() { <-u.sending }()
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-u.closed:
		return u.err
	default:
	}
	u.guard.remember(p)
	stop := context.AfterFunc(ctx, func() { u.fail(ctx.Err()) })
	err = udpproto.WriteFrame(u.stream.writer, wire)
	stopped := stop()
	if !stopped || ctx.Err() != nil {
		u.fail(ctx.Err())
		return ctx.Err()
	}
	if err != nil {
		u.fail(err)
	}
	return err
}

// Receive cancellation affects only this wait; it does not destroy the flow.
// Returned Payload belongs to the caller. Incoming queues are bounded to 32.
func (u *UDPConn) Receive(ctx context.Context) (Datagram, error) {
	if err := ctx.Err(); err != nil {
		return Datagram{}, err
	}
	select {
	case <-ctx.Done():
		return Datagram{}, ctx.Err()
	case <-u.closed:
		return Datagram{}, u.err
	case d := <-u.queue:
		return d, nil
	}
}

func (u *UDPConn) Close() error {
	u.fail(net.ErrClosed)
	<-u.done
	return nil
}
