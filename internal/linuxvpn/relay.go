package linuxvpn

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/ippacket"
)

// Relay runs exactly two bounded packet pumps. The TUN descriptor is retained
// between attempts, but a failed stream is never replayed or sent directly.
func Relay(ctx context.Context, device Device, conn net.Conn, peer Peer) error {
	a, b, err := peer.Addresses()
	if err != nil {
		return err
	}
	deadlines, ok := device.(interface{ SetReadDeadline(time.Time) error })
	if !ok {
		return ErrNetwork
	}
	if deadlines.SetReadDeadline(time.Time{}) != nil {
		return ErrNetwork
	}
	stream := &ippacket.Stream{Reader: conn, Writer: conn}
	stop := context.AfterFunc(ctx, func() { conn.Close(); deadlines.SetReadDeadline(time.Now()) })
	defer stop()
	done := make(chan error, 1)
	go func() {
		defer conn.Close()
		var buf [ippacket.MTU + 1]byte
		for {
			n, err := device.Read(buf[:])
			if err != nil {
				done <- err
				return
			}
			src, _, err := ippacket.Addresses(buf[:n])
			if err != nil || (src != a && src != b) {
				continue
			}
			if err = stream.WritePacket(buf[:n]); err != nil {
				done <- err
				return
			}
		}
	}()
	var buf [ippacket.MTU]byte
	for {
		n, e := stream.ReadPacket(buf[:])
		if e != nil {
			err = e
			break
		}
		_, dst, e := ippacket.Addresses(buf[:n])
		if e != nil || (dst != a && dst != b) {
			err = ippacket.ErrPacket
			break
		}
		if nwrite, e := device.Write(buf[:n]); e != nil || nwrite != n {
			err = io.ErrShortWrite
			break
		}
	}
	conn.Close()
	deadlines.SetReadDeadline(time.Now())
	<-done
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
