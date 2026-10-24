package firefox

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

// The private IPC test runs without Gecko. The native Gecko HTTPS relay is
// exercised separately by TestGeckoManagedIPC on the compiled source runtime.
func TestManagedUDPPrivateIPC(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	request, err := udpproto.Encode(udpproto.Packet{
		Host: "example.invalid", Port: 5353, Data: []byte{0, 1, 0xff, 0x80},
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		read := func(n int) ([]byte, error) {
			b := make([]byte, n)
			_, e := io.ReadFull(c, b)
			return b, e
		}
		greeting, err := read(3)
		if err != nil || !bytes.Equal(greeting, []byte{5, 1, 2}) {
			done <- io.ErrUnexpectedEOF
			return
		}
		c.Write([]byte{5, 2})
		auth, err := read(2)
		if err != nil || auth[0] != 1 {
			done <- io.ErrUnexpectedEOF
			return
		}
		name, err := read(int(auth[1]))
		if err != nil || string(name) != "foxtunnel" {
			done <- io.ErrUnexpectedEOF
			return
		}
		lenPassword, err := read(1)
		if err != nil {
			done <- err
			return
		}
		password, err := read(int(lenPassword[0]))
		if err != nil || string(password) != "private-secret" {
			done <- io.ErrUnexpectedEOF
			return
		}
		c.Write([]byte{1, 0})
		head, err := read(6)
		if err != nil || head[0] != 5 || head[1] != 0xf0 ||
			head[2] != 0 || head[3] != 0 || int(binary.BigEndian.Uint16(head[4:6])) != len(request) {
			done <- io.ErrUnexpectedEOF
			return
		}
		packet, err := read(len(request))
		if err != nil || !bytes.Equal(packet, request) {
			done <- io.ErrUnexpectedEOF
			return
		}
		c.Write([]byte{5, 0, byte(len(packet) >> 8), byte(len(packet))})
		_, err = c.Write(packet)
		done <- err
	}()
	ready := make(chan struct{})
	close(ready)
	m := &Managed{
		ready: ready, done: make(chan struct{}), listen: listener.Addr().String(),
		timeout: 3 * time.Second, token: "private-secret",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	actual, err := m.ExchangeUDP(ctx, request)
	if err != nil || !bytes.Equal(actual, request) {
		t.Fatalf("private UDP exchange: reply %v err %v", actual, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestManagedUDPRejectsInvalidFrameBeforeSocket(t *testing.T) {
	m := &Managed{ready: make(chan struct{}), done: make(chan struct{}), timeout: time.Second}
	if _, err := m.ExchangeUDP(context.Background(), []byte{0, 1, 2}); err == nil {
		t.Fatal("invalid datagram must not start IPC")
	}
}
