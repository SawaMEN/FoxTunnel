//go:build linux

package nativetun

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestValidateNativeTUNOptions(t *testing.T) {
	ok := Options{Name: "ftun0", MTU: 1400, SOCKS: "127.0.0.1:1080"}
	if err := Validate(ok); err != nil {
		t.Fatal(err)
	}
	inputs := []Options{
		{Name: "lo", MTU: 1400, SOCKS: ok.SOCKS},
		{Name: "x;ip route", MTU: 1400, SOCKS: ok.SOCKS},
		{Name: "abcdefghijklmnop", MTU: 1400, SOCKS: ok.SOCKS},
		{Name: "ftun0", MTU: 1000, SOCKS: ok.SOCKS},
		{Name: "ftun0", MTU: 1400, SOCKS: "0.0.0.0:1080"},
		{Name: "ftun0", MTU: 1400, SOCKS: "proxy.example:1080"},
		{Name: "ftun0", MTU: 1400, SOCKS: "127.0.0.1:0"},
	}
	for _, input := range inputs {
		if err := Validate(input); err == nil {
			t.Errorf("accepted %+v", input)
		}
	}
}

func TestSOCKSConnectNumericIPv4AndIPv6(t *testing.T) {
	for _, dst := range []string{"198.51.100.5:53", "[2001:db8::1]:443"} {
		t.Run(dst, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			errs := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					errs <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				var greeting [3]byte
				if _, err = io.ReadFull(conn, greeting[:]); err != nil {
					errs <- err
					return
				}
				if greeting != [3]byte{5, 1, 0} {
					errs <- io.ErrUnexpectedEOF
					return
				}
				if _, err = conn.Write([]byte{5, 0}); err != nil {
					errs <- err
					return
				}
				var hdr [4]byte
				if _, err = io.ReadFull(conn, hdr[:]); err != nil {
					errs <- err
					return
				}
				if hdr[0] != 5 || hdr[1] != 1 {
					errs <- io.ErrUnexpectedEOF
					return
				}
				size := 6
				if hdr[3] == 4 {
					size = 18
				} else if hdr[3] != 1 {
					errs <- io.ErrUnexpectedEOF
					return
				}
				request := make([]byte, size)
				if _, err = io.ReadFull(conn, request); err != nil {
					errs <- err
					return
				}
				if _, err = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
					errs <- err
					return
				}
				errs <- nil
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			c, err := dialSOCKS(ctx, listener.Addr().String(), dst)
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSOCKSConnectRefusesNonNumericAndFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, dst := range []string{"example.com:443", "127.0.0.1:0", "hostname", ""} {
		_, err := dialSOCKS(ctx, "127.0.0.1:1080", dst)
		if err == nil || !strings.Contains(err.Error(), "") {
			t.Errorf("expected rejection for %q", dst)
		}
	}
}

func TestSOCKSUDPAssociateRelaysLoopback(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	_ = relay.SetReadDeadline(time.Now().Add(3 * time.Second))
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	done := make(chan error, 1)
	go func() {
		c, err := tcp.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		var greet [3]byte
		if _, err = io.ReadFull(c, greet[:]); err != nil {
			done <- err
			return
		}
		if greet != [3]byte{5, 1, 0} {
			done <- io.ErrUnexpectedEOF
			return
		}
		if _, err = c.Write([]byte{5, 0}); err != nil {
			done <- err
			return
		}
		var request [10]byte
		if _, err = io.ReadFull(c, request[:]); err != nil {
			done <- err
			return
		}
		if request != [10]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0} {
			done <- io.ErrUnexpectedEOF
			return
		}
		addr := relay.LocalAddr().(*net.UDPAddr)
		reply := []byte{5, 0, 0, 1, 127, 0, 0, 1, byte(addr.Port >> 8), byte(addr.Port)}
		if _, err = c.Write(reply); err != nil {
			done <- err
			return
		}
		var dummy [1]byte
		_, _ = c.Read(dummy[:])
		done <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	control, packet, err := dialUDPSOCKS(ctx, tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = packet.SetDeadline(time.Now().Add(time.Second))
	if _, err := packet.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var payload [8]byte
	n, source, err := relay.ReadFromUDP(payload[:])
	if err != nil {
		t.Fatal(err)
	}
	if string(payload[:n]) != "ping" {
		t.Fatalf("got %q", payload[:n])
	}
	if _, err := relay.WriteToUDP([]byte("pong"), source); err != nil {
		t.Fatal(err)
	}
	if n, err = packet.Read(payload[:]); err != nil || string(payload[:n]) != "pong" {
		t.Fatalf("got %q, %v", payload[:n], err)
	}
	control.Close()
	packet.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSOCKSUDPAssociateRejectsPublicRelay(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		c, err := tcp.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var greet [3]byte
		if _, err = io.ReadFull(c, greet[:]); err != nil {
			return
		}
		_, _ = c.Write([]byte{5, 0})
		var req [10]byte
		if _, err = io.ReadFull(c, req[:]); err != nil {
			return
		}
		// A hostile local proxy must not induce packets to a public UDP relay.
		_, _ = c.Write([]byte{5, 0, 0, 1, 8, 8, 8, 8, 0, 53})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctrl, packet, err := dialUDPSOCKS(ctx, tcp.Addr().String())
	if err == nil {
		packet.Close()
		ctrl.Close()
		t.Fatal("accepted non-loopback UDP relay")
	}
}

func TestNativeReadSOCKSReplyRejectsMalformed(t *testing.T) {
	for _, wire := range []string{
		"", "\x05\x01\x00\x01", "\x04\x00\x00\x01",
		"\x05\x00\x00\xff", "\x05\x00\x00\x01\x01\x02",
	} {
		if err := readReply(strings.NewReader(wire)); err == nil {
			t.Errorf("accepted %q", wire)
		}
	}
}
