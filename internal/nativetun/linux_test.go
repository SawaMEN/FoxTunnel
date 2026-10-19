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
