//go:build linux

package nativetun

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// A mock local SOCKS5 server deliberately stalls after accepting TCP.
// The I/O must stop on the caller's context, not on the 8s fallback deadline.
func TestStage6SOCKSHandshakeCancellation(t *testing.T) {
	for _, command := range []string{"connect", "associate"} {
		for _, stage := range []string{"greeting", "reply"} {
			t.Run(command+"/"+stage, func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				serverDone := make(chan error, 1)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						serverDone <- err
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					var greet [3]byte
					if _, err := io.ReadFull(conn, greet[:]); err != nil {
						serverDone <- err
						return
					}
					if greet != [3]byte{5, 1, 0} {
						serverDone <- errors.New("invalid SOCKS greeting")
						return
					}
					if stage == "reply" {
						if _, err := conn.Write([]byte{5, 0}); err != nil {
							serverDone <- err
							return
						}
						var request [10]byte
						if _, err := io.ReadFull(conn, request[:]); err != nil {
							serverDone <- err
							return
						}
						wantCommand := byte(1)
						if command == "associate" {
							wantCommand = 3
						}
						if request[0] != 5 || request[1] != wantCommand ||
							request[3] != 1 {
							serverDone <- errors.New("incorrect SOCKS request")
							return
						}
					}
					// Hold the handshake open until context cancellation closes TCP.
					var payload [1]byte
					n, err := conn.Read(payload[:])
					if n != 0 || !errors.Is(err, io.EOF) {
						serverDone <- errors.New("SOCKS handshake socket was not closed on context cancellation")
						return
					}
					serverDone <- nil
				}()
				ctx, cancel := context.WithCancel(context.Background())
				result := make(chan error, 1)
				go func() {
					if command == "connect" {
						conn, err := dialSOCKS(ctx, listener.Addr().String(), "198.51.100.6:443")
						if conn != nil {
							_ = conn.Close()
						}
						result <- err
					} else {
						ctrl, datagram, err := dialUDPSOCKS(ctx, listener.Addr().String())
						if ctrl != nil {
							_ = ctrl.Close()
						}
						if datagram != nil {
							_ = datagram.Close()
						}
						result <- err
					}
				}()
				time.AfterFunc(100*time.Millisecond, cancel)
				defer cancel()
				select {
				case err := <-result:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("expected context.Canceled, got %v", err)
					}
				case <-time.After(1500 * time.Millisecond):
					t.Fatal("SOCKS handshake ignored context cancellation")
				}
				select {
				case err := <-serverDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(1500 * time.Millisecond):
					t.Fatal("stalled local SOCKS peer retained TCP control socket")
				}
			})
		}
	}
}

func TestStage6SOCKSHandshakeDeadlineExceeded(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var greeting [3]byte
		_, _ = io.ReadFull(conn, greeting[:])
		_, _ = io.Copy(io.Discard, conn)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = dialSOCKS(ctx, listener.Addr().String(), "[2001:db8::5]:53")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline error, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("cancellation too slow: %v", time.Since(start))
	}
}
