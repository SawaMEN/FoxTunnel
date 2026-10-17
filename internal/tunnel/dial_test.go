package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestFallbackDoesNotWaitForBrokenFamily(t *testing.T) {
	ips := []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888"), netip.MustParseAddr("8.8.8.8")}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	primaryStopped := make(chan struct{})
	peer, success := net.Pipe()
	defer peer.Close()
	start := time.Now()
	c, err := dialFamilies(ctx, ips, "443", 20*time.Millisecond, func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "8.8.8.8:443" {
			return success, nil
		}
		<-ctx.Done()
		close(primaryStopped)
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if time.Since(start) > time.Second {
		t.Fatal("fallback waited for primary timeout")
	}
	select {
	case <-primaryStopped:
	case <-time.After(time.Second):
		t.Fatal("losing dial not cancelled")
	}
}
func TestFallbackStartsImmediatelyAfterFailure(t *testing.T) {
	ips := []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}
	peer, success := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := dialFamilies(ctx, ips, "443", time.Hour, func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "127.0.0.1:443" {
			return success, nil
		}
		return nil, errors.New("unreachable")
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
func TestDialFamiliesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := dialFamilies(ctx, []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, "443", time.Hour, func(context.Context, string, string) (net.Conn, error) {
		t.Error("dial after cancellation")
		return nil, errors.New("unexpected")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// A dial can succeed at the same time as the other family. The result not
// returned to the caller must be closed rather than stranded on the channel.
func TestDialFamiliesClosesSuccessfulLoser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ready := make(chan struct{})
	started := make(chan struct{}, 2)
	peers := make(chan net.Conn, 2)
	go func() { <-started; <-started; close(ready) }()
	c, err := dialFamilies(ctx, []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}, "443", 0, func(context.Context, string, string) (net.Conn, error) {
		peer, conn := net.Pipe()
		peers <- peer
		started <- struct{}{}
		<-ready
		return conn, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	for i := 0; i < 2; i++ {
		peer := <-peers
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		_, err := peer.Read(b[:])
		peer.Close()
		if err != io.EOF {
			t.Fatalf("dial socket was not closed: %v", err)
		}
	}
}
