package access

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func meteredUDP(t *testing.T, quota int64) (net.Conn, *net.UDPConn, *Controller) {
	t.Helper()
	d := policy()
	d.Users[0].QuotaBytes = quota
	controller := newTest(t, d, "")
	ctx, done := begin(t, controller, "alice", secretA)
	t.Cleanup(done)
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { relay.Close() })
	conn, err := DialDatagram(ctx, func(context.Context) (net.Conn, error) {
		return net.DialUDP("udp4", nil, relay.LocalAddr().(*net.UDPAddr))
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	relay.SetDeadline(time.Now().Add(2 * time.Second))
	return conn, relay, controller
}

func TestDatagramQuotaRejectsWholeWrite(t *testing.T) {
	conn, relay, controller := meteredUDP(t, 4)
	if n, err := conn.Write([]byte("large")); n != 0 || !errors.Is(err, ErrQuota) {
		t.Fatalf("oversized write: n=%d err=%v", n, err)
	}
	if n, err := conn.Write([]byte("fits")); n != 4 || err != nil {
		t.Fatalf("fitting write: n=%d err=%v", n, err)
	}
	buf := make([]byte, 100)
	n, _, err := relay.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "fits" {
		t.Fatalf("partial or altered datagram forwarded: %q, %v", buf[:n], err)
	}
	if got := controller.Snapshot().Users[0].Bytes; got != 4 {
		t.Fatal("usage", got)
	}
}

func TestDatagramQuotaRejectsWholeRead(t *testing.T) {
	conn, relay, controller := meteredUDP(t, 4)
	if _, err := relay.WriteToUDP([]byte("large"), conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1233)
	if n, err := conn.Read(buf); n != 0 || !errors.Is(err, ErrQuota) {
		t.Fatalf("partial datagram exposed: n=%d err=%v", n, err)
	}
	if _, err := relay.WriteToUDP([]byte("fits"), conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "fits" {
		t.Fatalf("fitting read: %q, %v", buf[:n], err)
	}
	if got := controller.Snapshot().Users[0].Bytes; got != 4 {
		t.Fatal("usage", got)
	}
}

func TestDatagramWritePreservesLargeAndEmptyPackets(t *testing.T) {
	conn, relay, controller := meteredUDP(t, 0)
	buf := make([]byte, 65535)
	for _, size := range []int{40000, 0, 17} {
		if n, err := conn.Write(make([]byte, size)); n != size || err != nil {
			t.Fatalf("write %d: %d, %v", size, n, err)
		}
		n, _, err := relay.ReadFromUDP(buf)
		if err != nil || n != size {
			t.Fatalf("packet boundary changed for %d: %d, %v", size, n, err)
		}
	}
	if got := controller.Snapshot().Users[0].Bytes; got != 40017 {
		t.Fatal("usage", got)
	}
}
