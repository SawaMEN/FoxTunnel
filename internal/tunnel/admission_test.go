package tunnel

import (
	"net"
	"testing"
	"time"
)

func TestSOCKSLimitIncludesIncompleteHandshake(t *testing.T) {
	c, err := NewClient("https://example.org", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.MaxConnections = 1
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() { done <- c.Serve(l) }()
	first, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	first.SetDeadline(time.Now().Add(time.Second))
	first.Write([]byte{5, 1, 0})
	var reply [2]byte
	if _, err := first.Read(reply[:]); err != nil {
		t.Fatal(err)
	}
	// The first socket is now waiting for the CONNECT request and occupies a slot.
	second, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetDeadline(time.Now().Add(time.Second))
	second.Write([]byte{5, 1, 0})
	if _, err := second.Read(reply[:]); err == nil {
		t.Fatal("SOCKS handshake bypassed admission limit")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("excess connection queued instead of closed")
	}
	first.Close()
	l.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
