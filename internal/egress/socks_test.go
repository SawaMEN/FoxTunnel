package egress

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestConfiguration(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1:1080", "socks5://localhost:1080", "socks5://127.0.0.1:0", "socks5://127.0.0.1:1080/path", "socks5://127.0.0.1:1080?", "socks5://u@127.0.0.1:1080", "socks5://u:@127.0.0.1:1080", "socks5://0.0.0.0:1080"} {
		if _, err := New(raw, ""); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	if _, err := New("", "1.1.1.1:53"); err == nil {
		t.Fatal("orphan DNS accepted")
	}
	if _, err := New("socks5://127.0.0.1:1080", "dns.example:53"); err == nil {
		t.Fatal("DNS bootstrap leak")
	}
	if p, err := New("", ""); err != nil || p != nil {
		t.Fatal("direct default changed")
	}
	for _, raw := range []string{"socks5://127.0.0.1:1080", "socks5://u:p%40ss@[::1]:1080"} {
		if _, err := New(raw, ""); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCancelledNegotiationClosesSocket(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := l.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	p, _ := New("socks5://secret-user:secret-password@"+l.Addr().String(), "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := p.DialContext(ctx, "tcp", "8.8.8.8:443"); result <- err }()
	var c net.Conn
	select {
	case c = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("not connected")
	}
	defer c.Close()
	cancel()
	select {
	case err := <-result:
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("error %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not interrupt handshake")
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	_, err = io.Copy(io.Discard, c)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("proxy socket leaked")
	}
}

func TestUDPRejectsMalformedAndForeignPackets(t *testing.T) {
	// Test the connected datagram decoder independently of the fake echo exit.
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	udp, err := net.DialUDP("udp4", nil, relay.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer b.Close()
	p := &udpConn{UDPConn: udp, control: a, target: netip.MustParseAddrPort("8.8.8.8:443"), header: []byte{0, 0, 0, 1, 8, 8, 8, 8, 1, 187}}
	defer p.Close()
	p.SetDeadline(time.Now().Add(time.Second))
	p.Write([]byte("request"))
	buf := make([]byte, 100)
	_, peer, err := relay.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{{0, 0}, {0, 0, 1, 1, 8, 8, 8, 8, 1, 187, 42}, {1, 0, 0, 1, 8, 8, 8, 8, 1, 187, 42}, {0, 0, 0, 1, 1, 1, 1, 1, 1, 187, 42}, {0, 0, 0, 1, 8, 8, 8, 8, 0, 53, 42}} {
		relay.WriteToUDP(bad, peer)
	}
	relay.WriteToUDP(append(append([]byte{}, p.header...), []byte("valid")...), peer)
	n, err := p.Read(buf)
	if err != nil || string(buf[:n]) != "valid" {
		t.Fatalf("%q %v", buf[:n], err)
	}
}
