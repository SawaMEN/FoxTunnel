package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/SawaMEN/VetroffProxy/internal/bond"
	"io"
	"net"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/VetroffProxy/internal/egress"
	"github.com/SawaMEN/VetroffProxy/internal/udpproto"
	"golang.org/x/net/dns/dnsmessage"
)

// This exit does not connect to the requested target. It echoes only inside
// SOCKS, so successful roundtrips prove that the destination was not dialed
// directly. Public destination IPs need no external network access.
func cascadeExit(t *testing.T, rejectUDP bool, noAuth ...bool) (*egress.Proxy, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	tcpCount, udpCount := new(atomic.Int64), new(atomic.Int64)
	method := byte(2)
	if len(noAuth) > 0 && noAuth[0] {
		method = 0
	}
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				var greet [3]byte
				if _, e := io.ReadFull(c, greet[:]); e != nil {
					return
				}
				if greet != [3]byte{5, 1, method} {
					return
				}
				c.Write([]byte{5, method})
				if method == 2 {
					var auth [2]byte
					io.ReadFull(c, auth[:])
					user := make([]byte, int(auth[1]))
					io.ReadFull(c, user)
					var n [1]byte
					io.ReadFull(c, n[:])
					pass := make([]byte, int(n[0]))
					io.ReadFull(c, pass)
					if string(user) != "cascade-user" || string(pass) != "cascade-password" {
						c.Write([]byte{1, 1})
						return
					}
					c.Write([]byte{1, 0})
				}
				var header [4]byte
				if _, e := io.ReadFull(c, header[:]); e != nil {
					return
				}
				size := 6
				if header[3] == 4 {
					size = 18
				}
				addr := make([]byte, size)
				if _, e := io.ReadFull(c, addr); e != nil {
					return
				}
				if header[1] == 1 {
					tcpCount.Add(1)
					c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
					// Reserved DNS endpoint in this fixture; answer A and AAAA queries locally.
					if binary.BigEndian.Uint16(addr[len(addr)-2:]) == 53 {
						serveCascadeDNS(c)
						return
					}
					io.Copy(c, c)
					return
				}
				if header[1] != 3 {
					return
				}
				udpCount.Add(1)
				if rejectUDP {
					c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				u, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if e != nil {
					return
				}
				defer u.Close()
				port := u.LocalAddr().(*net.UDPAddr).Port
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, byte(port >> 8), byte(port)}) // wildcard relay address
				done := make(chan struct{})
				go func() {
					defer close(done)
					b := make([]byte, 65535)
					for {
						n, a, e := u.ReadFromUDP(b)
						if e != nil {
							return
						}
						u.WriteToUDP(b[:n], a)
					}
				}()
				io.Copy(io.Discard, c)
				u.Close()
				<-done
			}()
		}
	}()
	credentials := "cascade-user:cascade-password@"
	if method == 0 {
		credentials = ""
	}
	p, e := egress.New("socks5://"+credentials+l.Addr().String(), "9.9.9.9:53")
	if e != nil {
		t.Fatal(e)
	}
	return p, tcpCount, udpCount
}

func serveCascadeDNS(c net.Conn) {
	var size [2]byte
	if _, err := io.ReadFull(c, size[:]); err != nil {
		return
	}
	b := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(c, b); err != nil {
		return
	}
	var q dnsmessage.Message
	if q.Unpack(b) != nil {
		return
	}
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true}, Questions: q.Questions}
	for _, question := range q.Questions {
		if question.Type == dnsmessage.TypeA {
			response.Answers = append(response.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 10}, Body: &dnsmessage.AResource{A: [4]byte{8, 8, 8, 8}}})
		}
	}
	wire, _ := response.Pack()
	binary.BigEndian.PutUint16(size[:], uint16(len(wire)))
	c.Write(append(size[:], wire...))
}

func TestCascadeTCPTransports(t *testing.T) {
	for _, mode := range []string{"h2-connect", "h2-post", "wss", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up", "h3-connect", "h3-post"} {
		t.Run(mode, func(t *testing.T) {
			p, count, _ := cascadeExit(t, false, mode == "h2-connect")
			server := &Server{Username: "alice", Password: "secret", Egress: p}
			// TCP carriers include WSS, which requires HTTP/1.1 ALPN.
			c, _ := testClient(t, server)
			if isH3Transport(mode) {
				node := setupEndpoint(t, c, server)
				startNativeH3(t, node, server)
				usePrimary(t, c, node.URL)
			}
			if err := c.SetTransport(mode); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := c.DialContext(ctx, "tcp", "8.8.8.8:443")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			conn.Write([]byte("cascade TCP"))
			b := make([]byte, 11)
			if _, err = io.ReadFull(conn, b); err != nil || string(b) != "cascade TCP" {
				t.Fatalf("roundtrip %q: %v", b, err)
			}
			if count.Load() != 1 {
				t.Fatalf("proxy CONNECT count %d", count.Load())
			}
		})
	}
}

func TestCascadeUDPBothModes(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			p, _, count := cascadeExit(t, false, !stream)
			c, _ := udpFixture(t, &Server{Username: "alice", Password: "secret", EnableUDP: true, Egress: p})
			c.EnableUDP = true
			c.UDPStreaming = stream
			control, bind, status := udpAssociation(t, c)
			defer control.Close()
			if status != 0 {
				t.Fatal(status)
			}
			conn, err := net.DialUDP("udp4", nil, bind)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			for _, host := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
				for _, text := range []string{"cascade UDP", ""} {
					raw, _ := udpproto.Encode(udpproto.Packet{Host: host, Port: 443, Data: []byte(text)})
					if _, err = conn.Write(raw); err != nil {
						t.Fatal(err)
					}
					buf := make([]byte, 65535)
					n, e := conn.Read(buf)
					if e != nil {
						t.Fatal(e)
					}
					packet, e := udpproto.Parse(buf[:n])
					if e != nil || packet.Host != host || packet.Port != 443 || string(packet.Data) != text {
						t.Fatalf("reply %+v: %v", packet, e)
					}
				}
			}
			if count.Load() < 2 {
				t.Fatal("UDP bypassed proxy")
			}
		})
	}
}

func TestCascadeDNSAndDestinationPolicy(t *testing.T) {
	p, count, _ := cascadeExit(t, false)
	s := &Server{Egress: p}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := s.dialTarget(ctx, "cascade-only.invalid", "443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if count.Load() < 2 {
		t.Fatal("DNS or payload bypassed SOCKS")
	}
	ip, err := s.resolveUDP(ctx, "cascade-only.invalid")
	if err != nil || ip != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("UDP DNS: %v %v", ip, err)
	}
	before := count.Load()
	if conn, err = s.dialTarget(ctx, "127.0.0.1", "443"); err == nil {
		conn.Close()
		t.Fatal("private target allowed")
	}
	if _, err = s.resolveUDP(ctx, "::1"); err == nil {
		t.Fatal("private UDP allowed")
	}
	if count.Load() != before {
		t.Fatal("prohibited address reached proxy")
	}
}

func TestCascadeFailureNeverDialsDestination(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	// Keep an actual destination listening while the selected proxy is refused.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := dead.Addr().String()
	dead.Close()
	p, err := egress.New("socks5://"+address, "")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Egress: p, AllowPrivate: true}
	host, port, _ := net.SplitHostPort(target.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if c, e := s.dialTarget(ctx, host, port); e == nil {
		c.Close()
		t.Fatal("direct TCP fallback")
	}
	target.(*net.TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond))
	if c, e := target.Accept(); e == nil {
		c.Close()
		t.Fatal("direct target contacted")
	}
	// An exit rejecting UDP must not fall back to the reachable UDP target.
	p, _, _ = cascadeExit(t, true)
	s.Egress = p
	udp := startUDPEcho(t)
	if c, e := s.dialUDPTarget(ctx, udp.LocalAddr().String()); e == nil {
		c.Close()
		t.Fatal("direct UDP fallback")
	}
}

func TestCascadeUDPControlClosureAndFiltering(t *testing.T) {
	p, _, _ := cascadeExit(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, e := p.DialContext(ctx, "udp", "8.8.8.8:53")
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(time.Second))
	payload := bytes.Repeat([]byte{42}, 4000)
	if _, e = c.Write(payload); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 8000)
	n, e := c.Read(b)
	if e != nil || !bytes.Equal(b[:n], payload) {
		t.Fatalf("large UDP %d %v", n, e)
	}
	c.Close()
	if _, e = c.Read(b); e == nil {
		t.Fatal("closed association remains readable")
	}
}

func TestCascadeBondRelayAndHub(t *testing.T) {
	for _, lanes := range []bool{false, true} {
		t.Run(fmt.Sprint(lanes), func(t *testing.T) {
			exit, count, _ := cascadeExit(t, false)
			server := &Server{Username: "alice", Password: "secret", Egress: exit}
			hub := server.NewBondHub()
			defer hub.Close()
			server.Bond = hub
			c, hubURL := udpFixture(t, server)
			relay, closeRelay, err := NewBondRelay(hubURL, "alice", "secret", c.CACertFile)
			if err != nil {
				t.Fatal(err)
			}
			defer closeRelay()
			node := setupEndpoint(t, c, &Server{Username: "alice", Password: "secret", Bond: relay, BondRelayOnly: true})
			endpoint, _ := url.Parse(node.URL)
			client := &bond.Client{Endpoints: []*url.URL{endpoint, endpoint}, Transport: c.transport, Username: "alice", Password: "secret", PersistentLanes: lanes}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stream, err := client.Open(ctx, "8.8.8.8:443")
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			payload := []byte("bond through cascade")
			if _, err = stream.Write(payload); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, len(payload))
			if _, err = io.ReadFull(stream, b); err != nil || !bytes.Equal(payload, b) {
				t.Fatalf("bond reply %q: %v", b, err)
			}
			if count.Load() != 1 {
				t.Fatalf("bond exit SOCKS dials: %d", count.Load())
			}
		})
	}
}

// Exercise two complete Vetroff servers, using the second client's real
// SOCKS listener as the first server's exit rather than a protocol stub.
func TestCascadeVetroffToVetroff(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			second := &Server{Username: "alice", Password: "secret", EnableUDP: true, AllowPrivate: true}
			next, _ := udpFixture(t, second)
			next.EnableUDP = true
			next.UDPStreaming = stream
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			proxyAddress := listener.Addr().String()
			nextContext, cancelNext := context.WithCancel(context.Background())
			nextDone := make(chan struct{})
			stopNext := func() {
				cancelNext()
				listener.Close()
				select {
				case <-nextDone:
				case <-time.After(5 * time.Second):
					t.Error("next hop did not stop")
				}
			}
			t.Cleanup(stopNext)
			go func() { defer close(nextDone); _ = next.ServeContext(nextContext, listener) }()
			exit, err := egress.New("socks5://"+proxyAddress, "")
			if err != nil {
				t.Fatal(err)
			}
			first, _ := udpFixture(t, &Server{Username: "alice", Password: "secret", EnableUDP: true, AllowPrivate: true, Egress: exit})
			first.EnableUDP = true
			first.UDPStreaming = stream
			var accepts atomic.Int64
			target := testDestination(t, func(c net.Conn) { accepts.Add(1); io.Copy(c, c) })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := first.DialContext(ctx, "tcp", target)
			if err != nil {
				t.Fatal(err)
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			conn.Write([]byte("two hops"))
			b := make([]byte, 8)
			if _, err = io.ReadFull(conn, b); err != nil || string(b) != "two hops" {
				t.Fatalf("TCP %q %v", b, err)
			}
			conn.Close()
			udp := startUDPEcho(t)
			if !stream {
				reply, err := first.ExchangeUDP(ctx, Datagram{Address: udp.LocalAddr().String(), Payload: []byte("two UDP hops")})
				if err != nil || string(reply.Payload) != "two UDP hops" {
					t.Fatalf("UDP %+v %v", reply, err)
				}
			} else {
				control, bind, status := udpAssociation(t, first)
				defer control.Close()
				if status != 0 {
					t.Fatal(status)
				}
				socket, err := net.DialUDP("udp4", nil, bind)
				if err != nil {
					t.Fatal(err)
				}
				defer socket.Close()
				socket.SetDeadline(time.Now().Add(5 * time.Second))
				sendStreamTestPacket(t, socket, udp.LocalAddr().(*net.UDPAddr).Port, "two UDP hops")
				packet := make([]byte, 2048)
				n, err := socket.Read(packet)
				if err != nil {
					t.Fatal(err)
				}
				reply, err := udpproto.Parse(packet[:n])
				if err != nil || string(reply.Data) != "two UDP hops" {
					t.Fatalf("UDP %+v %v", reply, err)
				}
			}
			stopNext()
			if conn, err = first.DialContext(ctx, "tcp", target); err == nil {
				conn.Close()
				t.Fatal("dead next hop fell back to direct")
			}
			if accepts.Load() != 1 {
				t.Fatalf("target connections %d", accepts.Load())
			}
		})
	}
}
