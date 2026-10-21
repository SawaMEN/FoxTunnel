package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func datagramFixture(t *testing.T, mode, backend string) (*Client, *Server) {
	t.Helper()
	s := &Server{Username: "alice", Password: "secret", AllowPrivate: true, EnableUDP: true, RequireProtocolNegotiation: true}
	c, _ := testClient(t, s)
	if mode == "h3-post" {
		node := setupEndpoint(t, c, s)
		startNativeH3(t, node, s)
		usePrimary(t, c, node.URL)
	}
	selected := backend
	if backend == "neqo" {
		selected = "auto"
	}
	if err := c.SetTLSBackend(selected); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTransport(mode); err != nil {
		t.Fatal(err)
	}
	if backend == "neqo" {
		if err := c.SetQUICBackend("neqo", false, 2*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	c.EnableUDP = true
	c.RequireProtocolNegotiation = true
	return c, s
}

func TestStage4UDPDatagramBoundaries(t *testing.T) { testStage4UDPDatagramBoundaries(t, "go") }
func testStage4UDPDatagramBoundaries(t *testing.T, backend string) {
	for _, mode := range []string{"h2-connect", "h2-post", "wss", "h3-post"} {
		if backend == "neqo" && mode != "h3-post" {
			continue
		}
		if backend == "nss" && mode == "h3-post" {
			continue
		}
		for _, network := range []string{"udp4", "udp6"} {
			t.Run(mode+"/"+network, func(t *testing.T) {
				ip := net.IPv4(127, 0, 0, 1)
				if network == "udp6" {
					ip = net.IPv6loopback
				}
				target, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
				if err != nil {
					if network == "udp6" {
						t.Skip("IPv6 loopback unavailable:", err)
					}
					t.Fatal(err)
				}
				defer target.Close()
				peers := make(chan string, 32)
				go func() {
					var b [2048]byte
					for {
						n, peer, err := target.ReadFromUDP(b[:])
						if err != nil {
							return
						}
						peers <- peer.String()
						_, _ = target.WriteToUDP(b[:n], peer)
					}
				}()
				c, _ := datagramFixture(t, mode, backend)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				stream, err := c.OpenUDP(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer stream.Close()
				address := target.LocalAddr().String()
				_, header, err := encodeDatagram(Datagram{Address: address})
				if err != nil {
					t.Fatal(err)
				}
				var firstPeer string
				for _, size := range []int{0, 7, MaxUDPDatagram - len(header)} {
					want := bytes.Repeat([]byte{0xa5}, size)
					d := Datagram{Address: address, Payload: want}
					reply, err := c.ExchangeUDP(ctx, d)
					if err != nil || !bytes.Equal(reply.Payload, want) || reply.Address != address {
						t.Fatal("v1", size, err, reply.Address)
					}
					<-peers
					if err = stream.Send(ctx, d); err != nil {
						t.Fatal(err)
					}
					reply, err = stream.Receive(ctx)
					if err != nil || !bytes.Equal(reply.Payload, want) || reply.Address != address {
						t.Fatal("v2", size, err, reply.Address)
					}
					peer := <-peers
					if firstPeer == "" {
						firstPeer = peer
					} else if peer != firstPeer {
						t.Fatal("v2 lost destination NAT mapping", firstPeer, peer)
					}
				}
				tooLarge := Datagram{Address: address, Payload: make([]byte, MaxUDPDatagram-len(header)+1)}
				if stream.Send(ctx, tooLarge) == nil {
					t.Fatal("oversize accepted")
				}
				if _, err = c.ExchangeUDP(ctx, tooLarge); err == nil {
					t.Fatal("oversize v1 accepted")
				}
				if err = stream.Send(ctx, Datagram{Address: address, Payload: []byte("after")}); err != nil {
					t.Fatal(err)
				}
				if d, err := stream.Receive(ctx); err != nil || string(d.Payload) != "after" {
					t.Fatal("invalid send broke association", err)
				}
			})
		}
	}
}

func TestStage4UDPReceiveCancellationAndLoss(t *testing.T) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	var drops atomic.Int32
	go func() {
		var b [128]byte
		for {
			n, peer, err := target.ReadFromUDP(b[:])
			if err != nil {
				return
			}
			if string(b[:n]) == "drop" {
				drops.Add(1)
				continue
			}
			_, _ = target.WriteToUDP(b[:n], peer)
		}
	}()
	c, _ := datagramFixture(t, "h3-post", "go")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := c.OpenUDP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	address := target.LocalAddr().String()
	if err = stream.Send(ctx, Datagram{Address: address, Payload: []byte("drop")}); err != nil {
		t.Fatal(err)
	}
	wait, stop := context.WithTimeout(ctx, 80*time.Millisecond)
	_, err = stream.Receive(wait)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("lost packet did not time out", err)
	}
	if err = stream.Send(ctx, Datagram{Address: address, Payload: []byte("alive")}); err != nil {
		t.Fatal(err)
	}
	if d, err := stream.Receive(ctx); err != nil || string(d.Payload) != "alive" {
		t.Fatal("Receive cancellation killed flow", err)
	}
	if drops.Load() != 1 {
		t.Fatal("lost datagram was replayed", drops.Load())
	}
}

func TestStage4UDPOneShotCancellationReleasesSocket(t *testing.T) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	seen := make(chan struct{})
	go func() { var b [128]byte; _, _, _ = target.ReadFromUDP(b[:]); close(seen) }()
	c, s := datagramFixture(t, "h2-connect", "go")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := c.ExchangeUDP(ctx, Datagram{Address: target.LocalAddr().String(), Payload: []byte("wait")})
		done <- err
	}()
	select {
	case <-seen:
	case <-time.After(time.Second):
		t.Fatal("target not reached")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancel accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("client cancellation stalled")
	}
	deadline := time.Now().Add(time.Second)
	for s.activeTunnels.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.activeTunnels.Load() != 0 {
		t.Fatal("cancelled v1 socket retained admission")
	}
}

func TestStage4UDPSetupBudgetAndRejectedCleanup(t *testing.T) {
	c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	c.ConnectTimeout = 40 * time.Millisecond
	started := time.Now()
	stream, err := c.openUDPStream(context.Background())
	if stream != nil {
		stream.close()
		t.Fatal("stall accepted")
	}
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatal("UDP setup budget", err)
	}
	for _, responseError := range []bool{false, true} {
		force := make(chan struct{})
		defer close(force)
		var body *stage3JoinBody
		c.transport = stage3RoundTripper(func(r *http.Request) (*http.Response, error) {
			body = &stage3JoinBody{ctx: r.Context(), force: force}
			response := &http.Response{StatusCode: 502, ProtoMajor: 2, Body: body}
			if responseError {
				return response, io.ErrUnexpectedEOF
			}
			return response, nil
		})
		done := make(chan error, 1)
		go func() { _, err := c.openUDPStream(context.Background()); done <- err }()
		select {
		case err := <-done:
			if err == nil || !body.cancelled.Load() {
				t.Fatal("rejected response not cancelled", err)
			}
		case <-time.After(time.Second):
			t.Fatal("UDP response close deadlocked")
		}
	}
}

func TestStage4UDPServerRejectsMalformedFrameWithReset(t *testing.T) {
	for _, mode := range []string{"h2-connect", "h3-post"} {
		t.Run(mode, func(t *testing.T) {

			c, _ := datagramFixture(t, mode, "go")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			stream, err := c.openUDPStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.close()
			if _, err = stream.writer.Write([]byte{0, 0}); err != nil {
				t.Fatal(err)
			}
			_, err = io.ReadAll(stream.response)
			if err == nil {
				t.Fatal("malformed frame reported successful EOF")
			}

		})
	}
}

func TestStage4UDPRemoteDNS(t *testing.T) {
	dns, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	var queries atomic.Int32
	go func() {
		var b [1500]byte
		for {
			n, peer, err := dns.ReadFromUDP(b[:])
			if err != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(b[:n]) != nil {
				continue
			}
			m.Header.Response = true
			m.Header.Authoritative = true
			for _, q := range m.Questions {
				queries.Add(1)
				if q.Type == dnsmessage.TypeA {
					m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}})
				}
			}
			wire, err := m.Pack()
			if err == nil {
				_, _ = dns.WriteToUDP(wire, peer)
			}
		}
	}()
	c, s := datagramFixture(t, "h2-connect", "go")
	// No requests have started. Configure only the server's resolver.
	s.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", dns.LocalAddr().String())
	}}
	target := startUDPEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d := Datagram{Address: net.JoinHostPort("foxtunnel-test.invalid", strconv.Itoa(target.LocalAddr().(*net.UDPAddr).Port)), Payload: []byte("remote DNS")}
	reply, err := c.ExchangeUDP(ctx, d)
	if err != nil || !bytes.Equal(reply.Payload, d.Payload) || queries.Load() == 0 {
		t.Fatal("remote DNS", err, queries.Load())
	}
	stream, err := c.OpenUDP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err = stream.Send(ctx, d); err != nil {
		t.Fatal(err)
	}
	if reply, err = stream.Receive(ctx); err != nil || !bytes.Equal(reply.Payload, d.Payload) {
		t.Fatal("stream remote DNS", err)
	}
}

func TestStage4UDPNoResponseIsDistinctFromEmptyPayload(t *testing.T) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	c, s := datagramFixture(t, "h2-connect", "go")
	s.DialTimeout = 20 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err = c.ExchangeUDP(ctx, Datagram{Address: target.LocalAddr().String(), Payload: []byte("silent")}); !errors.Is(err, ErrUDPNoResponse) {
		t.Fatal("remote timeout lost HTTP 204 semantics", err)
	}
}
