package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestSecurityStage5ManagedUDPIsolation(t *testing.T) {
	testSecurityStage5ManagedUDPIsolation(t, "go")
}

func testSecurityStage5ManagedUDPIsolation(t *testing.T, backend string) {
	for _, mode := range []string{"h2-connect", "h3-post"} {
		if backend == "nss" && mode == "h3-post" || backend == "neqo" && mode != "h3-post" {
			continue
		}
		for _, operation := range []string{"rotate", "disable", "remove"} {
			t.Run(mode+"/"+operation, func(t *testing.T) {
				ctrl := accessController(t)
				s := &Server{Access: ctrl, AllowPrivate: true, EnableUDP: true}
				alice, _ := testClient(t, s)
				if mode == "h3-post" {
					node := setupEndpoint(t, alice, s)
					startNativeH3(t, node, s)
					usePrimary(t, alice, node.URL)
				}
				configure := func(c *Client, name, password string) {
					t.Helper()
					selected := backend
					if backend == "neqo" {
						selected = "auto"
					}
					accessClient(t, c, name, password, mode, selected)
					if backend == "neqo" {
						if err := c.SetQUICBackend("neqo", false, time.Second); err != nil {
							t.Fatal(err)
						}
					}
					c.EnableUDP = true
				}
				configure(alice, "alice", accessAlice)
				bob, err := NewClient(alice.ServerURL.String(), "bob", accessBob, alice.CACertFile)
				if err != nil {
					t.Fatal(err)
				}
				defer bob.Close()
				configure(bob, "bob", accessBob)
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				a, err := alice.OpenUDP(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer a.Close()
				b, err := bob.OpenUDP(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer b.Close()
				target := startUDPEcho(t)
				d := Datagram{Address: target.LocalAddr().String(), Payload: []byte("owned UDP")}
				echo := func(conn *UDPConn) {
					t.Helper()
					if err := conn.Send(ctx, d); err != nil {
						t.Fatal(err)
					}
					r, err := conn.Receive(ctx)
					if err != nil || string(r.Payload) != string(d.Payload) {
						t.Fatal("UDP echo", err)
					}
				}
				echo(a)
				echo(b)
				before := ctrl.Snapshot().Users[0].Bytes
				policy := accessPolicy()
				switch operation {
				case "rotate":
					policy.Users[0].Password = accessAlice + "-rotated"
				case "disable":
					policy.Users[0].Disabled = true
				case "remove":
					policy.Users = policy.Users[1:]
				}
				if err := ctrl.Replace(policy); err != nil {
					t.Fatal(err)
				}
				wait, cancelWait := context.WithTimeout(ctx, time.Second)
				_, err = a.Receive(wait)
				cancelWait()
				if err == nil || errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("revoked UDP association not terminated", err)
				}
				echo(b)
				stale, err := alice.OpenUDP(ctx)
				if err == nil {
					stale.Close()
					t.Fatal("stale credentials admitted")
				}
				waitAccess(t, func() bool {
					for _, u := range ctrl.Snapshot().Users {
						if u.ID == "a" {
							return u.ActiveRequests == 0 && u.ActiveTunnels == 0
						}
					}
					return true
				})
				if operation == "rotate" {
					fresh, err := NewClient(alice.ServerURL.String(), "alice", policy.Users[0].Password, alice.CACertFile)
					if err != nil {
						t.Fatal(err)
					}
					defer fresh.Close()
					configure(fresh, "alice", policy.Users[0].Password)
					u, err := fresh.OpenUDP(ctx)
					if err != nil {
						t.Fatal("new credentials refused", err)
					}
					defer u.Close()
					echo(u)
					if after := ctrl.Snapshot().Users[0].Bytes; before == 0 || after <= before {
						t.Fatal("rotation reset accounting", before, after)
					}
				}
				if snapshot := ctrl.Snapshot(); snapshot.StateFailed {
					t.Fatal("access state failed")
				}
			})
		}
	}
}

func TestSecurityStage5SpecialDestinationsDeniedBeforeDial(t *testing.T) {
	s := &Server{}
	for _, host := range []string{
		"0.1.2.3", "240.0.0.1", "255.255.255.254", "192.88.99.1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1",
		"64:ff9b:1::1", "100::1", "100:0:0:1::1", "2001::1",
		"2001:2::1", "2002:7f00:1::1", "3fff::1", "5f00::1",
		"2606:4700::1111%eth0", "4000::1",
	} {
		t.Run(host, func(t *testing.T) {
			if safePublicIP(netip.MustParseAddr(host)) {
				t.Fatal("special destination passed default policy")
			}
			if _, err := s.resolveUDP(context.Background(), host); err == nil {
				t.Fatal("UDP accepted special destination")
			}
			_, err := s.dialResolvedTarget(context.Background(), host, "443", func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("TCP reached socket dialer before filtering")
				return nil, errors.New("unexpected dial")
			})
			if err == nil {
				t.Fatal("TCP accepted special destination")
			}
		})
	}
	for _, host := range []string{"1.1.1.1", "8.8.8.8", "::ffff:8.8.8.8", "2001:4860:4860::8888", "2606:4700:4700::1111"} {
		if !safePublicIP(netip.MustParseAddr(host)) {
			t.Errorf("ordinary public destination rejected: %s", host)
		}
	}
}

// The second A answer rebinds to loopback. A single lookup returns a mixed
// private/public set; neither family retry nor socket dial may resolve it again.
func stage5RebindingResolver(t *testing.T) (*net.Resolver, *atomic.Int32) {
	t.Helper()
	dns, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dns.Close() })
	queries := new(atomic.Int32)
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
			m.Header.Response, m.Header.Authoritative = true, true
			for _, q := range m.Questions {
				if q.Type != dnsmessage.TypeA {
					continue
				}
				first := queries.Add(1) == 1
				for _, ip := range [][4]byte{{127, 0, 0, 1}, {10, 0, 0, 1}} {
					m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: ip}})
				}
				if first {
					for _, ip := range [][4]byte{{8, 8, 8, 8}, {1, 1, 1, 1}} {
						m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: ip}})
					}
				}
			}
			wire, err := m.Pack()
			if err == nil {
				_, _ = dns.WriteToUDP(wire, peer)
			}
		}
	}()
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", dns.LocalAddr().String())
	}}, queries
}

func TestSecurityStage5DNSFilteredAndPinnedAcrossRetries(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			resolver, queries := stage5RebindingResolver(t)
			s := &Server{Resolver: resolver}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if network == "udp" {
				ip, err := s.resolveUDP(ctx, "rebinding.invalid")
				if err != nil || !safePublicIP(ip) {
					t.Fatal("public answer not selected", ip, err)
				}
			} else {
				var calls int
				_, err := s.dialResolvedTarget(ctx, "rebinding.invalid", "443", func(_ context.Context, network, address string) (net.Conn, error) {
					calls++
					host, port, err := net.SplitHostPort(address)
					ip, parseErr := netip.ParseAddr(host)
					if err != nil || parseErr != nil || !safePublicIP(ip) || port != "443" || network != "tcp" {
						t.Errorf("dial was not pinned: %s %s", network, address)
					}
					return nil, errors.New("synthetic dial failure")
				})
				if err == nil || calls != 2 {
					t.Fatal("did not retry both filtered public IPs", calls, err)
				}
			}
			if queries.Load() != 1 {
				t.Fatal("hostname resolved more than once", queries.Load())
			}
			// A new operation must see the rebound private-only answer and refuse.
			if _, err := s.resolveUDP(ctx, "rebinding.invalid"); err == nil {
				t.Fatal("rebound private-only response accepted")
			}
		})
	}
}

func TestSecurityStage5UDPBodyBudgetReleasesAdmission(t *testing.T) {
	for _, mode := range []string{"h2-connect", "h3-post"} {
		t.Run(mode, func(t *testing.T) {
			s := &Server{Username: "alice", Password: "secret", EnableUDP: true, MaxTunnels: 1, DialTimeout: 40 * time.Millisecond}
			c, _ := testClient(t, s)
			if mode == "h3-post" {
				node := setupEndpoint(t, c, s)
				startNativeH3(t, node, s)
				usePrimary(t, c, node.URL)
			}
			if err := c.SetTransport(mode); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			reader, writer := io.Pipe()
			defer writer.Close()
			defer reader.Close()
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.ServerURL.String()+udpPath, reader)
			req.Header.Set("Proxy-Authorization", basicAuth("alice", "secret"))
			started := time.Now()
			resp, err := c.transport.RoundTrip(req)
			if resp != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			if ctx.Err() != nil || time.Since(started) > time.Second {
				t.Fatal("server held incomplete body until client cancellation", err)
			}
			if err == nil && resp.StatusCode == http.StatusOK {
				t.Fatal("incomplete datagram succeeded")
			}
			waitAccess(t, func() bool { return s.activeTunnels.Load() == 0 })
		})
	}
}
