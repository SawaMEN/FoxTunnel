package firefox

import (
	"bytes"
	"context"
	"fmt"
	"github.com/SawaMEN/VetroffProxy/internal/tunnel"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Controlled loopback path disruption; it does not modify the host network.
// A UDP upstream socket rotation simulates a NAT source-port rebind while the
// client-facing proxy address remains fixed. One active QUIC client per relay.
type networkRelay struct {
	sync.Mutex
	enabled         bool
	conns           map[net.Conn]bool
	tcp             net.Listener
	front, upstream net.PacketConn
	client          net.Addr
	destination     net.Addr
	done            chan struct{}
}

func newNetworkRelay(t *testing.T, mode, target string) *networkRelay {
	t.Helper()
	r := &networkRelay{enabled: true, conns: map[net.Conn]bool{}, done: make(chan struct{})}
	if mode == "h2-connect" {
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		r.tcp = listener
		go func() {
			defer close(r.done)
			for {
				c, e := listener.Accept()
				if e != nil {
					return
				}
				go func() {
					defer c.Close()
					r.Lock()
					enabled := r.enabled
					r.Unlock()
					if !enabled {
						return
					}
					remote, e := net.DialTimeout("tcp", target, time.Second)
					if e != nil {
						return
					}
					defer remote.Close()
					r.Lock()
					if !r.enabled {
						r.Unlock()
						return
					}
					r.conns[c] = true
					r.conns[remote] = true
					r.Unlock()
					defer func() { r.Lock(); delete(r.conns, c); delete(r.conns, remote); r.Unlock() }()
					finished := make(chan struct{})
					go func() { io.Copy(remote, c); remote.Close(); close(finished) }()
					io.Copy(c, remote)
					c.Close()
					<-finished
				}()
			}
		}()
	} else {
		front, e := net.ListenPacket("udp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		r.front = front
		r.destination, e = net.ResolveUDPAddr("udp", target)
		if e != nil {
			t.Fatal(e)
		}
		if e := r.rotate(); e != nil {
			t.Fatal(e)
		}
		go func() {
			defer close(r.done)
			b := make([]byte, 65536)
			for {
				n, client, e := front.ReadFrom(b)
				if e != nil {
					return
				}
				r.Lock()
				if r.enabled {
					r.client = client
					r.upstream.WriteTo(b[:n], r.destination)
				}
				r.Unlock()
			}
		}()
	}
	t.Cleanup(func() {
		r.setEnabled(false)
		if r.tcp != nil {
			r.tcp.Close()
		} else {
			r.front.Close()
			r.Lock()
			r.upstream.Close()
			r.Unlock()
		}
		<-r.done
	})
	return r
}
func (r *networkRelay) address() string {
	if r.tcp != nil {
		return r.tcp.Addr().String()
	}
	return r.front.LocalAddr().String()
}
func (r *networkRelay) setEnabled(enabled bool) {
	r.Lock()
	defer r.Unlock()
	r.enabled = enabled
	if !enabled {
		for c := range r.conns {
			c.Close()
		}
	}
}
func (r *networkRelay) rotate() error {
	socket, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	r.Lock()
	old := r.upstream
	r.upstream = socket
	r.Unlock()
	if old != nil {
		old.Close()
	}
	go func() {
		b := make([]byte, 65536)
		for {
			n, _, e := socket.ReadFrom(b)
			if e != nil {
				return
			}
			r.Lock()
			if r.enabled && r.client != nil && r.upstream == socket {
				r.front.WriteTo(b[:n], r.client)
			}
			r.Unlock()
		}
	}()
	return nil
}
func TestGeckoNetworkRecovery(t *testing.T) {
	if os.Getenv("VETROFF_XPCSHELL") == "" {
		t.Skip("native runtime required")
	}
	for _, mode := range []string{"h2-connect", "h3-connect"} {
		t.Run(mode, func(t *testing.T) {
			echo := nativeEcho(t)
			cfg := nativeProxy(t, mode, &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true})
			relay := newNetworkRelay(t, mode, strings.TrimPrefix(cfg.Server, "https://"))
			cfg.Server = "https://" + relay.address()
			cfg.IdleTimeoutMS = 1500
			cfg.ConnectTimeoutMS = 2000
			cfg.DrainTimeoutMS = 1000
			h := startOperationalHelper(t, context.Background(), cfg)
			c, e := nativeSOCKS(h.listen, echo)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			exchange := func() error {
				c.SetDeadline(time.Now().Add(5 * time.Second))
				payload := bytes.Repeat([]byte{0, 255, 13, 10, 42}, 5000)
				if _, e := c.Write(payload); e != nil {
					return e
				}
				received := make([]byte, len(payload))
				if _, e := io.ReadFull(c, received); e != nil {
					return e
				}
				if !bytes.Equal(payload, received) {
					return fmt.Errorf("relay binary mismatch")
				}
				return nil
			}
			if e := exchange(); e != nil {
				t.Fatal(e)
			}
			if mode == "h3-connect" {
				relay.Lock()
				before := relay.upstream.LocalAddr().String()
				relay.Unlock()
				if e := relay.rotate(); e != nil {
					t.Fatal(e)
				}
				relay.Lock()
				after := relay.upstream.LocalAddr().String()
				relay.Unlock()
				if before == after {
					t.Fatal("source port did not change")
				}
				if e := exchange(); e != nil {
					t.Fatalf("active QUIC stream did not survive NAT rebinding: %v", e)
				}
			}
			relay.setEnabled(false)
			c.SetReadDeadline(time.Now().Add(4 * time.Second))
			var b [1]byte
			if _, e := c.Read(b[:]); e == nil {
				t.Fatal("broken path remained readable")
			} else if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
				t.Fatal("broken path did not terminate within idle budget")
			}
			c.Close()
			if c, e := nativeSOCKS(h.listen, echo); e == nil {
				c.Close()
				t.Fatal("CONNECT succeeded during path outage")
			}
			relay.setEnabled(true)
			if e := operationalRound(h, echo, 29); e != nil {
				t.Fatalf("new CONNECT failed after path recovery: %v\n%s", e, h.stderr.text())
			}
			t.Log("same helper recovered after outage; interrupted streams were not replayed")
		})
	}
}

func TestNetworkRelayPeers(t *testing.T) {
	t.Run("tcp", func(t *testing.T) {
		target := nativeEcho(t)
		r := newNetworkRelay(t, "h2-connect", target)
		c, e := net.Dial("tcp", r.address())
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		c.Write([]byte("hello"))
		b := make([]byte, 5)
		if _, e := io.ReadFull(c, b); e != nil || string(b) != "hello" {
			t.Fatal("TCP relay", e)
		}
		r.setEnabled(false)
		if _, e := c.Read(b); e == nil {
			t.Fatal("TCP path did not close")
		}
		r.setEnabled(true)
		next, e := net.Dial("tcp", r.address())
		if e != nil {
			t.Fatal(e)
		}
		next.Close()
	})
	t.Run("udp", func(t *testing.T) {
		socket, e := net.ListenPacket("udp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer socket.Close()
		go func() {
			b := make([]byte, 2048)
			for {
				n, a, e := socket.ReadFrom(b)
				if e != nil {
					return
				}
				socket.WriteTo(b[:n], a)
			}
		}()
		r := newNetworkRelay(t, "h3-connect", socket.LocalAddr().String())
		client, e := net.Dial("udp", r.address())
		if e != nil {
			t.Fatal(e)
		}
		defer client.Close()
		exchange := func() {
			t.Helper()
			client.SetDeadline(time.Now().Add(time.Second))
			client.Write([]byte("hello"))
			b := make([]byte, 5)
			if _, e := io.ReadFull(client, b); e != nil || string(b) != "hello" {
				t.Fatal("UDP relay", e)
			}
		}
		exchange()
		if e := r.rotate(); e != nil {
			t.Fatal(e)
		}
		exchange()
		r.setEnabled(false)
		client.SetDeadline(time.Now().Add(100 * time.Millisecond))
		client.Write([]byte("drop"))
		b := make([]byte, 4)
		if _, e := client.Read(b); e == nil {
			t.Fatal("UDP outage did not drop data")
		}
		r.setEnabled(true)
		exchange()
	})
}
