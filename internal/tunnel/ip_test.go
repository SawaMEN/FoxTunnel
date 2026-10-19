package tunnel

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/access"
	"github.com/SawaMEN/FoxTunnel/internal/ippacket"
	"github.com/SawaMEN/FoxTunnel/internal/linuxvpn"
)

type ipEchoDevice struct {
	packets  chan []byte
	done     chan struct{}
	once     sync.Once
	injected *atomic.Int64
}

func (d *ipEchoDevice) Read(p []byte) (int, error) {
	select {
	case data := <-d.packets:
		return copy(p, data), nil
	case <-d.done:
		return 0, io.EOF
	}
}
func (d *ipEchoDevice) Write(p []byte) (int, error) {
	data := append([]byte(nil), p...)
	d.injected.Add(1)
	if data[0]>>4 == 4 {
		copy(data[12:16], p[16:20])
		copy(data[16:20], p[12:16])
		data[10] = 0
		data[11] = 0
		ipChecksum(data)
	} else {
		copy(data[8:24], p[24:40])
		copy(data[24:40], p[8:24])
	}
	select {
	case d.packets <- data:
		return len(p), nil
	case <-d.done:
		return 0, io.EOF
	}
}
func (d *ipEchoDevice) Close() error { d.once.Do(func() { close(d.done) }); return nil }
func ipChecksum(p []byte) {
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
}
func testIP(v6 bool) []byte {
	if v6 {
		p := make([]byte, 48)
		p[0] = 0x60
		p[5] = 8
		p[6] = 17
		p[7] = 64
		a, b := netip.MustParseAddr("fd62:666f:78::2").As16(), netip.MustParseAddr("2620:fe::fe").As16()
		copy(p[8:24], a[:])
		copy(p[24:40], b[:])
		return p
	}
	p := make([]byte, 28)
	p[0] = 0x45
	p[3] = 28
	p[8] = 64
	p[9] = 17
	copy(p[12:16], []byte{100, 96, 0, 2})
	copy(p[16:20], []byte{9, 9, 9, 9})
	p[25] = 8
	ipChecksum(p)
	return p
}
func TestIPTransports(t *testing.T) { testIPTransports(t, "go", false) }
func testIPTransports(t *testing.T, backend string, neqo bool) {
	for _, mode := range []string{"h2-connect", "h2-post", "h3-post", "wss", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		if backend == "nss" && mode == "h3-post" && !neqo {
			continue
		}
		if neqo && mode != "h3-post" {
			continue
		}
		t.Run(mode, func(t *testing.T) {
			secret := "packet-012345678901234567890123456789"
			policy := access.Document{Version: 1, Users: []access.User{{ID: "alice", Username: "alice", Password: secret}}}
			manager, err := access.New(policy, "")
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			var injected atomic.Int64
			hub := &linuxvpn.Hub{Peers: map[string]linuxvpn.Peer{"alice": {ID: "alice", IPv4: "100.96.0.2", IPv6: "fd62:666f:78::2"}}, Open: func(context.Context, linuxvpn.Peer) (linuxvpn.Device, error) {
				return &ipEchoDevice{packets: make(chan []byte, 1), done: make(chan struct{}), injected: &injected}, nil
			}}
			server := &Server{Access: manager, IP: hub}
			c, _ := testClient(t, server)
			c.Password = secret
			if mode == "h3-post" {
				node := setupEndpoint(t, c, server)
				startNativeH3(t, node, server)
				usePrimary(t, c, node.URL)
			}
			selected := backend
			if neqo {
				selected = "auto"
			}
			if err := c.SetTLSBackend(selected); err != nil {
				t.Fatal(err)
			}
			if err := c.SetTransport(mode); err != nil {
				t.Fatal(err)
			}
			if neqo {
				if err := c.SetQUICBackend("neqo", false, time.Second); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := c.DialIP(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			stream := &ippacket.Stream{Reader: conn, Writer: conn}
			for _, v6 := range []bool{false, true} {
				packet := testIP(v6)
				if err := stream.WritePacket(packet); err != nil {
					t.Fatal(err)
				}
				var buf [ippacket.MTU]byte
				n, err := stream.ReadPacket(buf[:])
				if err != nil {
					t.Fatal(err)
				}
				src, dst, err := ippacket.Addresses(buf[:n])
				wantSrc, wantDst, _ := ippacket.Addresses(packet)
				if err != nil || src != wantDst || dst != wantSrc {
					t.Fatal(src, dst, err)
				}
			}
			if injected.Load() != 2 || manager.Snapshot().Users[0].Bytes != 2*(28+48) {
				t.Fatal("packet metering", manager.Snapshot())
			}
			if other, err := c.DialIP(ctx); err == nil {
				other.Close()
				t.Fatal("duplicate peer IP session admitted")
			}
			policy.Users[0].Disabled = true
			if err := manager.Replace(policy); err != nil {
				t.Fatal(err)
			}
			var buf [ippacket.MTU]byte
			conn.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := stream.ReadPacket(buf[:]); err == nil {
				t.Fatal("revoked IP stream remained open")
			} else if e, ok := err.(net.Error); ok && e.Timeout() {
				t.Fatal("revocation did not close IP stream")
			}
		})
	}
}
func TestIPNegotiationFailsClosed(t *testing.T) {
	c, _ := testClient(t, &Server{Username: "alice", Password: "secret"})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if conn, err := c.DialIP(ctx); err == nil {
		conn.Close()
		t.Fatal("unconfigured IP server accepted session")
	}
	c.Padding = true
	if _, err := c.DialIP(ctx); err == nil {
		t.Fatal("IP padding accepted")
	}
}
