package firefox

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

func TestGeckoManagedUDPMultiNode(t *testing.T) {
	bundle := os.Getenv("FOXTUNNEL_NECKO_BUNDLE")
	if bundle == "" {
		t.Skip("new verified native streaming-upload bundle required")
	}
	var streams [2]atomic.Int32
	makeEndpoint := func(index int) Config {
		server := &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true, EnableUDP: true}
		return nativeProxy(t, "h2-connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/foxtunnel-udp-stream-v2" {
				if r.ProtoMajor != 2 {
					http.Error(w, "native H2 required", 400)
					return
				}
				streams[index].Add(1)
			}
			server.ServeHTTP(w, r)
		}))
	}
	a, b := makeEndpoint(0), makeEndpoint(1)
	roots, err := os.ReadFile(a.CACert)
	if err != nil {
		t.Fatal(err)
	}
	more, err := os.ReadFile(b.CACert)
	if err != nil {
		t.Fatal(err)
	}
	a.CACert = filepath.Join(t.TempDir(), "roots.pem")
	if err = os.WriteFile(a.CACert, append(roots, more...), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := tunnel.NewClient(a.Server, "u", "p", a.CACert)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetManagedHTTPTransport("h2-connect", func() (tunnel.ManagedTransport, error) { return NewManaged(bundle, a) })
	c.EnableUDP = true
	c.UDPStreaming = true
	c.UDPMultiNode = true
	c.ConnectTimeout = 10 * time.Second
	if err = c.SetFallbackServers([]string{b.Server}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.ServeContext(ctx, listener) }()
	defer func() {
		cancel()
		listener.Close()
		c.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("native UDP multi-node workers survived close")
		}
	}()
	control, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	control.SetDeadline(time.Now().Add(15 * time.Second))
	control.Write([]byte{5, 1, 0})
	var greeting [2]byte
	if _, err = io.ReadFull(control, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatal("SOCKS greeting", err)
	}
	control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	var bind [10]byte
	if _, err = io.ReadFull(control, bind[:]); err != nil || bind[1] != 0 || bind[3] != 1 {
		t.Fatal("SOCKS UDP association", err)
	}
	socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IP(bind[4:8]), Port: int(binary.BigEndian.Uint16(bind[8:]))})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	socket.SetDeadline(time.Now().Add(15 * time.Second))
	targets := []*net.UDPConn{managedUDPEcho(t), managedUDPEcho(t)}
	for index, target := range targets {
		for sequence := 0; sequence < 3; sequence++ {
			payload := []byte{byte(index), byte(sequence), 0, 255, 128, 42}
			wire, err := udpproto.Encode(udpproto.Packet{Host: "127.0.0.1", Port: uint16(target.LocalAddr().(*net.UDPAddr).Port), Data: payload})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = socket.Write(wire); err != nil {
				t.Fatal(err)
			}
			var response [udpproto.MaxDatagram + 1]byte
			n, err := socket.Read(response[:])
			if err != nil {
				t.Fatal("native multi-node datagram", err)
			}
			packet, err := udpproto.Parse(response[:n])
			if err != nil || packet.Port != uint16(target.LocalAddr().(*net.UDPAddr).Port) || !bytes.Equal(packet.Data, payload) {
				t.Fatal("native multi-node response changed flow/bytes", err)
			}
		}
	}
	if streams[0].Load() != 1 || streams[1].Load() != 1 {
		t.Fatalf("expected one native stream per trusted origin: %d %d", streams[0].Load(), streams[1].Load())
	}
}
func managedUDPEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var b [2048]byte
		for {
			n, peer, e := socket.ReadFromUDP(b[:])
			if e != nil {
				return
			}
			socket.WriteToUDP(b[:n], peer)
		}
	}()
	t.Cleanup(func() { socket.Close(); <-done })
	return socket
}
