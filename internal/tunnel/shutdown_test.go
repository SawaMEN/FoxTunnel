package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServeContextStopsActiveAndIncompleteConnections(t *testing.T) {
	for _, mode := range []string{"h2-connect", "h2-post", "h3-post", "wss", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up", "bond"} {
		t.Run(mode, func(t *testing.T) {
			targetClosed := make(chan struct{})
			target := testDestination(t, func(c net.Conn) { io.Copy(c, c); close(targetClosed) })
			server := &Server{Username: "alice", Password: "secret", AllowPrivate: true}
			if mode == "bond" {
				hub := server.NewBondHub()
				defer hub.Close()
				server.Bond = hub
			}
			node := httptest.NewUnstartedServer(server)
			node.EnableHTTP2 = true
			node.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
			node.StartTLS()
			defer node.Close()
			if mode == "h3-post" {
				startNativeH3(t, node, server)
			}
			ca := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: node.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			client, err := NewClient(node.URL, "alice", "secret", ca)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := client.SetTLSBackend("go"); err != nil {
				t.Fatal(err)
			}
			if mode == "bond" {
				secondary := httptest.NewUnstartedServer(server)
				secondary.EnableHTTP2 = true
				secondary.TLS = node.TLS.Clone()
				secondary.StartTLS()
				defer secondary.Close()
				if err := client.SetFallbackServers([]string{secondary.URL}); err != nil {
					t.Fatal(err)
				}
				err = client.EnableBond()
			} else {
				err = client.SetTransport(mode)
			}
			if err != nil {
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
			go func() { done <- client.ServeContext(ctx, listener) }()
			conn, code := connectSOCKS(t, listener.Addr().String(), target)
			if code != 0 {
				t.Fatalf("SOCKS code %d", code)
			}
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			var reply [4]byte
			if _, err := io.ReadFull(conn, reply[:]); err != nil {
				t.Fatal(err)
			}
			pending, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer pending.Close()
			pending.SetDeadline(time.Now().Add(2 * time.Second))
			pending.Write([]byte{5})
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("ServeContext did not join its handlers")
			}
			conn.SetReadDeadline(time.Now().Add(time.Second))
			var one [1]byte
			if _, err := conn.Read(one[:]); err == nil {
				t.Fatal("active SOCKS socket survived cancellation")
			}
			if _, err := pending.Read(one[:]); err == nil {
				t.Fatal("incomplete greeting survived cancellation")
			}
			select {
			case <-targetClosed:
			case <-time.After(2 * time.Second):
				t.Fatal("destination survived cancellation")
			}
		})
	}
}
