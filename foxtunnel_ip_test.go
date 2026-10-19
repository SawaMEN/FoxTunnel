package foxtunnel_test

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	ft "github.com/SawaMEN/FoxTunnel"
)

func TestPublicIPOwnershipAndCapacity(t *testing.T) {
	secret := "sdk-packet-012345678901234567890123456789"
	controller, err := ft.NewAccessController(ft.AccessPolicy{Version: 1, Users: []ft.AccessUser{{ID: "sdk", Username: "sdk", Password: secret}}}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	// The host handler implements its own TUN/policy; this fixture only echoes
	// records to verify the public SDK boundary and lifecycle without privileges.
	server, err := ft.NewServer(ft.ServerConfig{Access: controller, IPHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		http.NewResponseController(w).Flush()
		buf := make([]byte, 1300)
		for {
			n, e := r.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				http.NewResponseController(w).Flush()
			}
			if e != nil {
				return
			}
		}
	})})
	if err != nil {
		t.Fatal(err)
	}
	node := httptest.NewUnstartedServer(server)
	node.EnableHTTP2 = true
	node.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	node.StartTLS()
	defer node.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: node.Certificate().Raw}), 0600) != nil {
		t.Fatal("certificate fixture")
	}
	c, err := ft.NewClient(ft.ClientConfig{ServerURL: node.URL, CACertFile: ca, Credentials: ft.Credentials{Username: "sdk", Password: secret}, MaxConnections: 1, TLSBackend: "go"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	conn, err := c.DialIP(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	packet := make([]byte, 28)
	packet[0] = 0x45
	if err := conn.WritePacket(packet); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, ft.IPMTU)
	if n, e := conn.ReadPacket(buf); e != nil || n != len(packet) {
		t.Fatal(n, e)
	}
	if other, err := c.DialIP(context.Background()); !errors.Is(err, ft.ErrCapacity) {
		if other != nil {
			other.Close()
		}
		t.Fatal("IP session bypassed SDK capacity", err)
	}
	c.Close()
	if _, err := conn.ReadPacket(buf); err == nil || err == io.ErrShortBuffer {
		t.Fatal("Client.Close left packet session alive", err)
	}
}
