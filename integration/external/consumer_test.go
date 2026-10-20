// This is a DIFFERENT module. It cannot import FoxTunnel/internal packages.
package consumer_test

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

	ft "github.com/SawaMEN/FoxTunnel"
)

func TestIndependentProject(t *testing.T) {
	creds := ft.Credentials{Username: "consumer", Password: "test-only"}
	handler, err := ft.NewServer(ft.ServerConfig{RequireProtocolNegotiation: true, Credentials: creds, AllowPrivateDestinations: true})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		c, e := target.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()
	client, err := ft.NewClient(ft.ClientConfig{RequireProtocolNegotiation: true, ServerURL: server.URL, Credentials: creds, CACertFile: ca, Transport: "xhttp-packet-up"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	c, err := client.DialContext(context.Background(), "tcp", target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.Write([]byte("external project")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 16)
	if _, err = io.ReadFull(c, got); err != nil || string(got) != "external project" {
		t.Fatal("public API failed", string(got), err)
	}
}

func TestPublicAccessController(t *testing.T) {
	policy := ft.AccessPolicy{Version: 1, Users: []ft.AccessUser{{ID: "external", Username: "external-client", Password: "random-external-test-secret-0123456789"}}}
	controller, err := ft.NewAccessController(policy, "")
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	server, err := ft.NewServer(ft.ServerConfig{Access: controller})
	if err != nil || server == nil {
		t.Fatal("public access API", err)
	}
	if _, err := ft.NewServer(ft.ServerConfig{Access: controller, Credentials: ft.Credentials{Username: "legacy", Password: "secret"}}); err == nil {
		t.Fatal("mixed authorization accepted")
	}
	policy.Users[0].Disabled = true
	if err := controller.Replace(policy); err != nil {
		t.Fatal(err)
	}
	if s := controller.Snapshot(); len(s.Users) != 1 || !s.Users[0].Disabled {
		t.Fatal("access snapshot")
	}
}
