package consumer_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	ft "github.com/SawaMEN/FoxTunnel"
)

func TestPublicUDPAPIAndOwnership(t *testing.T) {
	for _, mode := range []string{"h2-connect", "h3-post"} {
		t.Run(mode, func(t *testing.T) {
			endpoint, ca, creds, h3 := publicProxy(t, true)
			target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			go func() {
				var b [1500]byte
				for {
					n, peer, err := target.ReadFromUDP(b[:])
					if err != nil {
						return
					}
					_, _ = target.WriteToUDP(b[:n], peer)
				}
			}()
			client, err := ft.NewClient(ft.ClientConfig{ServerURL: endpoint, CACertFile: ca, Credentials: creds, EnableUDP: true, Transport: mode, TLSBackend: "go", RequireProtocolNegotiation: true, MaxConnections: 1, ConnectTimeout: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			d := ft.Datagram{Address: target.LocalAddr().String(), Payload: []byte("external UDP API")}
			if reply, err := client.ExchangeUDP(ctx, d); err != nil || !bytes.Equal(reply.Payload, d.Payload) {
				t.Fatal("one-shot", err)
			}
			flow, err := client.OpenUDP(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer flow.Close()
			if _, err = client.OpenUDP(ctx); !errors.Is(err, ft.ErrCapacity) {
				t.Fatal("UDP escaped shared limit", err)
			}
			if _, err = client.DialContext(ctx, "tcp", "example.org:443"); !errors.Is(err, ft.ErrCapacity) {
				t.Fatal("TCP escaped UDP limit", err)
			}
			if _, err = client.ExchangeUDP(ctx, d); !errors.Is(err, ft.ErrCapacity) {
				t.Fatal("one-shot escaped UDP limit", err)
			}
			wait, stop := context.WithTimeout(ctx, 25*time.Millisecond)
			_, err = flow.Receive(wait)
			stop()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("Receive cancellation", err)
			}
			if err = flow.Send(ctx, d); err != nil {
				t.Fatal(err)
			}
			if reply, err := flow.Receive(ctx); err != nil || !bytes.Equal(reply.Payload, d.Payload) {
				t.Fatal("stream", err)
			}
			if err = client.NotifyNetworkChange(); err != nil {
				t.Fatal(err)
			}
			if err = flow.Send(ctx, d); err != nil {
				t.Fatal(err)
			}
			if _, err = flow.Receive(ctx); err != nil {
				t.Fatal("network signal destroyed active flow", err)
			}
			flow.Close()
			if _, err = client.ExchangeUDP(ctx, d); err != nil {
				t.Fatal("closed flow retained capacity", err)
			}
			active, err := client.OpenUDP(ctx)
			if err != nil {
				t.Fatal(err)
			}
			received := make(chan error, 1)
			go func() { _, err := active.Receive(context.Background()); received <- err }()
			client.Close()
			select {
			case err := <-received:
				if err == nil {
					t.Fatal("client Close kept UDP alive")
				}
			case <-time.After(time.Second):
				t.Fatal("UDP receive stranded on Close")
			}
			active.Close()
			if _, err = client.OpenUDP(ctx); !errors.Is(err, net.ErrClosed) {
				t.Fatal("UDP opened after Client.Close", err)
			}
			if mode == "h3-post" && h3.Load() == 0 {
				t.Fatal("no actual HTTP/3 UDP requests")
			}
		})
	}
}

func TestPublicUDPDisabled(t *testing.T) {
	endpoint, ca, creds, _ := publicProxy(t, true)
	client, err := ft.NewClient(ft.ClientConfig{ServerURL: endpoint, CACertFile: ca, Credentials: creds, TLSBackend: "go"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err = client.OpenUDP(context.Background()); !errors.Is(err, ft.ErrUDPDisabled) {
		t.Fatal("UDP opt-in ignored", err)
	}
	if _, err = client.ExchangeUDP(context.Background(), ft.Datagram{Address: "127.0.0.1:53"}); !errors.Is(err, ft.ErrUDPDisabled) {
		t.Fatal("UDP exchange opt-in ignored", err)
	}
}

func TestPublicUDPCloseCancelsPendingSetup(t *testing.T) {
	entered := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := ft.NewClient(ft.ClientConfig{ServerURL: server.URL, CACertFile: ca, Credentials: ft.Credentials{Username: "alice", Password: "secret"}, TLSBackend: "go", EnableUDP: true, ConnectTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		flow, err := client.OpenUDP(context.Background())
		if flow != nil {
			flow.Close()
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("UDP setup did not start")
	}
	client.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal("pending UDP setup survived Close", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending UDP setup stranded")
	}
}
