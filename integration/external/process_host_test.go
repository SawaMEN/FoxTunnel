package consumer_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/processhost"
)

func TestSDKProcessHost(t *testing.T) {
	binary := os.Getenv("FOX_SDK_PROCESS_BINARY")
	if binary == "" {
		t.Skip("requires a built process runtime; CI evidence rejects this skip")
	}
	endpoint, ca, creds, _ := publicProxy(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("external-process-payload")) }))
	defer origin.Close()
	for _, carrier := range []string{"h2-connect", "h3-post"} {
		t.Run(carrier, func(t *testing.T) {
			dir := t.TempDir()
			link := filepath.Join(dir, "connection.txt")
			data, _ := json.Marshal(map[string]any{"v": 1, "servers": []string{endpoint}, "username": creds.Username, "password": creds.Password, "tls": "go", "transport": carrier})
			if err := os.WriteFile(link, []byte("vetroff://"+base64.RawURLEncoding.EncodeToString(data)), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			child, err := processhost.StartClient(ctx, processhost.ClientOptions{Executable: binary, LinkFile: link, CACertFile: ca})
			if err != nil {
				t.Fatal(err)
			}
			defer child.Close()
			proxy, _ := url.Parse("socks5h://" + child.Address)
			transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			response, err := client.Get(origin.URL)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(body) != "external-process-payload" {
				t.Fatal("process path corrupted payload", err)
			}
			// Incomplete SOCKS sessions must be closed along with active work.
			local, err := net.DialTimeout("tcp", child.Address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer local.Close()
			cancel()
			select {
			case <-child.Done():
			case <-time.After(7 * time.Second):
				t.Fatal("child was not reaped")
			}
			if err := child.Wait(); err != nil {
				t.Fatal("EOF shutdown failed", err)
			}
			local.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := local.Read(make([]byte, 1)); err == nil {
				t.Fatal("SOCKS socket survived child shutdown")
			}
			rebound, err := net.Listen("tcp", child.Address)
			if err != nil {
				t.Fatal("process listener leaked", err)
			}
			rebound.Close()
		})
	}
}
