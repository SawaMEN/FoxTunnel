package firefox

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
	"github.com/SawaMEN/FoxTunnel/internal/xhttp"
)

func TestGeckoManagedXHTTP(t *testing.T) {
	runtime := os.Getenv("FOXTUNNEL_XPCSHELL")
	bundle := os.Getenv("FOXTUNNEL_NECKO_BUNDLE")
	if runtime == "" && bundle == "" {
		t.Skip("explicit native research runtime required")
	}
	for _, mode := range []string{"xhttp-packet-up", "xhttp-stream-one", "xhttp-stream-up"} {
		t.Run(mode, func(t *testing.T) {
			if bundle == "" && mode != "xhttp-packet-up" {
				t.Skip("new verified streaming-upload bundle required")
			}
			var posts atomic.Int32
			route := xhttp.Settings{Path: "/native/carrier/", Host: "native-route.example"}
			server := &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true, Padding: true, XHTTPSettings: route}
			cfg := nativeProxy(t, "h2-connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					posts.Add(1)
					want := "application/grpc"
					if mode == "xhttp-packet-up" {
						want = "application/octet-stream"
					}
					if r.Header.Get("Content-Type") != want {
						http.Error(w, "carrier Content-Type", 400)
						return
					}
				}
				server.ServeHTTP(w, r)
			}))
			c, err := tunnel.NewClient(cfg.Server, "u", "p", cfg.CACert)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetManagedHTTPTransport(mode, func() (tunnel.ManagedTransport, error) {
				if bundle != "" {
					return NewManaged(bundle, cfg)
				}
				return newManagedRuntime(runtime, cfg)
			})
			if err = c.SetXHTTPSettings(route.Path, route.Host); err != nil {
				t.Fatal(err)
			}
			c.Padding = true
			c.RequireProtocolNegotiation = true
			c.ConnectTimeout = 10 * time.Second
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := c.DialContext(ctx, "tcp", nativeEcho(t))
			if err != nil {
				t.Fatal("native XHTTP setup:", err)
			}
			defer conn.Close()
			cancel()
			conn.SetDeadline(time.Now().Add(15 * time.Second))
			data := bytes.Repeat([]byte{0, 128, 255, 42}, 64<<10)
			sent := make(chan error, 1)
			go func() {
				_, e := conn.Write(data)
				if e == nil {
					e = conn.(interface{ CloseWrite() error }).CloseWrite()
				}
				sent <- e
			}()
			got, err := io.ReadAll(conn)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("native XHTTP binary padding/FIN: %d, %v", len(got), err)
			}
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
			if posts.Load() == 0 {
				t.Fatal("native carrier did not upload")
			}
		})
	}
}
