package firefox

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/cluster"
	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
)

func TestGeckoManagedBond(t *testing.T) {
	bundle := os.Getenv("FOXTUNNEL_NECKO_BUNDLE")
	if bundle == "" {
		t.Skip("verified native bundle required")
	}
	for _, lanes := range []bool{false, true} {
		for _, discovery := range []bool{false, true} {
			name := "rpc"
			if lanes {
				name = "lanes"
			}
			if discovery {
				name += "-discovery"
			}
			t.Run(name, func(t *testing.T) {
				target := nativeEcho(t)
				server := &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true}
				hub := server.NewBondHub()
				defer hub.Close()
				server.Bond = hub
				var failed atomic.Bool
				var calls [2]atomic.Int32
				var manifest cluster.Manifest
				ready := make(chan struct{})
				endpoint := func(index int) Config {
					return nativeProxy(t, "h2-connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						<-ready
						if r.URL.Path == cluster.Path {
							w.Header().Set("Content-Type", "application/json")
							json.NewEncoder(w).Encode(manifest)
							return
						}
						if r.ProtoMajor != 2 {
							http.Error(w, "native H2 required", 400)
							return
						}
						calls[index].Add(1)
						if index == 0 && failed.Load() {
							http.Error(w, "outage", 503)
							return
						}
						server.ServeHTTP(w, r)
					}))
				}
				a, b := endpoint(0), endpoint(1)
				first, err := os.ReadFile(a.CACert)
				if err != nil {
					t.Fatal(err)
				}
				second, err := os.ReadFile(b.CACert)
				if err != nil {
					t.Fatal(err)
				}
				a.CACert = filepath.Join(t.TempDir(), "roots.pem")
				if err = os.WriteFile(a.CACert, append(first, second...), 0600); err != nil {
					t.Fatal(err)
				}
				identity, err := hub.Identity()
				if err != nil {
					t.Fatal(err)
				}
				manifest = cluster.Manifest{Version: 1, HubID: identity, ValidFor: 120, Nodes: []cluster.Node{{URL: a.Server, Weight: 1}, {URL: b.Server, Weight: 1}}}
				close(ready)
				c, err := tunnel.NewClient(a.Server, "u", "p", a.CACert)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				c.SetManagedHTTPTransport("h2-connect", func() (tunnel.ManagedTransport, error) { return NewManaged(bundle, a) })
				c.BondAdaptive = true
				c.BondAutoTune = true
				c.BondTraffic = "auto"
				c.BondLanes = lanes
				c.FallbackAttemptTimeout = time.Second
				c.ConnectTimeout = 10 * time.Second
				if discovery {
					err = c.EnableBondDiscovery(context.Background())
				} else {
					if err = c.SetFallbackServers([]string{b.Server}); err == nil {
						err = c.EnableBond()
					}
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
				go func() { done <- c.ServeContext(ctx, listener) }()
				defer func() {
					cancel()
					listener.Close()
					c.Close()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("native bond SOCKS workers survived close")
					}
				}()
				conn, err := nativeSOCKS(listener.Addr().String(), target)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(30 * time.Second))
				payload := bytes.Repeat([]byte{0, 255, 128, 42}, 32<<10)
				for i := 0; i < 2; i++ {
					if i == 1 {
						failed.Store(true)
					}
					written := make(chan error, 1)
					go func() { _, e := conn.Write(payload); written <- e }()
					got := make([]byte, len(payload))
					if _, err = io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
						t.Fatalf("native bond round %d: %v", i, err)
					}
					if err = <-written; err != nil {
						t.Fatal(err)
					}
				}
				if calls[1].Load() == 0 {
					t.Fatal("secondary HTTPS origin was not used")
				}
			})
		}
	}
}
