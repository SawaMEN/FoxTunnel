package firefox

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/VetroffProxy/internal/bond"
	"github.com/SawaMEN/VetroffProxy/internal/cluster"
	"github.com/SawaMEN/VetroffProxy/internal/tunnel"
	"github.com/quic-go/quic-go"
)

func TestGeckoManagedBond(t *testing.T) {
	bundle := os.Getenv("VETROFF_NECKO_BUNDLE")
	runtime := os.Getenv("VETROFF_XPCSHELL")
	if bundle == "" && runtime == "" {
		t.Skip("verified native bundle required")
	}
	for _, mode := range []string{"h2-connect", "h3-connect"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "h3-connect" && bundle == "" {
				t.Skip("verified H3 native bundle required")
			}
			testGeckoManagedBond(t, bundle, runtime, mode)
		})
	}
}

func testGeckoManagedBond(t *testing.T, bundle, runtime, mode string) {
	t.Helper()
	type originConnectionKey struct{}
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
				if bundle == "" && lanes {
					t.Skip("verified new streaming-upload bundle required for persistent lanes")
				}
				target := nativeEcho(t)
				server := &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true}
				hub := server.NewBondHub()
				defer hub.Close()
				server.Bond = hub
				var failed atomic.Int32
				failed.Store(-1)
				var calls [2]atomic.Int32
				var activeLanes [2]atomic.Int32
				var cutLanes atomic.Int32
				var paths [2]context.Context
				var losePath [2]context.CancelFunc
				for index := range paths {
					paths[index], losePath[index] = context.WithCancel(context.Background())
					defer losePath[index]()
				}
				var manifest cluster.Manifest
				ready := make(chan struct{})
				endpoint := func(index int) Config {
					return nativeProxyConfigured(t, mode, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						<-ready
						if r.URL.Path == cluster.Path {
							w.Header().Set("Content-Type", "application/json")
							json.NewEncoder(w).Encode(manifest)
							return
						}
						expected := 2
						if mode == "h3-connect" {
							expected = 3
						}
						if r.ProtoMajor != expected {
							http.Error(w, "native carrier protocol required", 400)
							return
						}
						calls[index].Add(1)
						if int32(index) == failed.Load() {
							http.Error(w, "outage", 503)
							return
						}
						if r.Header.Get(bond.LaneHeader) != "" {
							activeLanes[index].Add(1)
							defer activeLanes[index].Add(-1)
							// Drop the origin connection, including lanes still binding.
							// Closing only a request body can manufacture an HTTP 400
							// binding rejection instead of a real network failure.
							stop := context.AfterFunc(paths[index], func() {
								cutLanes.Add(1)
								if mode == "h3-connect" {
									r.Context().Value(nativeH3ConnectionKey{}).(*quic.Conn).CloseWithError(0x100, "test origin outage")
								} else {
									r.Context().Value(originConnectionKey{}).(net.Conn).Close()
								}
							})
							defer stop()
						}
						server.ServeHTTP(w, r)
					}), func(server *httptest.Server) {
						server.Config.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
							return context.WithValue(ctx, originConnectionKey{}, conn)
						}
					})
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
				c.SetManagedHTTPTransport(mode, func() (tunnel.ManagedTransport, error) {
					if bundle != "" {
						return NewManaged(bundle, a)
					}
					return newManagedRuntime(runtime, a)
				})
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
						index := 0
						if lanes {
							if activeLanes[index].Load() == 0 {
								index = 1
							}
							if activeLanes[index].Load() == 0 {
								t.Fatal("no active native lane available for path-loss test")
							}
						}
						failed.Store(int32(index))
						losePath[index]()
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
				if lanes && cutLanes.Load() == 0 {
					t.Fatal("path loss did not interrupt an established native lane")
				}
			})
		}
	}
}
