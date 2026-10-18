package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/SawaMEN/FoxTunnel/internal/xhttp"
)

func TestXHTTPSettings(t *testing.T) { testXHTTPSettings(t, "go") }
func testXHTTPSettings(t *testing.T, backend string) {
	for _, mode := range []string{"xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) {
			settings, _ := xhttp.Normalize("/api/custom-v1", "route.example:8443")
			var seen atomic.Int64
			s := &Server{Username: "alice", Password: "secret", AllowPrivate: true, XHTTPSettings: settings}
			c, addr := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host != settings.Host || r.TLS.ServerName != "example.com" || !xhttp.MatchesAt(r, settings) {
					t.Error("carrier settings or TLS identity changed", r.Host, r.TLS.ServerName, r.URL.Path)
				}
				seen.Add(1)
				s.ServeHTTP(w, r)
			}))
			if err := c.SetTLSBackend(backend); err != nil {
				t.Fatal(err)
			}
			if err := c.SetServerIdentity("example.com", ""); err != nil {
				t.Fatal(err)
			}
			if err := c.SetTransport(mode); err != nil {
				t.Fatal(err)
			}
			if err := c.SetXHTTPSettings(settings.Path, settings.Host); err != nil {
				t.Fatal(err)
			}
			target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			conn, code := connectSOCKS(t, addr, target)
			defer conn.Close()
			if code != 0 {
				t.Fatal(code)
			}
			payload := bytes.Repeat([]byte("XHTTP independent Host/SNI"), 100)
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
				t.Fatal(err)
			}
			if seen.Load() == 0 {
				t.Fatal("route not exercised")
			}
		})
	}
}
func TestXHTTPRejectedRouteUsesCover(t *testing.T) {
	settings, _ := xhttp.Normalize("/api/route", "route.example")
	s := &Server{Username: "alice", Password: "secret", XHTTPSettings: settings, Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("credentials reached cover")
		}
		w.WriteHeader(418)
	})}
	for _, c := range []struct{ path, host, auth string }{{settings.Path, "wrong.example", basicAuth("alice", "secret")}, {xhttp.Path, settings.Host, basicAuth("alice", "secret")}, {settings.Path, settings.Host, basicAuth("alice", "wrong")}} {
		r := httptest.NewRequest("POST", "https://node"+c.path, nil)
		r.ProtoMajor = 2
		r.Host = c.host
		r.Header.Set("Proxy-Authorization", c.auth)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 418 || s.xhttpServer != nil {
			t.Fatal("rejected route allocated carrier", w.Code)
		}
	}
}
func TestXHTTPSettingsRequireExplicitMode(t *testing.T) {
	c, err := NewClient("https://main.example", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetXHTTPSettings("/api", ""); err == nil {
		t.Fatal("XHTTP settings silently ignored")
	}
	if err := c.SetTransport("xhttp-stream-up"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetXHTTPSettings("/api", ""); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTransport("wss"); err == nil {
		t.Fatal("XHTTP settings silently lost")
	}
	if err := c.SetXHTTPSettings("", ""); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTransport("wss"); err != nil {
		t.Fatal(err)
	}
}
func TestXHTTPThroughHTTPSFrontend(t *testing.T) {
	for _, mode := range []string{"xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) {
			settings, _ := xhttp.Normalize("/relay/api", "route.example")
			s := &Server{Username: "alice", Password: "secret", AllowPrivate: true, XHTTPSettings: settings}
			backend := httptest.NewUnstartedServer(s)
			backend.EnableHTTP2 = true
			backend.StartTLS()
			defer backend.Close()
			upstream, _ := url.Parse(backend.URL)
			proxy := &httputil.ReverseProxy{Transport: backend.Client().Transport, FlushInterval: -1, Rewrite: func(p *httputil.ProxyRequest) {
				p.SetURL(upstream)
				p.Out.Host = p.In.Host
				// Proxy-Authorization is hop-by-hop. This controlled frontend explicitly
				// forwards it to the one verified backend rather than dropping it.
				p.Out.Header.Set("Proxy-Authorization", p.In.Header.Get("Proxy-Authorization"))
			}}
			c, _ := testClient(t, proxy)
			defer c.Close()
			if err := c.SetTransport(mode); err != nil {
				t.Fatal(err)
			}
			if err := c.SetXHTTPSettings(settings.Path, settings.Host); err != nil {
				t.Fatal(err)
			}
			target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			stream, err := c.openTunnel(context.Background(), target)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.close()
			if _, err := stream.writer.Write([]byte("frontend")); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 8)
			if _, err := io.ReadFull(stream.response.Body, got); err != nil || string(got) != "frontend" {
				t.Fatal(err)
			}
		})
	}
}
