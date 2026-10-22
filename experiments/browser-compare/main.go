// A loopback-only transport behavior fixture, never a forwarding proxy.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/webprofile"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type phase struct {
	Started   int `json:"started"`
	Finished  int `json:"finished"`
	Canceled  int `json:"canceled"`
	Active    int `json:"active"`
	MaxActive int `json:"max_active"`
}
type connection struct {
	ID                int                 `json:"id"`
	ALPN              string              `json:"alpn,omitempty"`
	Resumed           *bool               `json:"session_resumed,omitempty"`
	Requests          map[string]int      `json:"requests"`
	H2                *webprofile.Profile `json:"h2_wire,omitempty"`
	CaptureIncomplete bool                `json:"capture_incomplete,omitempty"`
}
type report struct {
	Schema       int               `json:"schema"`
	Kind         string            `json:"kind"`
	Protocol     string            `json:"protocol"`
	Complete     bool              `json:"complete"`
	Rotations    int               `json:"rotations"`
	ClientFailed bool              `json:"client_failed"`
	Connections  []*connection     `json:"connections"`
	Phases       map[string]*phase `json:"phases"`
}
type fixture struct {
	mu      sync.Mutex
	report  report
	closers map[int]func()
	done    chan struct{}
	once    sync.Once
}
type connectionKey struct{}

func newFixture(protocol string) *fixture {
	f := &fixture{report: report{Schema: 1, Kind: "controlled-browser-behavior", Protocol: protocol,
		Phases: make(map[string]*phase)}, closers: make(map[int]func()), done: make(chan struct{})}
	for _, name := range []string{"cold", "sequential", "parallel", "cancel", "reconnect"} {
		f.report.Phases[name] = &phase{}
	}
	return f
}
func (f *fixture) add(close func()) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.report.Connections) >= 32 {
		return 0, errors.New("fixture connection capacity")
	}
	id := len(f.report.Connections) + 1
	f.report.Connections = append(f.report.Connections, &connection{ID: id, Requests: make(map[string]int)})
	f.closers[id] = close
	return id, nil
}
func (f *fixture) closeConnections() {
	f.mu.Lock()
	list := make([]func(), 0, len(f.closers))
	for _, close := range f.closers {
		list = append(list, close)
	}
	f.mu.Unlock()
	for _, close := range list {
		close()
	}
}
func (f *fixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "GET" {
		w.WriteHeader(405)
		return
	}
	if r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
		return
	}
	if r.URL.Path == "/favicon.ico" {
		w.WriteHeader(404)
		return
	}
	if r.URL.Path == "/rotate" {
		f.mu.Lock()
		f.report.Rotations++
		f.mu.Unlock()
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(200)
		time.AfterFunc(150*time.Millisecond, f.closeConnections)
		return
	}
	if r.URL.Path == "/done" || r.URL.Path == "/failed" {
		if r.URL.Path == "/failed" {
			f.mu.Lock()
			f.report.ClientFailed = true
			f.mu.Unlock()
		}
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(200)
		f.once.Do(func() { close(f.done) })
		return
	}
	name := r.URL.Path[1:]
	f.mu.Lock()
	p := f.report.Phases[name]
	if p == nil {
		f.mu.Unlock()
		w.WriteHeader(404)
		return
	}
	id, _ := r.Context().Value(connectionKey{}).(int)
	if id < 1 || id > len(f.report.Connections) {
		f.mu.Unlock()
		w.WriteHeader(500)
		return
	}
	c := f.report.Connections[id-1]
	if r.TLS != nil {
		resumed := r.TLS.DidResume
		c.Resumed = &resumed
		c.ALPN = r.TLS.NegotiatedProtocol
	}
	c.Requests[name]++
	p.Started++
	p.Active++
	p.MaxActive = max(p.MaxActive, p.Active)
	f.mu.Unlock()
	finished := false
	defer func() {
		f.mu.Lock()
		p.Active--
		if finished {
			p.Finished++
		} else {
			p.Canceled++
		}
		f.mu.Unlock()
	}()
	size := 64
	if name == "parallel" {
		size = 262144
	}
	if name == "cancel" {
		size = 4 << 20
	}
	w.Header().Set("Content-Length", fmt.Sprint(size))
	w.WriteHeader(200)
	block := make([]byte, 16<<10)
	for i := range block {
		block[i] = 'a'
	}
	for size > 0 {
		n := min(size, len(block))
		if _, err := w.Write(block[:n]); err != nil {
			return
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			return
		}
		size -= n
		if size > 0 {
			if err := pause(r.Context(), 10*time.Millisecond); err != nil {
				return
			}
		}
	}
	finished = true
}
func (f *fixture) valid() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.report.ClientFailed || f.report.Rotations != 2 {
		return false
	}
	for name, want := range map[string]int{"cold": 1, "sequential": 3, "parallel": 8, "cancel": 4, "reconnect": 2} {
		p := f.report.Phases[name]
		if p.Started != want || p.Active != 0 {
			return false
		}
		if name == "cancel" {
			if p.Canceled != want {
				return false
			}
		} else if p.Finished != want || p.Canceled != 0 {
			return false
		}
	}
	return f.report.Phases["parallel"].MaxActive > 1
}

type singleListener struct{ net.Conn }

func (l singleListener) Accept() (net.Conn, error) { return l.Conn, nil }
func (l singleListener) Close() error              { return nil }
func (l singleListener) Addr() net.Addr            { return l.Conn.LocalAddr() }

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}
func serve(ctx context.Context, protocol, cert, key, ready, out, backend string) error {
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	var ticket [32]byte
	if _, err = rand.Read(ticket[:]); err != nil {
		return err
	}
	cfg.SetSessionTicketKeys([][32]byte{ticket})
	f := newFixture(protocol)
	var wg sync.WaitGroup
	var shutdown func()
	var origin string
	if protocol == "h2" {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return err
		}
		shutdown = func() { listener.Close(); f.closeConnections() }
		origin = "https://localhost:" + fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)
		wg.Go(func() {
			for {
				raw, err := listener.Accept()
				if err != nil {
					return
				}
				id, err := f.add(func() { raw.Close() })
				if err != nil {
					raw.Close()
					return
				}
				wg.Go(func() {
					handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						f.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), connectionKey{}, id)))
					})
					p, err := webprofile.Capture(singleListener{raw}, cfg, handler, "controlled same-GET workload", 30*time.Second)
					f.mu.Lock()
					delete(f.closers, id)
					c := f.report.Connections[id-1]
					if err == nil {
						c.H2 = &p
					} else {
						c.CaptureIncomplete = true
					}
					f.mu.Unlock()
				})
			}
		})
	} else if protocol == "h3" {
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return err
		}
		server := &http3.Server{TLSConfig: cfg, QUICConfig: &quic.Config{Versions: []quic.Version{quic.Version1}, MaxIncomingStreams: 32}, Handler: f}
		server.ConnContext = func(ctx context.Context, c *quic.Conn) context.Context {
			id, err := f.add(func() { c.CloseWithError(0, "fixture rotation") })
			if err != nil {
				c.CloseWithError(1, "fixture capacity")
				return ctx
			}
			context.AfterFunc(c.Context(), func() { f.mu.Lock(); delete(f.closers, id); f.mu.Unlock() })
			return context.WithValue(ctx, connectionKey{}, id)
		}
		shutdown = func() { server.Close(); socket.Close(); f.closeConnections() }
		origin = "https://localhost:" + fmt.Sprint(socket.LocalAddr().(*net.UDPAddr).Port)
		wg.Go(func() { _ = server.Serve(socket) })
	} else {
		return errors.New("protocol must be h2 or h3")
	}
	defer shutdown()
	if err = writeJSON(ready, map[string]string{"origin": origin}); err != nil {
		return err
	}
	sampleErr := make(chan error, 1)
	if backend != "" {
		go func() { sampleErr <- nativeWorkload(ctx, origin, cert, backend, protocol) }()
	}
	select {
	case <-f.done:
	case err := <-sampleErr:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		return errors.New("fixture workload timeout")
	}
	// Let the final response flush and join canceled request handlers before
	// closing the transports. No unbounded observation log or body is retained.
	if err = pause(ctx, 250*time.Millisecond); err != nil {
		return err
	}
	for range 40 {
		if f.valid() {
			break
		}
		if err = pause(ctx, 25*time.Millisecond); err != nil {
			return err
		}
	}
	shutdown()
	wg.Wait()
	f.mu.Lock()
	f.report.Complete = false
	sort.Slice(f.report.Connections, func(i, j int) bool { return f.report.Connections[i].ID < f.report.Connections[j].ID })
	f.mu.Unlock()
	valid := f.valid()
	f.mu.Lock()
	f.report.Complete = valid
	err = writeJSON(out, f.report)
	f.mu.Unlock()
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("incomplete controlled workload")
	}
	return nil
}
func main() {
	protocol := flag.String("protocol", "h2", "h2 or h3")
	cert := flag.String("cert", "", "fixture cert")
	key := flag.String("key", "", "fixture key")
	ready := flag.String("ready", "", "new ready JSON")
	out := flag.String("out", "", "new result JSON")
	backend := flag.String("sample", "", "optional go/nss/neqo sample")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := serve(ctx, *protocol, *cert, *key, *ready, *out, *backend); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
