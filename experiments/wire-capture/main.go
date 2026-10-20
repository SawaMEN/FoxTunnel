// A controlled, loopback-only endpoint. Retains public transport metadata only.
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
	"github.com/SawaMEN/FoxTunnel/internal/webprofile"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	h3log "github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

type value struct {
	ID    uint64 `json:"id"`
	Value any    `json:"value"`
}
type observation struct {
	Schema   int    `json:"schema"`
	Kind     string `json:"kind"`
	Method   string `json:"capture_method"`
	Scenario string `json:"capture_scenario"`
	QUIC     struct {
		Version    uint32  `json:"version"`
		ALPN       string  `json:"tls_alpn"`
		Initial    int     `json:"initial_datagram_size"`
		Parameters []value `json:"transport_parameters"`
		Scope      string  `json:"parameter_scope"`
	} `json:"quic"`
	H3 struct {
		Settings []value `json:"settings"`
	} `json:"h3"`
}
type capture struct {
	mu           sync.Mutex
	result       observation
	connections  int
	seenSettings bool
}

func (c *capture) SupportsSchemas(string) bool      { return true }
func (c *capture) AddProducer() qlogwriter.Recorder { return c }
func (c *capture) Close() error                     { return nil }
func (c *capture) RecordEvent(e qlogwriter.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch e := e.(type) {
	case qlog.ParametersSet:
		if e.Initiator != qlog.InitiatorRemote || e.Restore {
			return
		}
		// These are effective peer values exposed by the endpoint decoder, including
		// protocol defaults. No claim about raw parameter order, presence or CID bytes.
		c.result.QUIC.Parameters = []value{
			{1, e.MaxIdleTimeout.Milliseconds()}, {3, int64(e.MaxUDPPayloadSize)},
			{4, int64(e.InitialMaxData)}, {5, int64(e.InitialMaxStreamDataBidiLocal)},
			{6, int64(e.InitialMaxStreamDataBidiRemote)}, {7, int64(e.InitialMaxStreamDataUni)},
			{8, e.InitialMaxStreamsBidi}, {9, e.InitialMaxStreamsUni}, {10, e.AckDelayExponent},
			{11, e.MaxAckDelay.Milliseconds()}, {12, e.DisableActiveMigration}, {14, e.ActiveConnectionIDLimit},
		}
	case h3log.FrameParsed:
		s, ok := e.Frame.Frame.(h3log.SettingsFrame)
		if !ok || c.seenSettings {
			return
		}
		c.seenSettings = true
		if s.MaxFieldSectionSize >= 0 {
			c.result.H3.Settings = append(c.result.H3.Settings, value{6, s.MaxFieldSectionSize})
		}
		if s.Datagram != nil {
			c.result.H3.Settings = append(c.result.H3.Settings, value{0x33, *s.Datagram})
		}
		if s.ExtendedConnect != nil {
			c.result.H3.Settings = append(c.result.H3.Settings, value{8, *s.ExtendedConnect})
		}
		for id, v := range s.Other {
			c.result.H3.Settings = append(c.result.H3.Settings, value{id, v})
		}
		sort.Slice(c.result.H3.Settings, func(i, j int) bool { return c.result.H3.Settings[i].ID < c.result.H3.Settings[j].ID })
	}
}

type packets struct {
	net.PacketConn
	capture *capture
}

func (p *packets) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, e := p.PacketConn.ReadFrom(b)
	// Force v1 at this fixture, so the Initial packet type is unambiguous.
	if n >= 6 && b[0]&0xf0 == 0xc0 && binary.BigEndian.Uint32(b[1:5]) == 1 {
		p.capture.mu.Lock()
		if p.capture.result.QUIC.Initial == 0 {
			p.capture.result.QUIC.Initial = n
		}
		p.capture.mu.Unlock()
	}
	return n, a, e
}
func save(path string, v any) error {
	data, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	_, e = f.Write(append(data, '\n'))
	return e
}
func sample(origin, cert, backend, protocol string) error {
	// All three subjects use the same IPv4 loopback path. Keep SNI and
	// hostname verification at localhost while avoiding a UDP ::1 first choice.
	origin = strings.Replace(origin, "//localhost:", "//127.0.0.1:", 1)
	c, e := tunnel.NewClient(origin, "fixture", "local-only", cert)
	if e != nil {
		return e
	}
	defer c.Close()
	selected := backend
	if backend == "neqo" {
		selected = "auto"
	}
	if e = c.SetTLSBackend(selected); e != nil {
		return e
	}
	mode := "h2-connect"
	if protocol == "h3" {
		mode = "h3-post"
	}
	if e = c.SetTransport(mode); e != nil {
		return e
	}
	if backend == "neqo" {
		if e = c.SetQUICBackend("neqo", false, 2*time.Second); e != nil {
			return e
		}
	}
	if e = c.SetServerIdentity("localhost", ""); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, e := c.DialContext(ctx, "tcp", "127.0.0.1:9")
	if conn != nil {
		conn.Close()
	}
	return e
}
func run() error {
	protocol := flag.String("protocol", "h2", "h2 or h3")
	cert := flag.String("cert", "", "fixture cert")
	key := flag.String("key", "", "fixture key")
	out := flag.String("out", "", "new observation JSON")
	ready := flag.String("ready", "", "new readiness JSON")
	backend := flag.String("sample", "", "optional go/nss/neqo client")
	flag.Parse()
	if *protocol != "h2" && *protocol != "h3" {
		return errors.New("unsupported protocol")
	}
	pair, e := tls.LoadX509KeyPair(*cert, *key)
	if e != nil {
		return e
	}
	config := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "controlled loopback fixture")
	})
	startSample := func(origin string) {
		if *backend != "" {
			go func() {
				if e := sample(origin, *cert, *backend, *protocol); e != nil {
					fmt.Fprintln(os.Stderr, "sample:", e)
				}
			}()
		}
	}
	if *protocol == "h2" {
		l, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if e != nil {
			return e
		}
		defer l.Close()
		_ = l.SetDeadline(time.Now().Add(20 * time.Second))
		origin := "https://localhost:" + fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
		if e = save(*ready, map[string]string{"origin": origin}); e != nil {
			return e
		}
		startSample(origin)
		result, e := webprofile.Capture(l, config, handler, "verified first connection; controlled loopback endpoint", 3*time.Second)
		if e != nil {
			return e
		}
		return save(*out, result)
	}
	c := &capture{}
	c.result.Schema = 1
	c.result.Kind = "h3-quic-observation"
	c.result.Method = "endpoint"
	c.result.Scenario = "verified first connection; controlled loopback endpoint; QUIC v1"
	c.result.QUIC.Scope = "selected effective peer parameters, including RFC defaults; no raw presence/order/CID claim"
	socket, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		return e
	}
	defer socket.Close()
	server := &http3.Server{TLSConfig: config, QUICConfig: &quic.Config{Versions: []quic.Version{quic.Version1}, Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.connections++
		return c
	}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.result.QUIC.Version = 1
		c.result.QUIC.ALPN = r.TLS.NegotiatedProtocol
		c.mu.Unlock()
		handler.ServeHTTP(w, r)
	})}
	defer server.Close()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(&packets{socket, c}) }()
	origin := "https://localhost:" + fmt.Sprint(socket.LocalAddr().(*net.UDPAddr).Port)
	if e = save(*ready, map[string]string{"origin": origin}); e != nil {
		return e
	}
	startSample(origin)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			c.mu.Lock()
			diagnostic := fmt.Sprintf("incomplete H3 metadata: connections=%d initial=%d alpn=%q params=%d settings=%d", c.connections, c.result.QUIC.Initial, c.result.QUIC.ALPN, len(c.result.QUIC.Parameters), len(c.result.H3.Settings))
			c.mu.Unlock()
			return errors.New(diagnostic)
		case e := <-serveDone:
			return e
		case <-tick.C:
			c.mu.Lock()
			complete := c.result.QUIC.Initial > 0 && c.result.QUIC.ALPN == "h3" && len(c.result.QUIC.Parameters) > 0 && len(c.result.H3.Settings) > 0
			if complete {
				if c.connections != 1 {
					c.mu.Unlock()
					return errors.New("multiple connections would mix observation")
				}
				e = save(*out, c.result)
				c.mu.Unlock()
				return e
			}
			c.mu.Unlock()
		}
	}
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
