package firefox

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

func httpIPCFixture(t *testing.T, serve func(net.Conn) error) *Managed {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	ready := make(chan struct{})
	close(ready)
	m := &Managed{ready: ready, done: make(chan struct{}), listen: listener.Addr().String(), timeout: 3 * time.Second, token: "secret"}
	finished := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			finished <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		read := func(n int) ([]byte, error) { b := make([]byte, n); _, e := io.ReadFull(c, b); return b, e }
		b, e := read(3)
		if e != nil || !bytes.Equal(b, []byte{5, 1, 2}) {
			finished <- errors.New("IPC greeting")
			return
		}
		c.Write([]byte{5, 2})
		b, e = read(2)
		if e != nil || b[0] != 1 {
			finished <- errors.New("IPC auth version")
			return
		}
		name, e := read(int(b[1]))
		if e != nil || string(name) != "foxtunnel" {
			finished <- errors.New("IPC username")
			return
		}
		b, e = read(1)
		if e != nil {
			finished <- e
			return
		}
		token, e := read(int(b[0]))
		if e != nil || string(token) != "secret" {
			finished <- errors.New("IPC secret")
			return
		}
		c.Write([]byte{1, 0})
		finished <- serve(c)
	}()
	t.Cleanup(func() {
		select {
		case err := <-finished:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(6 * time.Second):
			t.Error("IPC worker leaked")
		}
	})
	return m
}
func readHTTPRequestIPC(c net.Conn) (httpIPCRequest, error) {
	var head [6]byte
	_, err := io.ReadFull(c, head[:])
	if err != nil {
		return httpIPCRequest{}, err
	}
	if head[0] != 5 || head[1] != 0xf2 {
		return httpIPCRequest{}, errors.New("wrong HTTP operation")
	}
	n := int(binary.BigEndian.Uint16(head[4:]))
	if n < 2 || n > maxHTTPMetadata {
		return httpIPCRequest{}, errors.New("metadata size")
	}
	b := make([]byte, n)
	_, err = io.ReadFull(c, b)
	if err != nil {
		return httpIPCRequest{}, err
	}
	var meta httpIPCRequest
	err = json.Unmarshal(b, &meta)
	return meta, err
}
func writeHTTPResponseIPC(c net.Conn, status int) error {
	b, _ := json.Marshal(httpIPCResponse{Status: status, Proto: 2, Headers: [][2]string{{"X-Native-Test", "yes"}}})
	if err := writeHTTPBytes(c, []byte{5, 0, byte(len(b) >> 8), byte(len(b))}); err != nil {
		return err
	}
	return writeHTTPBytes(c, b)
}
func TestManagedHTTPResponseBeforeUploadAndFramedEOF(t *testing.T) {
	payload := bytes.Repeat([]byte{0, 255, 1, 128}, 25000)
	m := httpIPCFixture(t, func(c net.Conn) error {
		meta, err := readHTTPRequestIPC(c)
		if err != nil {
			return err
		}
		if meta.Method != "POST" || meta.Path != "/echo?q=1" || !meta.Body {
			return errors.New("wrong HTTP metadata")
		}
		if err = writeHTTPResponseIPC(c, 200); err != nil {
			return err
		}
		incoming := &httpIPCBody{conn: c}
		got, err := io.ReadAll(incoming)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, payload) {
			return errors.New("upload corrupted")
		}
		for len(got) > 0 {
			n := min(len(got), maxHTTPChunk)
			if err = writeHTTPChunk(c, got[:n]); err != nil {
				return err
			}
			got = got[n:]
		}
		return writeHTTPChunk(c, nil)
	})
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	written := make(chan error, 2)
	traceContext := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) { written <- info.Err }})
	req, _ := http.NewRequestWithContext(traceContext, "POST", "https://example.test/echo?q=1", reader)
	resp, err := m.RoundTrip(req)
	if err != nil {
		t.Fatal("headers must not wait for upload:", err)
	}
	defer resp.Body.Close()
	sent := make(chan error, 1)
	go func() { _, e := writer.Write(payload); writer.Close(); sent <- e }()
	got, err := io.ReadAll(resp.Body)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("binary duplex", len(got), err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-written:
		if err != nil {
			t.Fatal("body copy trace:", err)
		}
	case <-time.After(time.Second):
		t.Fatal("missing WroteRequest releases XHTTP packet window")
	}
	select {
	case <-written:
		t.Fatal("duplicate WroteRequest callback")
	default:
	}
	if resp.Header.Get("X-Native-Test") != "yes" {
		t.Fatal("lost response headers")
	}
}
func TestManagedHTTPTruncationIsNotEOF(t *testing.T) {
	for _, mode := range []string{"missing-terminator", "partial-body", "abort", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			m := httpIPCFixture(t, func(c net.Conn) error {
				if _, err := readHTTPRequestIPC(c); err != nil {
					return err
				}
				if err := writeHTTPResponseIPC(c, 200); err != nil {
					return err
				}
				switch mode {
				case "partial-body":
					return writeHTTPBytes(c, []byte{0, 0, 0, 8, 1})
				case "abort":
					return writeHTTPBytes(c, []byte{255, 255, 255, 255})
				case "oversized":
					return writeHTTPBytes(c, []byte{0, 1, 0, 0})
				}
				return nil
			})
			req, _ := http.NewRequest("GET", "https://example.test/", nil)
			resp, err := m.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			_, err = io.ReadAll(resp.Body)
			if err == nil {
				t.Fatal("native error treated as clean EOF")
			}
			// Bond retries truncated records on another lane using the same
			// sequence. A malformed length must remain a protocol failure.
			if errors.Is(err, io.ErrUnexpectedEOF) != (mode != "oversized") {
				t.Fatal("interrupted response and invalid framing must remain distinct:", err)
			}
		})
	}
}

// An H2 reset after response bytes must propagate as an interrupted stream.
// Bond can replay its sequence-numbered record; malformed IPC is still fatal.
func TestGeckoManagedHTTPInterruptedBody(t *testing.T) {
	bundle := os.Getenv("FOXTUNNEL_NECKO_BUNDLE")
	if bundle == "" {
		t.Skip("verified native bundle required")
	}
	abort := make(chan struct{})
	var abortOnce sync.Once
	interrupt := func() { abortOnce.Do(func() { close(abort) }) }
	defer interrupt()
	prefix := []byte{0, 255, 128, 42}
	var calls atomic.Int32
	cfg := nativeProxy(t, "h2-connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write(prefix)
		if err := http.NewResponseController(w).Flush(); err != nil {
			return
		}
		select {
		case <-abort:
			panic(http.ErrAbortHandler)
		case <-r.Context().Done():
		}
	}))
	m, err := NewManaged(bundle, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", cfg.Server+"/interrupted", nil)
	resp, err := m.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got := make([]byte, len(prefix))
	if _, err = io.ReadFull(resp.Body, got); err != nil || !bytes.Equal(got, prefix) {
		t.Fatal("response prefix", got, err)
	}
	interrupt()
	tail, err := io.ReadAll(resp.Body)
	if len(tail) != 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("native reset lost interruption category", len(tail), err)
	}
	if calls.Load() != 1 {
		t.Fatal("interrupted response was replayed by the HTTP adapter", calls.Load())
	}
}

func TestManagedHTTPParentCancellation(t *testing.T) {
	m := httpIPCFixture(t, func(c net.Conn) error {
		if _, err := readHTTPRequestIPC(c); err != nil {
			return err
		}
		if err := writeHTTPResponseIPC(c, 200); err != nil {
			return err
		}
		var b [1]byte
		_, err := c.Read(b[:])
		if err != io.EOF {
			return errors.New("cancel did not close IPC")
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.test/", nil)
	resp, err := m.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	cancel()
	if _, err := resp.Body.Read(make([]byte, 1)); err == nil {
		t.Fatal("cancellation left response readable")
	}
}

// Requires the actual pinned, packaged libxul. The server deliberately flushes
// headers before reading any upload byte to catch normalization deadlocks.
func TestGeckoManagedHTTP(t *testing.T) {
	bundle := os.Getenv("FOXTUNNEL_NECKO_BUNDLE")
	if bundle == "" {
		t.Skip("verified native bundle required")
	}
	var requests atomic.Int32
	cfg := nativeProxy(t, "h2-connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Header.Get("Proxy-Authorization") == "" || r.Header.Get("Content-Type") != "application/grpc" {
			http.Error(w, "protocol/auth", 400)
			return
		}
		requests.Add(1)
		w.Header().Set("X-Native-Test", "yes")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		if r.Body != nil {
			io.Copy(flushingWriter{w}, r.Body)
		}
	}))
	m, err := NewManaged(bundle, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	req, _ := http.NewRequestWithContext(ctx, "POST", cfg.Server+"/native-http", reader)
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := m.RoundTrip(req)
	if err != nil {
		t.Fatal("native headers before upload:", err)
	}
	defer resp.Body.Close()
	data := bytes.Repeat([]byte{0, 255, 128, 1}, 512<<10)
	uploaded := make(chan error, 1)
	go func() { _, e := writer.Write(data); writer.Close(); uploaded <- e }()
	got, err := io.ReadAll(resp.Body)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("native duplex payload: got %d, err %v", len(got), err)
	}
	if err := <-uploaded; err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 || resp.Header.Get("X-Native-Test") != "yes" {
		t.Fatal("request replayed or metadata lost")
	}
}

type flushingWriter struct{ http.ResponseWriter }

// A reused HTTP/2 connection may die after the peer consumed a POST but before
// any response headers. Gecko must not replay the finite body on a fresh TCP
// connection: the protocol layer owns acknowledgement and safe retry policy.
func TestGeckoManagedHTTPNoReplay(t *testing.T) {
	bundle, runtime := os.Getenv("FOXTUNNEL_NECKO_BUNDLE"), os.Getenv("FOXTUNNEL_XPCSHELL")
	if bundle == "" && runtime == "" {
		t.Skip("explicit native runtime required")
	}
	for _, operation := range []string{"finite-http", "udp-v1"} {
		t.Run(operation, func(t *testing.T) { testGeckoManagedHTTPNoReplay(t, bundle, runtime, operation) })
	}
}

func testGeckoManagedHTTPNoReplay(t *testing.T, bundle, runtime, operation string) {
	t.Helper()
	type connectionKey struct{}
	var posts, accepted atomic.Int32
	payload := bytes.Repeat([]byte{0, 255, 128, 42}, 16<<10)
	if operation == "udp-v1" {
		var err error
		payload, err = udpproto.Encode(udpproto.Packet{Host: "127.0.0.1", Port: 53, Data: []byte{0, 255, 128, 42}})
		if err != nil {
			t.Fatal(err)
		}
	}
	warmPayload := append([]byte(nil), payload...)
	warmPayload[len(warmPayload)-1] ^= 1
	cfg := nativeProxyConfigured(t, "h2-connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Write([]byte("warm"))
			return
		}
		body, err := io.ReadAll(r.Body)
		if operation == "udp-v1" && err == nil && bytes.Equal(body, warmPayload) {
			w.Write(warmPayload)
			return
		}
		if err != nil || !bytes.Equal(body, payload) {
			http.Error(w, "invalid upload", 400)
			return
		}
		posts.Add(1)
		// Close the real connection, not only the HTTP/2 stream. The first
		// request primed native connection reuse, which permits Gecko retries
		// by default even for POST when no response bytes have been received.
		r.Context().Value(connectionKey{}).(net.Conn).Close()
	}), func(server *httptest.Server) {
		server.Config.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
			return context.WithValue(ctx, connectionKey{}, conn)
		}
		server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				accepted.Add(1)
			}
		}
	})
	var m *Managed
	var err error
	if bundle != "" {
		m, err = NewManaged(bundle, cfg)
	} else {
		m, err = newManagedRuntime(runtime, cfg)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var resp *http.Response
	if operation == "udp-v1" {
		got, e := m.ExchangeUDP(ctx, warmPayload)
		if e != nil || !bytes.Equal(got, warmPayload) {
			t.Fatal("could not prime native UDP HTTP connection", e)
		}
	} else {
		warm, _ := http.NewRequestWithContext(ctx, "GET", cfg.Server+"/warm", nil)
		resp, err = m.RoundTrip(warm)
		if err != nil {
			t.Fatal(err)
		}
		got, e := io.ReadAll(resp.Body)
		resp.Body.Close()
		if e != nil || string(got) != "warm" || resp.ProtoMajor != 2 {
			t.Fatal("could not prime native H2 connection", e)
		}
	}
	if operation == "udp-v1" {
		_, err = m.ExchangeUDP(ctx, payload)
	} else {
		req, _ := http.NewRequestWithContext(ctx, "POST", cfg.Server+"/ambiguous", bytes.NewReader(payload))
		resp, err = m.RoundTrip(req)
		if resp != nil {
			resp.Body.Close()
			t.Fatal("closed connection unexpectedly produced response headers")
		}
	}
	if err == nil {
		t.Fatal("ambiguous POST was reported successful")
	}
	if posts.Load() != 1 || accepted.Load() != 1 {
		t.Fatalf("native POST replay: uploads=%d TCP accepts=%d", posts.Load(), accepted.Load())
	}
}

// Response headers must be observable while an empty native response pipe is
// still open. Neither that wakeup nor a later cancellation may synthesize EOF.
func TestGeckoManagedHTTPHeadersOnly(t *testing.T) {
	bundle := os.Getenv("FOXTUNNEL_NECKO_BUNDLE")
	if bundle == "" {
		t.Skip("verified early-response-header runtime required")
	}
	for _, mode := range []string{"delayed-body", "empty-body", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			release := make(chan struct{})
			cfg := nativeProxy(t, "h2-connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("X-Headers-Only", "yes")
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				select {
				case <-release:
					if mode == "delayed-body" {
						w.Write([]byte{0, 255, 128, 42})
					}
				case <-r.Context().Done():
				}
			}))
			m, err := NewManaged(bundle, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "GET", cfg.Server+"/headers-only", nil)
			resp, err := m.RoundTrip(req)
			if err != nil {
				t.Fatal("headers delayed until response data:", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 || resp.Header.Get("X-Headers-Only") != "yes" {
				t.Fatal("response metadata lost")
			}
			type result struct {
				data []byte
				err  error
			}
			read := make(chan result, 1)
			go func() { b, e := io.ReadAll(resp.Body); read <- result{b, e} }()
			select {
			case r := <-read:
				t.Fatalf("open response pipe produced premature EOF: %d bytes, %v", len(r.data), r.err)
			case <-time.After(100 * time.Millisecond):
			}
			if mode == "cancel" {
				cancel()
			} else {
				close(release)
			}
			select {
			case r := <-read:
				if mode == "cancel" {
					if r.err == nil {
						t.Fatal("cancellation became clean EOF")
					}
				} else if r.err != nil {
					t.Fatal(r.err)
				} else if mode == "delayed-body" && !bytes.Equal(r.data, []byte{0, 255, 128, 42}) {
					t.Fatal("response data lost after header delivery")
				} else if mode == "empty-body" && len(r.data) != 0 {
					t.Fatal("header notification inserted payload bytes")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("response pipe did not finish")
			}
		})
	}
}

func (w flushingWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.ResponseWriter.(http.Flusher).Flush()
	return n, err
}

func TestManagedHTTPSetupFailureCategories(t *testing.T) {
	for _, status := range []byte{1, 2} {
		t.Run(string(rune('0'+status)), func(t *testing.T) {
			m := httpIPCFixture(t, func(c net.Conn) error {
				if _, err := readHTTPRequestIPC(c); err != nil {
					return err
				}
				return writeHTTPBytes(c, []byte{5, status, 0, 0})
			})
			req, _ := http.NewRequest("GET", "https://example.test/", nil)
			resp, err := m.RoundTrip(req)
			if resp != nil || err == nil {
				t.Fatal("setup rejection accepted")
			}
			var network net.Error
			if errors.As(err, &network) != (status == 2) {
				t.Fatal("TLS/protocol denial and network outage must remain distinct", err)
			}
		})
	}
}

// This gate does not need the new streaming-upload API: CONNECT uses native
// transport handoff. It also tests the per-channel proxy selection in IPC.
func TestGeckoManagedHTTPConnect(t *testing.T) {
	runtime := os.Getenv("FOXTUNNEL_XPCSHELL")
	if runtime == "" {
		t.Skip("explicit native research runtime required")
	}
	for _, mode := range []string{"h2-connect", "h3-connect"} {
		t.Run(mode, func(t *testing.T) {
			target := nativeEcho(t)
			server := &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true}
			cfg := nativeProxy(t, mode, server)
			m, err := newManagedRuntime(runtime, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			req, _ := http.NewRequestWithContext(ctx, "CONNECT", cfg.Server, reader)
			req.Host = target
			resp, err := m.RoundTrip(req)
			if err != nil {
				t.Fatal("native CONNECT metadata:", err)
			}
			defer resp.Body.Close()
			payload := bytes.Repeat([]byte{0, 128, 255, 42}, 64<<10)
			uploaded := make(chan error, 1)
			go func() { _, e := writer.Write(payload); writer.Close(); uploaded <- e }()
			got, err := io.ReadAll(resp.Body)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("native CONNECT binary/FIN: got %d, %v", len(got), err)
			}
			if err := <-uploaded; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestManagedHTTPOwnedShutdownClosesPendingUpload(t *testing.T) {
	m := httpIPCFixture(t, func(c net.Conn) error {
		if _, err := readHTTPRequestIPC(c); err != nil {
			return err
		}
		if err := writeHTTPResponseIPC(c, 200); err != nil {
			return err
		}
		var b [1]byte
		_, err := c.Read(b[:])
		if err != io.EOF {
			return errors.New("owner left IPC alive")
		}
		return nil
	})
	life, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.lifetime = life
	reader, writer := io.Pipe()
	defer writer.Close()
	body := &observedHTTPBody{ReadCloser: reader, closed: make(chan struct{})}
	req, _ := http.NewRequest("POST", "https://example.test/", body)
	resp, err := m.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	cancel()
	select {
	case <-body.closed:
	case <-time.After(time.Second):
		t.Fatal("owned shutdown left upload body open")
	}
	done := make(chan error, 1)
	go func() { _, e := writer.Write([]byte{1}); done <- e }()
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("owned shutdown accepted upload")
		}
	case <-time.After(time.Second):
		t.Fatal("owned shutdown leaked upload reader")
	}
}

type observedHTTPBody struct {
	io.ReadCloser
	closed chan struct{}
	once   sync.Once
}

func (b *observedHTTPBody) Close() error {
	var err error
	b.once.Do(func() { err = b.ReadCloser.Close(); close(b.closed) })
	return err
}

func TestGeckoManagedHTTPGetAndTrust(t *testing.T) {
	runtime := os.Getenv("FOXTUNNEL_XPCSHELL")
	if runtime == "" {
		t.Skip("explicit native research runtime required")
	}
	payload := bytes.Repeat([]byte{0, 128, 255, 42}, 256<<10)
	var served atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Header.Get("Proxy-Authorization") == "" {
			http.Error(w, "native auth required", 400)
			return
		}
		served.Add(1)
		w.Header().Set("X-Native-Test", "yes")
		w.Write(payload)
	})
	a, b := nativeProxy(t, "h2-connect", handler), nativeProxy(t, "h2-connect", handler)
	m, err := newManagedRuntime(runtime, a)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", a.Server+"/native-get", nil)
	resp, err := m.RoundTrip(req)
	if err != nil {
		t.Fatal("native GET:", err)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || !bytes.Equal(got, payload) || resp.Header.Get("X-Native-Test") != "yes" {
		t.Fatalf("native GET payload/header: %d, %v", len(got), err)
	}
	// The second origin uses an independent CA. The shared helper must still
	// verify that origin before transmitting proxy credentials or a GET.
	req, _ = http.NewRequestWithContext(ctx, "GET", b.Server+"/untrusted", nil)
	resp, err = m.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil || served.Load() != 1 {
		t.Fatal("untrusted alternate origin received authenticated request")
	}
	var network net.Error
	if errors.As(err, &network) {
		t.Fatal("certificate failure was classified as a retryable network outage", err)
	}
}

func TestGeckoManagedHTTPAlternateOriginAndOutage(t *testing.T) {
	runtime := os.Getenv("FOXTUNNEL_XPCSHELL")
	if runtime == "" {
		t.Skip("explicit native research runtime required")
	}
	var first, second atomic.Int32
	a := nativeProxy(t, "h2-connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { first.Add(1); w.Write([]byte("primary")) }))
	b := nativeProxy(t, "h2-connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { second.Add(1); w.Write([]byte("alternate")) }))
	roots, err := os.ReadFile(a.CACert)
	if err != nil {
		t.Fatal(err)
	}
	more, err := os.ReadFile(b.CACert)
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "roots.pem")
	if err = os.WriteFile(ca, append(roots, more...), 0600); err != nil {
		t.Fatal(err)
	}
	a.CACert = ca
	m, err := newManagedRuntime(runtime, a)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", b.Server+"/alt", nil)
	resp, err := m.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(got) != "alternate" || first.Load() != 0 || second.Load() != 1 {
		t.Fatal("helper used configured primary instead of selected origin", string(got), err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := listener.Addr().String()
	listener.Close()
	req, _ = http.NewRequestWithContext(ctx, "GET", "https://"+dead+"/outage", nil)
	resp, err = m.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	var network net.Error
	if err == nil || !errors.As(err, &network) {
		t.Fatal("native connection refusal is not retryable", err)
	}
}

func TestGeckoManagedHTTPFixedUpload(t *testing.T) {
	runtime := os.Getenv("FOXTUNNEL_XPCSHELL")
	if runtime == "" {
		t.Skip("explicit native research runtime required")
	}
	payload := bytes.Repeat([]byte{0, 128, 255, 42}, 64<<10)
	cfg := nativeProxy(t, "h2-connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.ContentLength != int64(len(payload)) || r.Header.Get("Content-Type") != "application/grpc" {
			http.Error(w, "fixed body metadata", 400)
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(data, payload) {
			http.Error(w, "fixed upload corruption", 400)
			return
		}
		w.Write(data)
	}))
	m, err := newManagedRuntime(runtime, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", cfg.Server+"/fixed-upload", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := m.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 || !bytes.Equal(data, payload) {
		t.Fatal("native fixed upload/headers", resp.StatusCode, len(data), err)
	}
}

func TestGeckoManagedHTTPInteractiveDownload(t *testing.T) {
	runtime := os.Getenv("FOXTUNNEL_XPCSHELL")
	if runtime == "" {
		t.Skip("explicit native research runtime required")
	}
	cfg := nativeProxy(t, "h2-connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Intentionally omit Content-Type: headers must not await sniffed body bytes.
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		w.Write([]byte{42})
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	m, err := newManagedRuntime(runtime, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", cfg.Server+"/interactive", nil)
	resp, err := m.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b [1]byte
	if _, err = io.ReadFull(resp.Body, b[:]); err != nil || b[0] != 42 {
		t.Fatal("small response was buffered until EOF", err)
	}
}
