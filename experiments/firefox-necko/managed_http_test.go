package firefox

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
	req, _ := http.NewRequest("POST", "https://example.test/echo?q=1", reader)
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
			if _, err := io.ReadAll(resp.Body); err == nil {
				t.Fatal("native error treated as clean EOF")
			}
		})
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
		if r.ProtoMajor != 2 || r.Header.Get("Proxy-Authorization") == "" {
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
