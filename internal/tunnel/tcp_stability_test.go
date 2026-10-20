package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStage3TCPResetIsNotEOF(t *testing.T) {
	testStage3TCPResetIsNotEOF(t, "go")
}

func testStage3TCPResetIsNotEOF(t *testing.T, backend string) {
	for _, mode := range []string{"h2-connect", "h2-post", "wss"} {
		for _, padding := range []bool{false, true} {
			for _, socks := range []bool{false, true} {
				label := mode
				if padding {
					label += "/padding"
				}
				if socks {
					label += "/socks"
				} else {
					label += "/dial"
				}
				t.Run(label, func(t *testing.T) {
					reset := make(chan struct{})
					var once sync.Once
					trigger := func() { once.Do(func() { close(reset) }) }
					t.Cleanup(trigger)
					target := testDestination(t, func(c net.Conn) {
						_ = c.SetDeadline(time.Now().Add(5 * time.Second))
						if _, err := c.Write([]byte("partial")); err != nil {
							return
						}
						select {
						case <-reset:
						case <-time.After(5 * time.Second):
						}
						_ = c.(*net.TCPConn).SetLinger(0)
					})
					server := &Server{Username: "alice", Password: "secret", AllowPrivate: true, Padding: padding, RequireProtocolNegotiation: true}
					client, socksAddress := testClient(t, server)
					if err := client.SetTLSBackend(backend); err != nil {
						t.Fatal(err)
					}
					if err := client.SetTransport(mode); err != nil {
						t.Fatal(err)
					}
					client.Padding = padding
					client.RequireProtocolNegotiation = true
					var conn net.Conn
					var err error
					if socks {
						var status byte
						conn, status = connectSOCKS(t, socksAddress, target)
						if status != 0 {
							t.Fatal("SOCKS refused", status)
						}
					} else {
						ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						conn, err = client.DialContext(ctx, "tcp", target)
						cancel()
						if err != nil {
							t.Fatal(err)
						}
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					var prefix [7]byte
					if _, err = io.ReadFull(conn, prefix[:]); err != nil || string(prefix[:]) != "partial" {
						t.Fatal("prefix lost before reset", err, string(prefix[:]))
					}
					trigger()
					var next [1]byte
					if _, err = conn.Read(next[:]); err == nil || errors.Is(err, io.EOF) {
						t.Fatal("TCP reset disguised as successful EOF", err)
					}
					if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
						t.Fatal("reset did not unblock reader", err)
					}
				})
			}
		}
	}
}

type stage3RoundTripper func(*http.Request) (*http.Response, error)

func (f stage3RoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
func (f stage3RoundTripper) CloseIdleConnections() {}

func TestStage3TCPBackpressureDeadlineAndClose(t *testing.T) {
	client, err := NewClient("https://example.org", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, source := io.Pipe()
	defer source.Close()
	client.transport = stage3RoundTripper(func(r *http.Request) (*http.Response, error) {
		// Never consume upload: this models exhausted transport flow credit.
		return &http.Response{StatusCode: 200, ProtoMajor: 2, Header: make(http.Header), Body: response}, nil
	})
	conn, err := client.DialContext(context.Background(), "tcp", "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	var one [1]byte
	if _, err = conn.Read(one[:]); err == nil {
		t.Fatal("silent stream ignored read deadline")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal("read deadline lost", err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	sent := make(chan error, 1)
	go func() { _, err := source.Write([]byte("r")); sent <- err }()
	if _, err = io.ReadFull(conn, one[:]); err != nil || one[0] != 'r' {
		t.Fatal("resetting deadline destroyed stream", err)
	}
	if err = <-sent; err != nil {
		t.Fatal(err)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	n, err := conn.Write(bytes.Repeat([]byte{0x5a}, 1<<20))
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal("blocked upload ignored deadline", n, err)
	}
	if n > fastCopyBufferSize {
		t.Fatal("upload buffered beyond one copy chunk", n)
	}
	_ = conn.SetWriteDeadline(time.Time{})
	blocked := make(chan error, 1)
	go func() { _, err := conn.Write([]byte("blocked")); blocked <- err }()
	select {
	case err := <-blocked:
		t.Fatal("stalled carrier accepted more upload", err)
	case <-time.After(20 * time.Millisecond):
	}
	conn.Close()
	select {
	case err := <-blocked:
		if err == nil {
			t.Fatal("closed upload reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock upload")
	}
	client.schedulerMu.Lock()
	active := client.activeEndpoints
	client.schedulerMu.Unlock()
	for _, count := range active {
		if count != 0 {
			t.Fatal("Close leaked endpoint reservation", active)
		}
	}
}

type stage3JoinBody struct {
	ctx context.Context

	force <-chan struct{}

	cancelled atomic.Bool
}

func (b *stage3JoinBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *stage3JoinBody) Close() error {
	select {
	case <-b.ctx.Done():
		b.cancelled.Store(true)
	case <-b.force:
	}
	return nil
}

func TestStage3TCPRejectedSetupCancelsBeforeBodyClose(t *testing.T) {
	for _, responseError := range []bool{false, true} {
		client, err := NewClient("https://primary.example", "alice", "secret", "")
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		if err = client.SetFallbackServers([]string{"https://backup.example"}); err != nil {
			t.Fatal(err)
		}
		force := make(chan struct{})
		t.Cleanup(func() { close(force) })
		var body *stage3JoinBody
		var calls atomic.Int32
		client.transport = stage3RoundTripper(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			body = &stage3JoinBody{ctx: r.Context(), force: force}
			response := &http.Response{StatusCode: 502, ProtoMajor: 2, Body: body}
			if responseError {
				return response, io.ErrUnexpectedEOF
			}
			return response, nil
		})
		done := make(chan error, 1)
		go func() {
			stream, err := client.openTunnel(context.Background(), "example.org:443")
			if stream != nil {
				stream.close()
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil || body == nil || !body.cancelled.Load() || calls.Load() != 1 {
				t.Fatal("rejected setup was retained or replayed", err, calls.Load())
			}
		case <-time.After(time.Second):
			t.Fatal("response Close waited for a context that was not cancelled")
		}
	}
}

func TestStage3TCPPartialUploadIsNeverReplayed(t *testing.T) {
	for _, mode := range []string{"h2-connect", "h2-post"} {
		t.Run(mode, func(t *testing.T) {
			var backupCalls atomic.Int32
			client, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				backupCalls.Add(1)
				w.WriteHeader(http.StatusBadGateway)
			}))
			backup := client.ServerURL.String()
			reset := make(chan struct{})
			var once sync.Once
			trigger := func() { once.Do(func() { close(reset) }) }
			t.Cleanup(trigger)
			var primaryCalls atomic.Int32
			var received atomic.Int32
			primary := setupEndpoint(t, client, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				primaryCalls.Add(1)
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				var payload [4]byte
				if _, err := io.ReadFull(r.Body, payload[:]); err != nil || string(payload[:]) != "once" {
					t.Error("primary upload", err, string(payload[:]))
					return
				}
				received.Add(1)
				_, _ = w.Write([]byte("part"))
				w.(http.Flusher).Flush()
				select {
				case <-reset:
				case <-r.Context().Done():
				}
				panic(http.ErrAbortHandler)
			}))
			usePrimary(t, client, primary.URL)
			if err := client.SetFallbackServers([]string{backup}); err != nil {
				t.Fatal(err)
			}
			if err := client.SetTLSBackend("go"); err != nil {
				t.Fatal(err)
			}
			if err := client.SetTransport(mode); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, "tcp", "example.org:443")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err = conn.Write([]byte("once")); err != nil {
				t.Fatal(err)
			}
			var prefix [4]byte
			if _, err = io.ReadFull(conn, prefix[:]); err != nil || string(prefix[:]) != "part" {
				t.Fatal("partial response", err)
			}
			trigger()
			_, err = io.Copy(io.Discard, conn)
			if err == nil || primaryCalls.Load() != 1 || received.Load() != 1 || backupCalls.Load() != 0 {
				t.Fatal("ambiguous upload retried or reset hidden", err, primaryCalls.Load(), received.Load(), backupCalls.Load())
			}
		})
	}
}
