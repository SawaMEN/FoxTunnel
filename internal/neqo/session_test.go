//go:build neqo && cgo && linux && amd64

package neqo

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestUpdateNeqoSessionResumptionTrustAndNoEarlyRequests(t *testing.T) {
	for _, reason := range []string{"pin", "expired", "roots", "disabled"} {
		t.Run(reason, func(t *testing.T) {
			var calls atomic.Int32
			observed := make(chan bool, 4)
			raw, cfg := testServerQUIC(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !r.TLS.HandshakeComplete {
					t.Error("HTTP request sent with 0-RTT")
				}
				calls.Add(1)
				observed <- r.TLS.DidResume
				_, _ = w.Write([]byte("verified"))
			}), &quic.Config{Allow0RTT: true})
			var reject atomic.Bool
			var expired atomic.Bool
			var callbacks atomic.Int32
			pinError := errors.New("pin changed")
			cfg.SessionTicketsDisabled = reason == "disabled"
			cfg.Time = func() time.Time {
				if expired.Load() {
					return time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)
				}
				return time.Now()
			}
			cfg.VerifyConnection = func(state tls.ConnectionState) error {
				callbacks.Add(1)
				if len(state.VerifiedChains) == 0 {
					return errors.New("missing verified chain")
				}
				if reject.Load() {
					return pinError
				}
				return nil
			}
			base, err := NewTransport(Config{TLS: cfg, HandshakeTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			client := base.(*transport)
			defer client.CloseIdleConnections()
			get := func(tr Transport) error {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				req, _ := http.NewRequestWithContext(ctx, "GET", raw, nil)
				req.Header.Set("Proxy-Authorization", "Basic test-only")
				resp, err := tr.RoundTrip(req)
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				_, err = io.Copy(io.Discard, resp.Body)
				return err
			}
			waitTicket := func() {
				if reason == "disabled" {
					return
				}
				deadline := time.Now().Add(2 * time.Second)
				for time.Now().Before(deadline) {
					client.mu.Lock()
					n := len(client.sessions)
					client.mu.Unlock()
					if n > 0 {
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
				t.Fatal("verified connection supplied no resumption ticket")
			}
			if err := get(client); err != nil {
				t.Fatal(err)
			}
			if <-observed {
				t.Fatal("cold connection resumed")
			}
			waitTicket()
			client.CloseIdleConnections()
			if err := get(client); err != nil {
				t.Fatal(err)
			}
			if resumed := <-observed; resumed != (reason != "disabled") {
				t.Fatalf("unexpected resumption=%v", resumed)
			}
			if callbacks.Load() != 2 {
				t.Fatalf("verification callbacks=%d, want 2", callbacks.Load())
			}
			waitTicket()
			other, err := NewTransport(Config{TLS: cfg, HandshakeTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer other.CloseIdleConnections()
			if err := get(other); err != nil {
				t.Fatal(err)
			}
			if <-observed {
				t.Fatal("ticket leaked to another transport")
			}
			client.CloseIdleConnections()
			switch reason {
			case "pin", "disabled":
				reject.Store(true)
			case "expired":
				expired.Store(true)
			case "roots":
				client.config.RootCAs = x509.NewCertPool()
			}
			if err := get(client); err == nil {
				t.Fatal("changed trust accepted")
			} else if reason == "pin" && !errors.Is(err, pinError) {
				t.Fatalf("pin rejection: %v", err)
			}
			if calls.Load() != 3 {
				t.Fatal("HTTP data reached server after trust rejection")
			}
		})
	}
}

// A peer may cancel an unread upload after sending a complete response. QUIC
// STOP_SENDING must not turn that independent response into RESET_STREAM.
func TestEarlyResponsePreservesBodyAfterUploadStopped(t *testing.T) {
	payload := bytes.Repeat([]byte("verified-response"), 8192)
	raw, cfg := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write(payload); err != nil {
			t.Errorf("response: %v", err)
		}
	}))
	client, err := NewTransport(Config{TLS: cfg, HandshakeTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	for round := range 10 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var body io.ReadCloser = io.NopCloser(bytes.NewReader(make([]byte, 4<<20)))
		if round%2 == 1 {
			reader, writer := io.Pipe()
			defer writer.Close()
			body = reader // STOP_SENDING must unblock an idle upload too.
		}
		req, _ := http.NewRequestWithContext(ctx, "POST", raw, body)
		resp, err := client.RoundTrip(req)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		got, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("response truncated: %d/%d: %v", len(got), len(payload), err)
		}
	}
}
