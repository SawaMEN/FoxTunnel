package xhttp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestStableCancelledSetupDoesNotStartRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, mode := range []string{"xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			rt := roundTripFunc(func(r *http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected I/O") })
			c, err := Dial(ctx, rt, "https://example.com", mode, "token", "")
			if c != nil {
				c.Close()
			}
			if !errors.Is(err, context.Canceled) || calls != 0 {
				t.Fatalf("cancelled setup: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestStableXHTTPSustained(t *testing.T) {
	duration := 2 * time.Second
	if raw := os.Getenv("FOXTUNNEL_STABLE_SECONDS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 2 || n > 1800 {
			t.Fatal("invalid stable duration")
		}
		duration = time.Duration(n) * time.Second
	}
	for _, mode := range []string{"xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			s := &Server{MaxSessions: 1, Authorized: func(*http.Request) bool { return true }, ServeConn: func(c net.Conn, _ *http.Request) { defer c.Close(); io.Copy(c, c) }}
			server := httptest.NewUnstartedServer(s)
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			ctx, cancel := context.WithTimeout(t.Context(), duration+10*time.Second)
			defer cancel()
			carrier, err := Dial(ctx, server.Client().Transport, server.URL, mode, "token", "")
			if err != nil {
				t.Fatal(err)
			}
			defer carrier.Close()
			start := time.Now()
			rounds := 0
			for time.Since(start) < duration {
				size := 64
				if rounds%2 == 0 {
					size = 32768
				}
				data := bytes.Repeat([]byte{byte(rounds)}, size)
				carrier.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := carrier.Write(data); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(data))
				if _, err := io.ReadFull(carrier, got); err != nil || !bytes.Equal(data, got) {
					t.Fatalf("integrity round=%d: %v", rounds, err)
				}
				rounds++
				time.Sleep(20 * time.Millisecond)
			}
			carrier.Close()
			deadline := time.Now().Add(5 * time.Second)
			for {
				s.mu.Lock()
				active, pairs := s.active, len(s.sessions)
				s.mu.Unlock()
				if active == 0 && pairs == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("carrier retained: active=%d paired=%d", active, pairs)
				}
				time.Sleep(time.Millisecond)
			}
			if rounds < 2 {
				t.Fatal("insufficient exchanges")
			}
			t.Logf("held carrier duration=%s rounds=%d active_sessions=0", time.Since(start), rounds)
		})
	}
}
