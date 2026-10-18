package tunnel

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestPaddingEndToEnd(t *testing.T) { testPaddingBackend(t, "go") }
func testPaddingBackend(t *testing.T, backend string) {
	t.Helper()
	target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	client, addr := testClient(t, &Server{Username: "alice", Password: "secret", AllowPrivate: true, Padding: true})
	if err := client.SetTLSBackend(backend); err != nil {
		t.Fatal(err)
	}
	client.Padding = true
	conn, code := connectSOCKS(t, addr, target)
	defer conn.Close()
	if code != 0 {
		t.Fatal(code)
	}
	// Exercise all eight initial records, the transition and interactive flushes.
	for i := 0; i < 12; i++ {
		message := bytes.Repeat([]byte{byte(i)}, i+1)
		if _, err := conn.Write(message); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(message))
		if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, message) {
			t.Fatalf("interactive %d: %v", i, err)
		}
	}
	message := bytes.Repeat([]byte("raw tail"), 1<<16)
	done := make(chan error, 1)
	go func() { _, err := conn.Write(message); done <- err }()
	got := make([]byte, len(message))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, message) {
		t.Fatalf("bulk: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestPaddingHalfClose(t *testing.T) {
	target := testDestination(t, func(c net.Conn) { data, _ := io.ReadAll(c); _, _ = c.Write(data) })
	client, addr := testClient(t, &Server{Username: "alice", Password: "secret", AllowPrivate: true, Padding: true})
	client.Padding = true
	conn, code := connectSOCKS(t, addr, target)
	defer conn.Close()
	if code != 0 {
		t.Fatal(code)
	}
	if _, err := conn.Write([]byte("one padded record before EOF")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "one padded record before EOF" {
		t.Fatalf("half-close: %q %v", got, err)
	}
}
func TestPaddingNegotiationMismatch(t *testing.T) {
	for _, tc := range []struct {
		name     string
		request  bool
		response []string
		ok       bool
	}{
		{"required not acknowledged", true, nil, false},
		{"unexpected acknowledgement", false, []string{paddingVersion}, false},
		{"unknown version", true, []string{"future-v2"}, false},
		{"duplicate acknowledgement", true, []string{paddingVersion, paddingVersion}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			received := make(chan int64, 1)
			client, addr := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for _, v := range tc.response {
					w.Header().Add(paddingHeader, v)
				}
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				n, _ := io.Copy(io.Discard, r.Body)
				received <- n
			}))
			client.Padding = tc.request
			conn, code := connectSOCKS(t, addr, "example.com:443")
			conn.Close()
			if (code == 0) != tc.ok {
				t.Fatalf("SOCKS %d", code)
			}
			select {
			case n := <-received:
				if n != 0 {
					t.Fatal("application bytes sent before agreement")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("mismatched stream not cancelled")
			}
		})
	}
}
func TestPaddingServerOptInAndPlainCompatibility(t *testing.T) {
	target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	for _, tc := range []struct {
		name                    string
		client, server, success bool
	}{
		{"server rejects when disabled", true, false, false},
		{"plain client on enabled server", false, true, true},
		{"plain baseline", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, addr := testClient(t, &Server{Username: "alice", Password: "secret", AllowPrivate: true, Padding: tc.server})
			client.Padding = tc.client
			conn, code := connectSOCKS(t, addr, target)
			defer conn.Close()
			if (code == 0) != tc.success {
				t.Fatalf("SOCKS %d", code)
			}
			if tc.success {
				if _, err := conn.Write([]byte("plain")); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, 5)
				if _, err := io.ReadFull(conn, got); err != nil || string(got) != "plain" {
					t.Fatalf("%q %v", got, err)
				}
			}
		})
	}
}

func TestMalformedPaddedUploadDoesNotReachDestination(t *testing.T) {
	received := make(chan int, 1)
	target := testDestination(t, func(c net.Conn) { data, _ := io.ReadAll(c); received <- len(data) })
	client, _ := testClient(t, &Server{Username: "alice", Password: "secret", AllowPrivate: true, Padding: true})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, client.ServerURL.String(), bytes.NewReader([]byte{0, 0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = target
	req.Header.Set(paddingHeader, paddingVersion)
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret")))
	resp, err := client.transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	select {
	case n := <-received:
		if n != 0 {
			t.Fatalf("forwarded %d malformed bytes", n)
		}
	case <-ctx.Done():
		t.Fatal("malformed stream did not release destination")
	}
}
