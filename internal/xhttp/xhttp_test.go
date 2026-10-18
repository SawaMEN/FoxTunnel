package xhttp

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStreamingCarrierWire(t *testing.T) {
	for _, mode := range []string{"xhttp-stream-one", "xhttp-stream-up"} {
		t.Run(mode, func(t *testing.T) {
			served := make(chan struct{})
			s := &Server{MaxSessions: 1, Authorized: func(r *http.Request) bool { return r.Header.Get("Proxy-Authorization") == "token" }, ServeConn: func(c net.Conn, r *http.Request) { defer close(served); _, _ = io.Copy(c, c) }}
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !Matches(r) {
					t.Error("unexpected path", r.URL.Path)
				}
				if len(r.Header.Get("Referer")) < 100 {
					t.Error("missing header padding")
				}
				if r.Method == "POST" && r.Header.Get("Content-Type") != "application/grpc" {
					t.Error("wrong upload content type")
				}
				s.ServeHTTP(w, r)
			})
			server := httptest.NewUnstartedServer(h)
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			c, err := Dial(context.Background(), server.Client().Transport, server.URL, mode, "token", "")
			if err != nil {
				t.Fatal(err)
			}
			c.SetDeadline(time.Now().Add(2 * time.Second))
			payload := bytes.Repeat([]byte("ordered bytes"), 30000)
			wrote := make(chan error, 1)
			go func() { _, err := c.Write(payload); wrote <- err }()
			got := make([]byte, len(payload))
			_, err = io.ReadFull(c, got)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatal("corrupt carrier", err)
			}
			if err := <-wrote; err != nil {
				t.Fatal(err)
			}
			c.Close()
			select {
			case <-served:
			case <-time.After(2 * time.Second):
				t.Fatal("application leaked after close")
			}
		})
	}
}
func TestAdmissionAndPairExpiry(t *testing.T) {
	s := &Server{MaxSessions: 1, Authorized: func(*http.Request) bool { return false }}
	r := httptest.NewRequest("POST", "https://node"+Path, nil)
	r.ProtoMajor = 2
	s.ServeHTTP(httptest.NewRecorder(), r)
	if s.active != 0 {
		t.Fatal("unauthenticated allocation")
	}
	id := "00000000-0000-4000-8000-000000000001"
	p, ok := s.claim(id, true)
	if !ok {
		t.Fatal("claim")
	}
	if _, ok := s.claim(id, true); ok {
		t.Fatal("duplicate upload accepted")
	}
	if _, ok := s.claim("00000000-0000-4000-8000-000000000002", true); ok {
		t.Fatal("limit bypass")
	}
	s.mu.Lock()
	p.timer.Reset(time.Millisecond)
	s.mu.Unlock()
	select {
	case <-p.done:
	case <-time.After(time.Second):
		t.Fatal("unpaired session retained")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active != 0 || len(s.sessions) != 0 {
		t.Fatal("expired pair retained")
	}
}
func TestPathValidation(t *testing.T) {
	for _, path := range []string{Path + "bad", Path + "00000000-0000-4000-8000-000000000001/0", Path + "?token=secret", Path + "%2f", Path + "../"} {
		if Matches(httptest.NewRequest("GET", "https://node"+path, nil)) {
			t.Fatal("ambiguous path accepted", path)
		}
	}
}
