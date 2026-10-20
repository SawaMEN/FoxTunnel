//go:build neqo && cgo && linux && amd64

package neqo

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStage6NativeEngineTeardownAndBorrowedRead(t *testing.T) {
	var requests atomic.Int32
	raw, cfg := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(200)
		_ = http.NewResponseController(w).Flush()
		<-r.Context().Done()
	}))
	base, err := NewTransport(Config{TLS: cfg, HandshakeTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client := base.(*transport)
	defer client.CloseIdleConnections()
	for cycle := range 6 {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		var responses []*http.Response
		for range 4 {
			req, _ := http.NewRequestWithContext(ctx, "GET", raw, nil)
			response, err := client.RoundTrip(req)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			responses = append(responses, response)
		}
		client.CloseIdleConnections()
		client.mu.Lock()
		live := len(client.live)
		client.mu.Unlock()
		if live != 1 {
			cancel()
			t.Fatal("idle close destroyed active engine", cycle, live)
		}

		// Close races a read while the actor may borrow the caller's
		// memory. Once Read returns, immediate reuse must be safe.
		buffer := make([]byte, 32<<10)
		reading := make(chan struct{})
		done := make(chan error, 1)
		go func() { close(reading); _, err := responses[0].Body.Read(buffer); done <- err }()
		<-reading
		var closing sync.WaitGroup
		for range 4 {
			closing.Go(func() { _ = responses[0].Body.Close() })
		}
		closing.Wait()
		select {
		case err := <-done:
			if err == nil {
				cancel()
				t.Fatal("closed read succeeded")
			}
		case <-ctx.Done():
			cancel()
			t.Fatal("close did not join borrowed read")
		}
		for i := range buffer {
			buffer[i] = byte(i)
		}
		cancel()
		for _, response := range responses {
			_ = response.Body.Close()
		}
		client.CloseIdleConnections()
		client.mu.Lock()
		live, origins := len(client.live), len(client.origins)
		client.mu.Unlock()
		if live != 0 || origins != 0 {
			t.Fatal("native engine pool retained after teardown", live, origins)
		}
	}
	if requests.Load() != 24 {
		t.Fatal("unexpected request replay or missing request", requests.Load())
	}
}

func TestStage6AcceptedCommandJoinsBeforeReturningBuffer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &connection{commands: make(chan command), done: make(chan struct{})}
	buffer := make([]byte, 16)
	returned := make(chan struct{})
	go func() { _, _ = c.call(ctx, command{kind: 'r', data: buffer}); close(returned) }()
	cmd := <-c.commands
	cancel()
	select {
	case <-returned:
		t.Fatal("cancellation returned a still-borrowed buffer")
	case <-time.After(20 * time.Millisecond):
	}
	copy(cmd.data, "joined")
	cmd.reply <- result{n: 6}
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("actor reply did not return buffer ownership")
	}
	if string(buffer[:6]) != "joined" {
		t.Fatal(io.ErrUnexpectedEOF)
	}
}
