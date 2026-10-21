package tunnel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

func TestStage4UDPBlockedSendCancellationTerminatesSession(t *testing.T) {
	c, err := NewClient("https://example.org", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.EnableUDP = true
	reader, writer := io.Pipe()
	defer writer.Close()
	c.transport = stage3RoundTripper(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ProtoMajor: 2, Body: reader}, nil
	})
	flow, err := c.OpenUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- flow.Send(ctx, Datagram{Address: "127.0.0.1:53", Payload: []byte("blocked")}) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("send cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked Send leaked")
	}
	if _, err = flow.Receive(context.Background()); err == nil {
		t.Fatal("partial framed write left session alive")
	}
}

func TestStage4UDPIncomingQueueIsBounded(t *testing.T) {
	c, err := NewClient("https://example.org", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.EnableUDP = true
	reader, writer := io.Pipe()
	defer writer.Close()
	sent := make(chan error, 1)
	c.transport = stage3RoundTripper(func(r *http.Request) (*http.Response, error) {
		go func() {
			wire, err := udpproto.ReadFrame(r.Body)
			if err != nil {
				sent <- err
				return
			}
			for range 100 {
				if err = udpproto.WriteFrame(writer, wire); err != nil {
					sent <- err
					return
				}
			}
			sent <- nil
		}()
		return &http.Response{StatusCode: 200, ProtoMajor: 2, Body: reader}, nil
	})
	flow, err := c.OpenUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = flow.Send(ctx, Datagram{Address: "127.0.0.1:53", Payload: []byte("burst")}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-sent:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("slow consumer blocked frame reader")
	}
	// The writer completes after bytes are read; wait for final queue processing.
	deadline := time.Now().Add(time.Second)
	for len(flow.queue) < udpStreamQueued && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(flow.queue) != udpStreamQueued || cap(flow.queue) != udpStreamQueued {
		t.Fatal("receive queue bound", len(flow.queue), cap(flow.queue))
	}
}
