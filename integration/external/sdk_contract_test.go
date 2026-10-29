package consumer_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ft "github.com/SawaMEN/VetroffProxy"
)

func TestSDKRuntimeContract(t *testing.T) {
	info := ft.RuntimeInfo()
	if ft.SDKSchema != 1 || info.SDKSchema != ft.SDKSchema || info.ProcessSchema != 1 || info.ProtocolDraft != ft.ProtocolDraft || info.Product != "protocol-core" || !info.Experimental {
		t.Fatal("incompatible SDK contract", info)
	}
	info.TLSBackends[0] = "mutated"
	if ft.RuntimeInfo().TLSBackends[0] != "go" {
		t.Fatal("shared capability slice")
	}
}

func sdkClient(t *testing.T) *ft.Client {
	t.Helper()
	endpoint, ca, credentials, _ := publicProxy(t)
	c, err := ft.NewClient(ft.ClientConfig{ServerURL: endpoint, CACertFile: ca, Credentials: credentials, TLSBackend: "go", MaxConnections: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestSDKStatusLifecycle(t *testing.T) {
	c := sdkClient(t)
	if _, err := c.WatchStatus(context.Background(), 0); err == nil {
		t.Fatal("unbounded polling accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := c.WatchStatus(ctx, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-stream:
		data, _ := json.Marshal(event)
		if event.Schema != 1 || event.Sequence != 1 || event.Snapshot.Closed || event.Snapshot.Limit != 4 || strings.Contains(string(data), "external-sdk") || strings.Contains(string(data), "127.0.0.1") {
			t.Fatal("invalid or private initial state", string(data))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no initial snapshot")
	}
	// Leave the consumer unread while state and shutdown advance. Neither host
	// notifications nor Close may block on a subscriber.
	for i := 0; i < 100; i++ {
		if err := c.NotifyNetworkChange(); err != nil {
			t.Fatal(err)
		}
	}
	closed := make(chan struct{})
	go func() { c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("slow subscriber blocked Close")
	}
	deadline := time.After(3 * time.Second)
	seenClosed := false
	for {
		select {
		case event, ok := <-stream:
			if !ok {
				if !seenClosed {
					t.Fatal("closed state missing")
				}
				return
			}
			seenClosed = seenClosed || event.Snapshot.Closed
		case <-deadline:
			t.Fatal("watcher leaked after Close")
		}
	}
}

func TestSDKWatchCancellation(t *testing.T) {
	c := sdkClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	stream, err := c.WatchStatus(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-stream:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("canceled watcher leaked")
		}
	}
}

func TestSDKOperationMetricsInWatchEvents(t *testing.T) {
	c := sdkClient(t)
	origin := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer origin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	events, err := c.WatchStatus(ctx, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if i == 1 {
			if err := c.NotifyNetworkChange(); err != nil {
				t.Fatal(err)
			}
		}
		conn, err := c.DialContext(ctx, "tcp", origin.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
	for event := range events {
		op := event.Snapshot.Transport.Operations
		if op.TCP.Succeeded != 2 || op.Recovery.AfterNetworkChange != 1 {
			continue
		}
		data, err := json.Marshal(event)
		if err != nil || strings.Contains(string(data), origin.Listener.Addr().String()) || strings.Contains(string(data), "external-sdk") {
			t.Fatal("operation metrics leaked identity in a watch event", err)
		}
		return
	}
	t.Fatal("operation metrics did not reach the external SDK subscriber")
}

func TestSDKSOCKSCancellationIsolation(t *testing.T) {
	c := sdkClient(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("still-open")) }))
	defer origin.Close()
	direct, err := c.DialContext(context.Background(), "tcp", origin.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.ServeSOCKSContext(ctx, listener) }()
	local, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	local.SetDeadline(time.Now().Add(3 * time.Second))
	local.Write([]byte{5, 1, 0})
	var greeting [2]byte
	if _, err := io.ReadFull(local, greeting[:]); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SOCKS service leaked")
	}
	if _, err := local.Read(make([]byte, 1)); err == nil {
		t.Fatal("accepted socket survived service cancellation")
	}
	if c.Snapshot().Closed {
		t.Fatal("service cancellation closed the whole client")
	}
	if err := c.NotifyNetworkChange(); err != nil {
		t.Fatal(err)
	}
	if s := c.Snapshot(); s.TCPConnections != 1 || s.SOCKSListeners != 0 {
		t.Fatal("owned resources leaked", s)
	}
	direct.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(direct, "GET / HTTP/1.0\r\nHost: local\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(direct)
	if err != nil || !strings.Contains(string(body), "still-open") {
		t.Fatal("SOCKS cancellation broke independent stream", err)
	}
	direct.Close()
	c.Close()
	if _, err := c.DialContext(context.Background(), "tcp", "127.0.0.1:9"); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed client accepted setup", err)
	}
}
