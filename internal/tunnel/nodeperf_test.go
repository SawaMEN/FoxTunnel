package tunnel

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/nodeperf"
)

type nodePerfRoundTripper func(*http.Request) (*http.Response, error)

func (fn nodePerfRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}
func (nodePerfRoundTripper) CloseIdleConnections() {}

func TestMonitoredRoundTripCountsStreamingBodies(t *testing.T) {
	monitor := nodeperf.New()
	base := nodePerfRoundTripper(func(r *http.Request) (*http.Response, error) {
		uploaded, err := io.ReadAll(r.Body)
		if err != nil || string(uploaded) != "request-data" {
			t.Fatalf("unexpected uploaded body %q, %v", uploaded, err)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("response-data"))}, nil
	})
	req, err := http.NewRequest(http.MethodPost, "https://node.example/secret-path", strings.NewReader("request-data"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := monitoredRoundTrip(monitor, base, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	snap := monitor.Snapshot()
	if len(snap) != 1 || snap[0].Origin != "https://node.example" ||
		snap[0].ActiveRequests != 0 || snap[0].UploadedBytes != uint64(len("request-data")) ||
		snap[0].DownloadedBytes != uint64(len("response-data")) || snap[0].Samples != 1 ||
		snap[0].RequestLatencyMS < 0 {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
}

func TestMonitoredRoundTripFailureDoesNotLeakActive(t *testing.T) {
	monitor := nodeperf.New()
	req, _ := http.NewRequest(http.MethodGet, "https://node.example/", nil)
	base := nodePerfRoundTripper(func(*http.Request) (*http.Response, error) {
		time.Sleep(time.Millisecond)
		return nil, errors.New("dial failed")
	})
	if _, err := monitoredRoundTrip(monitor, base, req); err == nil {
		t.Fatal("expected failure")
	}
	snap := monitor.Snapshot()
	if len(snap) != 1 || snap[0].ActiveRequests != 0 || snap[0].FailedRequests != 1 {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
}
