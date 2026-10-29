package tunnel

import (
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/SawaMEN/VetroffProxy/internal/nodeperf"
)

// meteredBody does not buffer data. It preserves Read and Close semantics and
// counts only bytes actually consumed by the carrier/stream.
type meteredBody struct {
	io.ReadCloser
	onRead  func(int)
	onClose func()
	once    sync.Once
}

func (b *meteredBody) Read(data []byte) (int, error) {
	n, err := b.ReadCloser.Read(data)
	if n > 0 && b.onRead != nil {
		b.onRead(n)
	}
	return n, err
}

func (b *meteredBody) Close() error {
	err := b.ReadCloser.Close()
	if b.onClose != nil {
		b.once.Do(b.onClose)
	}
	return err
}

// monitoredRoundTrip observes the same TLS-verified per-origin transport used
// for real connections. It performs no additional network probes, reads no
// payload itself, and never changes the selected endpoint or retry policy.
func monitoredRoundTrip(m *nodeperf.Monitor, base tlsTransport, r *http.Request) (*http.Response, error) {
	origin := r.URL.Scheme + "://" + r.URL.Host
	m.Begin(origin)
	req := r
	if r.Body != nil {
		req = r.Clone(r.Context())
		req.Body = &meteredBody{
			ReadCloser: r.Body,
			onRead:     func(n int) { m.Transfer(origin, n, 0) },
		}
	}
	started := time.Now()
	resp, err := base.RoundTrip(req)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	m.Observe(origin, time.Since(started), status, err)
	if err != nil || resp == nil || resp.Body == nil {
		m.End(origin)
		return resp, err
	}
	resp.Body = &meteredBody{
		ReadCloser: resp.Body,
		onRead:     func(n int) { m.Transfer(origin, 0, n) },
		onClose:    func() { m.End(origin) },
	}
	return resp, nil
}
