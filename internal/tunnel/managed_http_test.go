package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
)

// This fixture verifies client routing and ownership, not Gecko's networking.
// Actual Mozilla transfer tests live in experiments/firefox-necko and CI.
type managedHTTPFixture struct {
	tlsTransport
	calls atomic.Int32
}

func (f *managedHTTPFixture) Ready(context.Context) error { return nil }
func (f *managedHTTPFixture) Close() error                { f.CloseIdleConnections(); return nil }
func (f *managedHTTPFixture) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected direct managed TCP bypass")
}
func (f *managedHTTPFixture) RoundTrip(r *http.Request) (*http.Response, error) {
	f.calls.Add(1)
	return f.tlsTransport.RoundTrip(r)
}
func installManagedHTTPFixture(t *testing.T, c *Client, mode string) *managedHTTPFixture {
	t.Helper()
	base, err := makeTLStransport("go", c.tlsConfig, "", "")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &managedHTTPFixture{tlsTransport: base}
	c.SetManagedHTTPTransport(mode, func() (ManagedTransport, error) { return fixture, nil })
	return fixture
}
func TestManagedHTTPTransports(t *testing.T) { testNativeTransports(t, "managed") }
func TestManagedHTTPBond(t *testing.T) {
	for _, lanes := range []bool{false, true} {
		testBondedSOCKSNativeLanes(t, "managed", 8, false, "h2-connect", lanes, "auto")
	}
}
func TestManagedHTTPUnknownOriginFailsBeforeFactory(t *testing.T) {
	c, err := NewClient("https://configured.example", "u", "p", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var called atomic.Bool
	c.SetManagedHTTPTransport("h2-connect", func() (ManagedTransport, error) { called.Store(true); return nil, errors.New("must not start") })
	req, _ := http.NewRequest("GET", "https://untrusted.example/", nil)
	if resp, err := c.transport.RoundTrip(req); err == nil || resp != nil || called.Load() {
		t.Fatal("untrusted origin reached native factory")
	}
}
func TestManagedHTTPMissingAdapterNeverUsesLegacy(t *testing.T) {
	c, err := NewClient("https://configured.example", "u", "p", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetManagedHTTPTransport("h2-connect", func() (ManagedTransport, error) { return &udpManagedFixture{}, nil })
	reader, writer := io.Pipe()
	defer writer.Close()
	req, _ := http.NewRequest("POST", "https://configured.example/", reader)
	if resp, err := c.transport.RoundTrip(req); err == nil || resp != nil {
		t.Fatal("missing native HTTP adapter accepted")
	}
	if _, err = writer.Write([]byte{1}); err == nil {
		t.Fatal("rejected request body survived")
	}
}
