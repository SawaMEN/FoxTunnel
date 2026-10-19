package access

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const secretA = "random-test-alice-credential-0123456789"
const secretB = "random-test-bob-credential-9876543210"

func policy() Document {
	return Document{Version: 1, Users: []User{{ID: "a", Username: "alice", Password: secretA}, {ID: "b", Username: "bob", Password: secretB}}}
}
func request(user, pass string) *http.Request {
	r := httptest.NewRequest("CONNECT", "https://example.org:443", nil)
	r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	return r
}
func begin(t *testing.T, c *Controller, user, pass string) (context.Context, func()) {
	t.Helper()
	ctx, done, err := c.Begin(request(user, pass))
	if err != nil {
		t.Fatal(err)
	}
	return ctx, done
}
func newTest(t *testing.T, d Document, path string) *Controller {
	t.Helper()
	c, err := New(d, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func TestAtomicRotationRevocationAndCarrierBinding(t *testing.T) {
	d := policy()
	c := newTest(t, d, "")
	alice, done := begin(t, c, "alice", secretA)
	defer done()
	bob, bdone := begin(t, c, "bob", secretB)
	defer bdone()
	wrong := request("bob", secretB).WithContext(Scope(alice))
	if _, _, err := c.Begin(wrong); !errors.Is(err, ErrDenied) {
		t.Fatal("switched principal within a carrier", err)
	}
	invalid := policy()
	invalid.Users[1].ID = "a"
	if c.Replace(invalid) == nil {
		t.Fatal("accepted duplicate ID")
	}
	if alice.Err() != nil {
		t.Fatal("failed reload revoked user")
	}
	d.Users[0].Password = secretB + "rotated"
	if err := c.Replace(d); err != nil {
		t.Fatal(err)
	}
	select {
	case <-alice.Done():
	case <-time.After(time.Second):
		t.Fatal("rotation did not cancel active work")
	}
	if bob.Err() != nil {
		t.Fatal("rotation affected another user")
	}
	if _, _, err := c.Begin(request("alice", secretA)); err == nil {
		t.Fatal("old credential accepted")
	}
	next, finish := begin(t, c, "alice", d.Users[0].Password)
	defer finish()
	if Owner(next) == Owner(alice) {
		t.Fatal("reused revoked carrier namespace")
	}
	d.Users = d.Users[1:]
	if c.Replace(d) != nil {
		t.Fatal("remove")
	}
	select {
	case <-next.Done():
	case <-time.After(time.Second):
		t.Fatal("remove did not revoke")
	}
}
func TestIndependentConcurrencyRateAndGlobalBudget(t *testing.T) {
	d := policy()
	d.Users[0].MaxRequests = 1
	d.Users[0].Burst = 1
	d.Users[0].RequestsPerSecond = .1
	c := newTest(t, d, "")
	_, done := begin(t, c, "alice", secretA)
	if _, _, err := c.Begin(request("alice", secretA)); !errors.Is(err, ErrLimited) {
		t.Fatal(err)
	}
	_, other := begin(t, c, "bob", secretB)
	other()
	done()
	if _, _, err := c.Begin(request("alice", secretA)); !errors.Is(err, ErrLimited) {
		t.Fatal("rate bucket reset after release", err)
	}
	c.mu.Lock()
	c.attempt = bucket{}
	c.policy.AttemptBurst = 1
	c.mu.Unlock()
	if _, _, err := c.Begin(request("unknown", "bad")); err == nil {
		t.Fatal("bad credential accepted")
	}
	if _, _, err := c.Begin(request("bob", secretB)); !errors.Is(err, ErrDenied) {
		t.Fatal("global attempt budget bypass", err)
	}
}

type sink struct {
	bytes  atomic.Int64
	closed atomic.Bool
}

func (s *sink) Read([]byte) (int, error) { return 0, io.EOF }
func (s *sink) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	s.bytes.Add(int64(len(p)))
	return len(p), nil
}
func (s *sink) Close() error                     { s.closed.Store(true); return nil }
func (s *sink) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (s *sink) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (s *sink) SetDeadline(time.Time) error      { return nil }
func (s *sink) SetReadDeadline(time.Time) error  { return nil }
func (s *sink) SetWriteDeadline(time.Time) error { return nil }
func TestConcurrentQuotaNeverOvershootsAndRotationKeepsUsage(t *testing.T) {
	d := policy()
	d.Users[0].QuotaBytes = 256 << 10
	d.Users[0].MaxTunnels = 128
	c := newTest(t, d, "")
	ctx, done := begin(t, c, "alice", secretA)
	defer done()
	var sinks []*sink
	var conns []net.Conn
	for range 64 {
		s := new(sink)
		conn, err := Dial(ctx, func(context.Context) (net.Conn, error) { return s, nil })
		if err != nil {
			t.Fatal(err)
		}
		sinks = append(sinks, s)
		conns = append(conns, conn)
	}
	var wg sync.WaitGroup
	for _, conn := range conns {
		wg.Go(func() { defer conn.Close(); _, _ = conn.Write(make([]byte, 64<<10)) })
	}
	wg.Wait()
	var total int64
	for _, s := range sinks {
		total += s.bytes.Load()
	}
	if total > 256<<10 || total == 0 {
		t.Fatal("quota overshoot or no progress", total)
	}
	if got := c.Snapshot().Users[0].Bytes; got != total {
		t.Fatal("meter mismatch", got, total)
	}
	d.Users[0].Password = secretA + "rotate"
	if c.Replace(d) != nil {
		t.Fatal("rotate")
	}
	if _, _, err := c.Begin(request("alice", d.Users[0].Password)); !errors.Is(err, ErrQuota) {
		t.Fatal("rotation reset quota", err)
	}
}
func TestTunnelLimitIncludesDialAndRevocationCancelsIt(t *testing.T) {
	d := policy()
	d.Users[0].MaxTunnels = 1
	c := newTest(t, d, "")
	ctx, done := begin(t, c, "alice", secretA)
	defer done()
	entered := make(chan struct{})
	ended := make(chan error, 1)
	go func() {
		_, err := Dial(ctx, func(ctx context.Context) (net.Conn, error) { close(entered); <-ctx.Done(); return nil, ctx.Err() })
		ended <- err
	}()
	<-entered
	var called bool
	if _, err := Dial(ctx, func(context.Context) (net.Conn, error) { called = true; return nil, io.EOF }); !errors.Is(err, ErrLimited) || called {
		t.Fatal("dial bypassed admission", err)
	}
	d.Users[0].Disabled = true
	c.Replace(d)
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("revoked dial retained")
	}
}
func TestDurableReservationsSurviveRestartAndStateFailure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux durable ledger")
	}
	if testing.Short() {
		t.Skip("durability")
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "usage.json")
	d := policy()
	d.Users[0].QuotaBytes = 4 << 20
	c := newTest(t, d, path)
	if second, err := New(d, path); err == nil {
		second.Close()
		t.Fatal("two writers opened the same ledger")
	}
	ctx, done := begin(t, c, "alice", secretA)
	s := new(sink)
	conn, err := Dial(ctx, func(context.Context) (net.Conn, error) { return s, nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write(make([]byte, 12345)); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	done()
	if n := c.Snapshot().Users[0].ChargedBytes; n != reservation {
		t.Fatal(n)
	}
	c.Close()
	c2 := newTest(t, d, path)
	if got := c2.Snapshot().Users[0]; got.ChargedBytes != reservation || got.Bytes != 0 {
		t.Fatal("restart reset reserved usage", got)
	}
	ctx2, end := begin(t, c2, "alice", secretA)
	defer end()
	c2.mu.Lock()
	c2.statePath = filepath.Join(dir, "missing", "state")
	c2.mu.Unlock()
	s2 := new(sink)
	conn2, err := Dial(ctx2, func(context.Context) (net.Conn, error) { return s2, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	if _, err = conn2.Write([]byte("must not leave socket")); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	if s2.bytes.Load() != 0 || !c2.Snapshot().StateFailed {
		t.Fatal("state failure leaked unaccounted bytes")
	}
}
func TestAccessDocumentsAndDiagnosticsDoNotExposeSecrets(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "policy.json")
	d := policy()
	data, _ := json.Marshal(d)
	os.WriteFile(file, data, 0600)
	if _, err := ReadDocument(file); err != nil {
		t.Fatal(err)
	}
	c := newTest(t, d, "")
	stats, _ := json.Marshal(c.Snapshot())
	if strings.Contains(string(stats), secretA) || strings.Contains(string(stats), "alice") {
		t.Fatal("diagnostics exposed credentials")
	}
	for _, bad := range []string{`{"v":1,"users":[],"users":[]}`, `{"v":1,"users":[],"PASSWORD":"` + secretA + `"}`, `{"v":1,"users":[{"id":"../../` + secretA + `"}]}`} {
		os.WriteFile(file, []byte(bad), 0600)
		_, err := ReadDocument(file)
		if err == nil || strings.Contains(err.Error(), secretA) {
			t.Fatal("unredacted config error", err)
		}
	}
	os.WriteFile(file, data, 0644)
	os.Chmod(file, 0644)
	if _, err := ReadDocument(file); err == nil {
		t.Fatal("world-readable credentials accepted")
	}
}
