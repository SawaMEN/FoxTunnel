package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/buildinfo"
	"github.com/SawaMEN/FoxTunnel/internal/neqo"
	"github.com/SawaMEN/FoxTunnel/internal/profile"
	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
)

type doctorFixture struct {
	config profile.Config
	path   string
	ca     string
	node   *httptest.Server
	seen   atomic.Int64
}

func newDoctorFixture(t *testing.T, mode, backend string, handler *tunnel.Server) *doctorFixture {
	t.Helper()
	if handler == nil {
		handler = &tunnel.Server{Username: "private-user-marker", Password: "private-password-marker-012345", AllowPrivate: true, EnableUDP: true}
	}
	f := &doctorFixture{}
	f.node = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.seen.Add(1)
		handler.ServeHTTP(w, r)
	}))
	f.node.EnableHTTP2 = true
	f.node.TLS = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}}
	f.node.StartTLS()
	t.Cleanup(f.node.Close)
	if mode == "h3-post" {
		udp, err := net.ListenPacket("udp4", f.node.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- handler.ServeHTTP3(ctx, udp, f.node.TLS, 32) }()
		t.Cleanup(func() {
			cancel()
			udp.Close()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("H3 server did not stop")
			}
		})
	}
	dir := t.TempDir()
	f.ca, f.path = filepath.Join(dir, "ca.pem"), filepath.Join(dir, "connection.txt")
	if err := os.WriteFile(f.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.node.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	f.config = profile.Config{Version: 1, Servers: []string{f.node.URL}, Username: handler.Username, Password: handler.Password, Transport: mode, TLSBackend: backend}
	f.save(t)
	return f
}

func (f *doctorFixture) save(t *testing.T) {
	t.Helper()
	link, err := profile.Encode(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.path, []byte(link+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func doctorTCPDestination(t *testing.T, behavior string) (string, *atomic.Int64) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	count := new(atomic.Int64)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				b := make([]byte, doctorPayloadBytes)
				if _, err := io.ReadFull(c, b); err != nil {
					return
				}
				switch behavior {
				case "silent":
					io.Copy(io.Discard, c) // Return as soon as doctor cancels.
					return
				case "mismatch":
					b[0] ^= 0xff
				}
				c.Write(b)
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return l.Addr().String(), count
}

func doctorUDPDestination(t *testing.T, mismatch bool) (string, *atomic.Int64) {
	t.Helper()
	l, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	count := new(atomic.Int64)
	go func() {
		b := make([]byte, 1500)
		for {
			n, a, err := l.ReadFrom(b)
			if err != nil {
				return
			}
			count.Add(1)
			if mismatch && n > 0 {
				b[0] ^= 0xff
			}
			l.WriteTo(b[:n], a)
		}
	}()
	return l.LocalAddr().String(), count
}

func callDoctor(t *testing.T, f *doctorFixture, target string, options ...string) (doctorReport, error, string) {
	t.Helper()
	args := []string{"--link-file", f.path, "--ca-cert", f.ca, "--target", target, "--json"}
	var out bytes.Buffer
	err := doctorCommand(context.Background(), append(args, options...), &out)
	var report doctorReport
	if e := json.Unmarshal(out.Bytes(), &report); e != nil {
		t.Fatalf("missing JSON diagnosis: %v, command error %v", e, err)
	}
	for _, secret := range []string{f.path, f.ca, f.config.Username, f.config.Password, f.node.URL, target, "vetroff://"} {
		if secret != "" && strings.Contains(out.String(), secret) {
			t.Fatal("diagnosis disclosed private input")
		}
	}
	return report, err, out.String()
}

func TestDoctorTCPTransportMatrix(t *testing.T) {
	for _, mode := range []string{"h2-connect", "h2-post", "h3-post", "wss", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) {
			f := newDoctorFixture(t, mode, "go", nil)
			target, calls := doctorTCPDestination(t, "echo")
			before, _ := os.ReadFile(f.path)
			r, err, _ := callDoctor(t, f, target)
			if err != nil || !r.OK || r.Schema != 1 || len(r.Checks) != 6 || r.Checks[5].Stage != "tcp_echo" || r.Transport != mode || calls.Load() != 1 {
				t.Fatalf("TCP diagnosis failed: %+v, %v, destination calls %d", r, err, calls.Load())
			}
			wantMajor := 2
			if mode == "h3-post" {
				wantMajor = 3
			}
			if r.Checks[3].HTTPMajor != wantMajor {
				t.Fatal("probe did not use selected HTTP protocol")
			}
			after, _ := os.ReadFile(f.path)
			if !bytes.Equal(before, after) {
				t.Fatal("doctor modified the profile")
			}
		})
	}
}

func TestDoctorNativeBackends(t *testing.T) {
	for _, mode := range []string{"h2-connect", "h3-post"} {
		t.Run(mode, func(t *testing.T) {
			if !buildinfo.NSSAvailable || mode == "h3-post" && !neqo.Available {
				t.Skip("native backend is not compiled in")
			}
			backend, engine := "nss", "legacy"
			if mode == "h3-post" {
				backend, engine = "auto", "mozilla"
			}
			f := newDoctorFixture(t, mode, backend, nil)
			target, _ := doctorTCPDestination(t, "echo")
			if r, err, _ := callDoctor(t, f, target, "--engine", engine); err != nil || !r.OK {
				t.Fatalf("native diagnosis failed: %+v, %v", r, err)
			}
		})
	}
}

func TestDoctorUDPEcho(t *testing.T) {
	for _, mode := range []string{"h2-connect", "h3-post"} {
		t.Run(mode, func(t *testing.T) {
			f := newDoctorFixture(t, mode, "go", nil)
			target, calls := doctorUDPDestination(t, false)
			r, err, _ := callDoctor(t, f, target, "--network", "udp")
			if err != nil || !r.OK || len(r.Checks) != 5 || r.Checks[4].Stage != "udp_echo" || calls.Load() != 1 {
				t.Fatalf("UDP diagnosis failed: %+v, %v", r, err)
			}
		})
	}
}

func TestDoctorDisabledUDP(t *testing.T) {
	f := newDoctorFixture(t, "h2-connect", "go", &tunnel.Server{Username: "private-user-marker", Password: "private-password-marker-012345", AllowPrivate: true})
	target, calls := doctorUDPDestination(t, false)
	r, err, _ := callDoctor(t, f, target, "--network", "udp")
	last := r.Checks[len(r.Checks)-1]
	if err == nil || r.OK || last.Stage != "udp_echo" || last.Reason != "udp_exchange_failed" || calls.Load() != 0 {
		t.Fatalf("disabled UDP passed or sent payload: %+v, %v", r, err)
	}
}

func TestDoctorNeverFollowsRedirects(t *testing.T) {
	var followed atomic.Int64
	redirect := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Add(1) }))
	defer redirect.Close()
	f := newDoctorFixture(t, "h2-connect", "go", &tunnel.Server{Username: "private-user-marker", Password: "private-password-marker-012345", Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirect.URL, http.StatusFound)
	})})
	f.config.Password = "wrong-private-password-marker"
	f.save(t)
	r, err, _ := callDoctor(t, f, "127.0.0.1:1")
	if err == nil || r.OK || r.Checks[3].HTTPStatus != http.StatusFound || followed.Load() != 0 {
		t.Fatal("redirect was followed or mistaken for a working tunnel")
	}
}

func TestDoctorCancelEstablishedProbe(t *testing.T) {
	f := newDoctorFixture(t, "h2-connect", "go", nil)
	target, _ := doctorTCPDestination(t, "silent")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.AfterFunc(200*time.Millisecond, cancel)
	defer timer.Stop()
	var out bytes.Buffer
	started := time.Now()
	err := doctorCommand(ctx, []string{"--link-file", f.path, "--ca-cert", f.ca, "--target", target, "--json"}, &out)
	var r doctorReport
	if e := json.Unmarshal(out.Bytes(), &r); e != nil {
		t.Fatal(e)
	}
	last := r.Checks[len(r.Checks)-1]
	if err == nil || r.OK || last.Reason != "canceled" || time.Since(started) > 3*time.Second {
		t.Fatalf("probe did not stop after parent cancellation: %+v, %v", r, err)
	}
}

func TestDoctorTrustBeforeCredentials(t *testing.T) {
	for _, failure := range []string{"ca", "sni", "pin"} {
		t.Run(failure, func(t *testing.T) {
			f := newDoctorFixture(t, "h2-connect", "go", nil)
			if failure == "ca" {
				other := newDoctorFixture(t, "h2-connect", "go", nil)
				// httptest shares its built-in certificate. Generate another CA.
				operationPair(t, other.ca, other.ca+".key", 42)
				f.ca = other.ca
			}
			if failure == "sni" {
				f.config.SNI = "wrong-name.invalid"
			}
			if failure == "pin" {
				f.config.PinSHA256 = "sha256/" + strings.Repeat("A", 43) + "="
			}
			f.save(t)
			r, err, _ := callDoctor(t, f, "127.0.0.1:1")
			last := r.Checks[len(r.Checks)-1]
			if err == nil || r.OK || last.Stage != "transport" || last.Reason != "tls_trust_failed" || f.seen.Load() != 0 {
				t.Fatalf("trust failure was concealed or credentials sent: %+v, %v", r, err)
			}
		})
	}
}

func TestDoctorAuthenticationAndDestinationFailures(t *testing.T) {
	f := newDoctorFixture(t, "h2-connect", "go", nil)
	f.config.Password = "wrong-private-password-marker"
	f.save(t)
	target, calls := doctorTCPDestination(t, "echo")
	r, err, _ := callDoctor(t, f, target)
	last := r.Checks[len(r.Checks)-1]
	if err == nil || r.OK || last.Stage != "tunnel" || last.Reason != "tunnel_rejected" || calls.Load() != 0 {
		t.Fatalf("bad credentials passed: %+v, %v", r, err)
	}
	f.config.Password = "private-password-marker-012345"
	f.save(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := l.Addr().String()
	l.Close()
	r, err, _ = callDoctor(t, f, closed)
	last = r.Checks[len(r.Checks)-1]
	if err == nil || r.OK || last.Reason != "destination_or_policy_unavailable" {
		t.Fatalf("unreachable destination passed: %+v, %v", r, err)
	}
}

func TestDoctorTimeoutAndEchoMismatch(t *testing.T) {
	for _, behavior := range []string{"silent", "mismatch"} {
		t.Run(behavior, func(t *testing.T) {
			f := newDoctorFixture(t, "h2-connect", "go", nil)
			target, calls := doctorTCPDestination(t, behavior)
			started := time.Now()
			r, err, _ := callDoctor(t, f, target, "--timeout", "300ms")
			want := "echo_mismatch"
			if behavior == "silent" {
				want = "timeout"
			}
			last := r.Checks[len(r.Checks)-1]
			if err == nil || r.OK || last.Stage != "tcp_echo" || last.Reason != want || time.Since(started) > 3*time.Second || calls.Load() != 1 {
				t.Fatalf("echo failure concealed or retried: %+v, %v", r, err)
			}
		})
	}
	f := newDoctorFixture(t, "h2-connect", "go", nil)
	target, calls := doctorUDPDestination(t, true)
	r, err, _ := callDoctor(t, f, target, "--network", "udp")
	if err == nil || r.OK || r.Checks[len(r.Checks)-1].Reason != "echo_mismatch" || calls.Load() != 1 {
		t.Fatal("UDP payload mismatch concealed or retried")
	}
}

func TestDoctorBlockedQUICDoesNotFallback(t *testing.T) {
	f := newDoctorFixture(t, "h2-connect", "go", nil)
	// Only TCP is listening. A live UDP socket consumes packets without reply.
	udp, err := net.ListenPacket("udp4", f.node.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	f.config.Transport = "h3-post"
	f.save(t)
	r, err, _ := callDoctor(t, f, "127.0.0.1:1", "--timeout", "200ms")
	last := r.Checks[len(r.Checks)-1]
	if err == nil || r.OK || last.Stage != "transport" || last.Reason != "timeout" || f.seen.Load() != 0 {
		t.Fatalf("blocked QUIC was concealed by TCP fallback: %+v, %v", r, err)
	}
}

func TestDoctorDNSFailureAndCancellation(t *testing.T) {
	f := newDoctorFixture(t, "h2-connect", "go", nil)
	f.config.Servers = []string{"https://unresolvable.invalid"}
	f.save(t)
	o := doctorOptions{linkFile: f.path, ca: f.ca, engine: "legacy", target: "remote-echo.invalid:1234", network: "tcp"}
	var lookups int
	r := runDoctor(context.Background(), o, func(_ context.Context, host string) ([]net.IPAddr, error) {
		lookups++
		if host != "unresolvable.invalid" {
			t.Error("destination DNS was resolved locally")
		}
		return nil, errors.New("private-parser-and-dns-error-marker")
	})
	last := r.Checks[len(r.Checks)-1]
	data, _ := json.Marshal(r)
	if r.OK || last.Stage != "dns" || last.Reason != "proxy_dns_failed" || lookups != 1 || strings.Contains(string(data), "private-parser") {
		t.Fatalf("DNS failure concealed or exposed: %+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = runDoctor(ctx, o, func(context.Context, string) ([]net.IPAddr, error) {
		t.Error("canceled diagnosis performed DNS")
		return nil, nil
	})
	if r.OK || r.Checks[len(r.Checks)-1].Reason != "canceled" {
		t.Fatal("canceled diagnosis passed")
	}
}

func TestDoctorServerSelection(t *testing.T) {
	f := newDoctorFixture(t, "h2-connect", "go", nil)
	selected := f.config.Servers[0]
	f.config.Servers = []string{"https://unresolvable.invalid", selected}
	f.config.Balance = "round-robin"
	f.config.SNI = "primary-only.invalid"
	f.config.PinSHA256 = "sha256/" + strings.Repeat("A", 43) + "="
	f.save(t)
	target, _ := doctorTCPDestination(t, "echo")
	r, err, _ := callDoctor(t, f, target, "--server-index", "1")
	if err != nil || !r.OK || r.ServerIndex != 1 {
		t.Fatalf("explicit node selection failed: %+v, %v", r, err)
	}
	r, err, _ = callDoctor(t, f, target, "--server-index", "2")
	if err == nil || r.OK || len(r.Checks) != 1 {
		t.Fatal("out-of-profile node accepted")
	}
}

func TestDoctorArgumentsAndCLI(t *testing.T) {
	for _, args := range [][]string{nil, {"--link-file", "-", "--target", "echo:1"}, {"--link-file", "private-path", "--target", "echo:65536"}, {"--link-file", "private-path", "--target", "echo:1", "--network", "secret-value"}, {"--timeout", "secret-value"}, {"--secret-flag"}, {"--link-file", "private-path", "--target", "echo:1", "extra"}} {
		var out bytes.Buffer
		err := doctorCommand(context.Background(), args, &out)
		if err == nil || strings.Contains(err.Error()+out.String(), "secret-value") || strings.Contains(err.Error()+out.String(), "private-path") {
			t.Fatal("bad arguments accepted or echoed")
		}
	}
	f := newDoctorFixture(t, "h2-connect", "go", nil)
	target, _ := doctorTCPDestination(t, "echo")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := helperCommand(ctx, "doctor", "--link-file", f.path, "--ca-cert", f.ca, "--target", target)
	cmd.Env = helperEnv(false)
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "PASS tcp_echo: ok") {
		t.Fatalf("doctor CLI failed: %v, %s", err, out)
	}
	cmd = helperCommand(ctx, "doctor", "--link-file", "private-path-marker", "--target", target, "--json")
	cmd.Env = helperEnv(false)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), `"ok":false`) || strings.Contains(string(out), "private-path-marker") {
		t.Fatal("CLI failure did not preserve exit status or redaction")
	}
	cmd = helperCommand(ctx, "doctor", "--help")
	cmd.Env = helperEnv(false)
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "--target") {
		t.Fatal("doctor CLI help failed")
	}
}

func TestDoctorCorrectPin(t *testing.T) {
	f := newDoctorFixture(t, "h2-connect", "go", nil)
	f.config.PinSHA256 = tlsidentity.Pin(f.node.Certificate())
	f.save(t)
	target, _ := doctorTCPDestination(t, "echo")
	if r, err, _ := callDoctor(t, f, target); err != nil || !r.OK {
		t.Fatalf("correct pin rejected: %+v, %v", r, err)
	}
}
