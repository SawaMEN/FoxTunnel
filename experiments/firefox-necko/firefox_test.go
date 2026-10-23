package firefox

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
)

func TestConfigRejectsDroppedTrustAndDuplicateKeys(t *testing.T) {
	for _, extra := range []string{`,"pin_sha256":"secret"`, `,"password":"second"`, `,"Password":"second"`, `,"transport":"h3-post"`, `,"listen":"0.0.0.0:1080"`, `,"listen":"[::1]:1080"`} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(`{"server":"https://example.org","username":"u","password":"p"`+extra+`}`), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadConfig(path); err == nil {
			t.Fatalf("accepted %s", extra)
		}
	}
}

type lockedBuffer struct {
	sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	// A failing native callback can emit logs at socket-loop frequency.
	// Keep the diagnostic tail without letting a failed test exhaust RAM.
	const limit = 64 << 10
	n := len(p)
	if len(p) >= limit {
		b.buffer.Reset()
		p = p[len(p)-limit:]
	} else if excess := b.buffer.Len() + len(p) - limit; excess > 0 {
		b.buffer.Next(excess)
	}
	_, err := b.buffer.Write(p)
	return n, err
}
func (b *lockedBuffer) text() string { b.Lock(); defer b.Unlock(); return b.buffer.String() }

// This is an actual Necko -> independent Go H2/H3 server -> TCP destination
// test, not a mock of the native runtime. Ordinary tests skip it unless a
// matching xpcshell + libxul runtime was explicitly supplied.
func TestGeckoCONNECT(t *testing.T) {
	testGeckoCONNECT(t, true)
}

// Separate the native handoff gate from directional EOF support. Both gates
// are required before this experiment may become a supported transport.
func TestGeckoCONNECTHandoff(t *testing.T) {
	testGeckoCONNECT(t, false)
}

func testGeckoCONNECT(t *testing.T, halfClose bool) {
	t.Helper()
	runtime := os.Getenv("FOXTUNNEL_XPCSHELL")
	if runtime == "" {
		t.Skip("set FOXTUNNEL_XPCSHELL to a real Gecko runtime")
	}
	for _, mode := range []string{"h2-connect", "h3-connect"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				for {
					c, err := echo.Accept()
					if err != nil {
						return
					}
					go func() {
						defer c.Close()
						if halfClose {
							data, _ := io.ReadAll(c)
							_, _ = c.Write(data)
						} else {
							_, _ = io.Copy(c, c)
						}
					}()
				}
			}()
			server := &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true}
			var mu sync.Mutex
			var seen []int
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "CONNECT" {
					mu.Lock()
					seen = append(seen, r.ProtoMajor)
					mu.Unlock()
					if r.Host != echo.Addr().String() || r.URL.Path != "" || r.Header.Get("X-FoxTunnel-Target") != "" {
						t.Error("not an authority-form CONNECT", r.Method, r.Host, r.URL.Path)
					}
				}
				server.ServeHTTP(w, r)
			})
			tcp := httptest.NewUnstartedServer(handler)
			tcp.EnableHTTP2 = true
			certificate, ca := testCertificate(t)
			tcp.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
			tcp.StartTLS()
			t.Cleanup(tcp.Close)
			if mode == "h3-connect" {
				udp, err := net.ListenPacket("udp", tcp.Listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer udp.Close()
				// Use the same observed handler for the independent HTTP/3 endpoint.
				go func() { _ = serveTestH3(ctx, udp, tcp.TLS, handler) }()
			}
			caPath := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca}), 0600); err != nil {
				t.Fatal(err)
			}
			listen, stderr := startTestHelper(t, runtime, Config{Server: tcp.URL, Username: "u", Password: "p", Transport: mode, Listen: "127.0.0.1:0", CACert: caPath})
			for round := 0; round < 2; round++ {
				conn, err := net.DialTimeout("tcp", listen, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = conn.Write([]byte{5, 1, 0})
				var greeting [2]byte
				if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
					conn.Close()
					t.Fatal("greeting", greeting, err)
				}
				port := echo.Addr().(*net.TCPAddr).Port
				_, _ = conn.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
				var reply [10]byte
				if _, err := io.ReadFull(conn, reply[:]); err != nil || reply[1] != 0 {
					conn.Close()
					t.Fatalf("CONNECT %v: %v\n%s", reply, err, stderr.text())
				}
				payload := bytes.Repeat([]byte{0, 255, 1, 13, 10, byte(round)}, 20000)
				if _, err := conn.Write(payload); err != nil {
					conn.Close()
					t.Fatal(err)
				}
				var data []byte
				if halfClose {
					if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
						conn.Close()
						t.Fatal(err)
					}
					data, err = io.ReadAll(io.LimitReader(conn, int64(len(payload)+1)))
				} else {
					data = make([]byte, len(payload))
					var n int
					n, err = io.ReadFull(conn, data)
					data = data[:n]
				}
				conn.Close()
				if err != nil || !bytes.Equal(data, payload) {
					t.Fatalf("binary payload (half-close=%v): received %d of %d: %v\n%s", halfClose, len(data), len(payload), err, stderr.text())
				}
			}
			mu.Lock()
			defer mu.Unlock()
			want := 2
			if mode == "h3-connect" {
				want = 3
			}
			if len(seen) != 2 || seen[0] != want || seen[1] != want {
				t.Fatal("negotiated protocol", seen)
			}
		})
	}
}

func startTestHelper(t *testing.T, runtime string, cfg Config) (string, *lockedBuffer) {
	t.Helper()
	listen, stderr, _ := startTestHelperContext(t, context.Background(), runtime, cfg)
	return listen, stderr
}

func startTestHelperContext(t *testing.T, parent context.Context, runtime string, cfg Config) (string, *lockedBuffer, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	read, write := io.Pipe()
	stderr := new(lockedBuffer)
	finished := make(chan struct{})
	go func() {
		err := Run(ctx, runtime, cfg, write, stderr)
		if err != nil && ctx.Err() == nil {
			_, _ = stderr.Write([]byte("\nhelper exit: " + err.Error() + "\n"))
		}
		write.CloseWithError(err)
		close(finished)
	}()
	t.Cleanup(func() { cancel(); read.Close(); <-finished })
	var ready struct {
		Type   string `json:"type"`
		Listen string `json:"listen"`
	}
	if err := json.NewDecoder(read).Decode(&ready); err != nil {
		t.Fatalf("helper startup: %v\n%s", err, stderr.text())
	}
	if ready.Type != "ready" || !strings.HasPrefix(ready.Listen, "127.0.0.1:") {
		t.Fatal("invalid readiness", ready)
	}
	go io.Copy(stderr, read)
	return ready.Listen, stderr, finished
}

func TestGeckoTrustBeforeCredentials(t *testing.T) {
	runtime := os.Getenv("FOXTUNNEL_XPCSHELL")
	if runtime == "" {
		t.Skip("set FOXTUNNEL_XPCSHELL to a real Gecko runtime")
	}
	for _, mode := range []string{"h2-connect", "h3-connect"} {
		for _, fault := range []string{"untrusted-root", "wrong-hostname"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				certificate, ca := testCertificate(t)
				if fault == "wrong-hostname" {
					certificate, ca = testCertificate(t, "other.invalid")
				} else {
					_, ca = testCertificate(t)
				}
				var requests atomic.Int32
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					http.Error(w, "trust check failed", http.StatusForbidden)
				})
				server := httptest.NewUnstartedServer(handler)
				server.EnableHTTP2 = true
				server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
				server.StartTLS()
				t.Cleanup(server.Close)
				if mode == "h3-connect" {
					udp, err := net.ListenPacket("udp", server.Listener.Addr().String())
					if err != nil {
						t.Fatal(err)
					}
					defer udp.Close()
					go func() { _ = serveTestH3(ctx, udp, server.TLS, handler) }()
				}
				caPath := filepath.Join(t.TempDir(), "ca.pem")
				if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca}), 0600); err != nil {
					t.Fatal(err)
				}
				listen, stderr := startTestHelper(t, runtime, Config{Server: server.URL, Username: "never-send", Password: "before-trust", Transport: mode, Listen: "127.0.0.1:0", CACert: caPath, ConnectTimeoutMS: 3000, MaxConnections: 1})
				// A timed-out CONNECT must release its session slot. Repeat on
				// the same helper with a one-session limit to detect leaked setup.
				for round := 0; round < 2; round++ {
					conn, err := net.DialTimeout("tcp", listen, time.Second)
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					_, _ = conn.Write([]byte{5, 1, 0})
					var greeting [2]byte
					if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
						t.Fatal("SOCKS greeting", greeting, err)
					}
					_, _ = conn.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 1, 187})
					var reply [10]byte
					n, err := io.ReadFull(conn, reply[:])
					// A setup timeout may close the socket without a SOCKS reply;
					// it must never report success or send HTTP credentials first.
					closed := n == 0 && err == io.EOF
					if !closed && (err != nil || reply[0] != 5 || reply[1] == 0) {
						t.Fatalf("trust failure must reject CONNECT: %v: %v\n%s", reply, err, stderr.text())
					}
					if requests.Load() != 0 {
						t.Fatalf("sent %d HTTP requests before proxy trust succeeded", requests.Load())
					}
				}
			})
		}
	}
}

func testCertificate(t *testing.T, dnsName ...string) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "FoxTunnel test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	ca, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	if len(dnsName) != 0 {
		leaf.IPAddresses = nil
		leaf.DNSNames = dnsName
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, ca
}
