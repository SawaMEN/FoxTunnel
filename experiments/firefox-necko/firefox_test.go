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
	return b.buffer.Write(p)
}
func (b *lockedBuffer) text() string { b.Lock(); defer b.Unlock(); return b.buffer.String() }

// This is an actual Necko -> independent Go H2/H3 server -> TCP destination
// test, not a mock of the native runtime. Ordinary tests skip it unless a
// matching xpcshell + libxul runtime was explicitly supplied.
func TestGeckoCONNECT(t *testing.T) {
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
					go func() { defer c.Close(); data, _ := io.ReadAll(c); _, _ = c.Write(data) }()
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
			defer tcp.Close()
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
			read, write := io.Pipe()
			defer read.Close()
			var stderr lockedBuffer
			finished := make(chan error, 1)
			go func() {
				err := Run(ctx, runtime, Config{Server: tcp.URL, Username: "u", Password: "p", Transport: mode, Listen: "127.0.0.1:0", CACert: caPath}, write, &stderr)
				write.CloseWithError(err)
				finished <- err
			}()
			defer func() { cancel(); read.Close(); <-finished }()
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
			go io.Copy(&stderr, read)
			for round := 0; round < 2; round++ {
				conn, err := net.DialTimeout("tcp", ready.Listen, time.Second)
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
				conn.(*net.TCPConn).CloseWrite()
				data, err := io.ReadAll(conn)
				conn.Close()
				if err != nil || !bytes.Equal(data, payload) {
					t.Fatal("half-close/binary payload", len(data), err)
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

func testCertificate(t *testing.T) (tls.Certificate, []byte) {
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
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, ca
}
