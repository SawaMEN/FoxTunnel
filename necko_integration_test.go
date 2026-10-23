package foxtunnel_test

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
	"errors"
	"io"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	ft "github.com/SawaMEN/FoxTunnel"
	"github.com/quic-go/quic-go/http3"
)

func TestIntegratedNecko(t *testing.T) {
	bundle := os.Getenv("FOXTUNNEL_NECKO_BUNDLE")
	if bundle == "" {
		t.Skip("set FOXTUNNEL_NECKO_BUNDLE to a verified bundle with the main CLI")
	}
	for _, mode := range []string{"h2-connect", "h3-connect"} {
		t.Run(mode, func(t *testing.T) {
			handler, err := ft.NewServer(ft.ServerConfig{Credentials: ft.Credentials{Username: "u", Password: "p"}, AllowPrivateDestinations: true})
			if err != nil {
				t.Fatal(err)
			}
			key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if e != nil {
				t.Fatal(e)
			}
			root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Necko integration CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
			caDER, e := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
			if e != nil {
				t.Fatal(e)
			}
			leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
			der, e := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
			if e != nil {
				t.Fatal(e)
			}
			proxy := httptest.NewUnstartedServer(handler)
			proxy.EnableHTTP2 = true
			proxy.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
			proxy.StartTLS()
			defer proxy.Close()
			ca := filepath.Join(t.TempDir(), "ca.pem")
			if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
				t.Fatal(err)
			}
			if mode == "h3-connect" {
				pc, e := net.ListenPacket("udp", proxy.Listener.Addr().String())
				if e != nil {
					t.Fatal(e)
				}
				h3 := &http3.Server{TLSConfig: proxy.TLS.Clone(), Handler: handler}
				done := make(chan struct{})
				go func() { defer close(done); h3.Serve(pc) }()
				defer func() { h3.Close(); pc.Close(); <-done }()
			}
			echo, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer echo.Close()
			go func() {
				for {
					c, e := echo.Accept()
					if e != nil {
						return
					}
					go func() { defer c.Close(); c.SetDeadline(time.Now().Add(10 * time.Second)); io.Copy(c, c) }()
				}
			}()
			t.Run("SDK", func(t *testing.T) {
				c, e := ft.NewClient(ft.ClientConfig{Engine: "necko", NeckoBundle: bundle, ServerURL: proxy.URL, CACertFile: ca, Transport: mode, Credentials: ft.Credentials{Username: "u", Password: "p"}, MaxConnections: 1})
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				conn, e := c.DialContext(ctx, "tcp", echo.Addr().String())
				cancel()
				if e != nil {
					t.Fatal(e)
				}
				if _, e = c.DialContext(context.Background(), "tcp", echo.Addr().String()); !errors.Is(e, ft.ErrCapacity) {
					t.Fatalf("capacity: %v", e)
				}
				integratedNeckoTransfer(t, conn)
				if c.Status().Engine != "necko" {
					t.Fatal("wrong engine status")
				}
				c.Close()
				if !c.Snapshot().Closed {
					t.Fatal("client not closed")
				}
				if _, e = c.DialContext(context.Background(), "tcp", echo.Addr().String()); !errors.Is(e, net.ErrClosed) {
					t.Fatalf("closed client: %v", e)
				}
			})
			t.Run("CLI", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, filepath.Join(bundle, "foxtunnel"), "client", "--engine", "necko", "--necko-bundle", bundle, "--server", proxy.URL, "--ca-cert", ca, "--transport", mode, "--listen", "127.0.0.1:0", "--events-json", "--shutdown-on-stdin-eof")
				cmd.Dir = t.TempDir()
				cmd.Env = append(os.Environ(), "FOXTUNNEL_USER=u", "FOXTUNNEL_PASSWORD=p")
				stdin, e := cmd.StdinPipe()
				if e != nil {
					t.Fatal(e)
				}
				stdout, e := cmd.StdoutPipe()
				if e != nil {
					t.Fatal(e)
				}
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				if e = cmd.Start(); e != nil {
					t.Fatal(e)
				}
				done := make(chan error, 1)
				go func() { done <- cmd.Wait() }()
				stopped := false
				defer func() {
					if !stopped {
						cancel()
						<-done
					}
				}()
				var ready struct {
					Type   string `json:"type"`
					Listen string `json:"tcp_listen"`
				}
				decoder := json.NewDecoder(stdout)
				if e = decoder.Decode(&ready); e != nil || ready.Type != "ready" {
					cancel()
					<-done
					stopped = true
					t.Fatalf("CLI ready: %v: %s", e, stderr.String())
				}
				conn, e := net.DialTimeout("tcp", ready.Listen, time.Second)
				if e != nil {
					t.Fatal(e)
				}
				host, p, _ := net.SplitHostPort(echo.Addr().String())
				port, _ := strconv.Atoi(p)
				ip := net.ParseIP(host).To4()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				conn.Write([]byte{5, 1, 0})
				var greeting [2]byte
				if _, e = io.ReadFull(conn, greeting[:]); e != nil || greeting != [2]byte{5, 0} {
					t.Fatal("CLI SOCKS greeting", e)
				}
				request := append([]byte{5, 1, 0, 1}, ip...)
				request = append(request, byte(port>>8), byte(port))
				conn.Write(request)
				var reply [10]byte
				if _, e = io.ReadFull(conn, reply[:]); e != nil || reply[1] != 0 {
					t.Fatal("CLI SOCKS CONNECT", e, reply)
				}
				integratedNeckoTransfer(t, conn)
				stdin.Close()
				select {
				case e = <-done:
					stopped = true
					if e != nil {
						t.Fatalf("CLI shutdown: %v %s", e, stderr.String())
					}
				case <-time.After(5 * time.Second):
					t.Fatal("CLI failed to join Necko")
				}
				if conn, e := net.DialTimeout("tcp", ready.Listen, 100*time.Millisecond); e == nil {
					conn.Close()
					t.Fatal("CLI listener survived shutdown")
				}
			})
		})
	}
}

func integratedNeckoTransfer(t *testing.T, c net.Conn) {
	t.Helper()
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	data := make([]byte, 128<<10)
	for i := range data {
		data[i] = byte(i)
	}
	done := make(chan error, 1)
	go func() {
		_, e := c.Write(data)
		if e == nil {
			e = c.(interface{ CloseWrite() error }).CloseWrite()
		}
		done <- e
	}()
	got, e := io.ReadAll(c)
	if e != nil || !bytes.Equal(got, data) {
		t.Fatalf("Necko binary half-close: %d bytes, %v", len(got), e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}
