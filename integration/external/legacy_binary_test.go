package consumer_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	ft "github.com/SawaMEN/FoxTunnel"
)

// The dedicated compatibility workflow builds the pre-negotiation revision.
// Ordinary SDK tests do not assume a legacy executable is installed.
func TestWireLegacyBinaryCompatibility(t *testing.T) {
	legacy := os.Getenv("FOXTUNNEL_LEGACY_BINARY")
	if legacy == "" {
		t.Skip("run the wire-compatibility workflow for actual legacy builds")
	}
	credentials := ft.Credentials{Username: "alice", Password: "secret"}
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	checkEcho := func(t *testing.T, conn net.Conn) {
		t.Helper()
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("wire")); err != nil {
			t.Fatal(err)
		}
		var reply [4]byte
		if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "wire" {
			t.Fatal("cross-version echo", err, string(reply[:]))
		}
	}
	unusedAddress := func(t *testing.T) string {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		listener.Close()
		return address
	}
	start := func(t *testing.T, address string, args ...string) {
		t.Helper()
		command := exec.Command(legacy, args...)
		command.Env = append(os.Environ(), "FOXTUNNEL_USER=alice", "FOXTUNNEL_PASSWORD=secret")
		command.Stdout, command.Stderr = io.Discard, os.Stderr
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = command.Process.Kill()
			_ = command.Wait()
		})
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
			if err == nil {
				conn.Close()
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("legacy process did not open listener", address)
	}
	for _, strictServer := range []bool{false, true} {
		label := "legacy-compatible-server"
		if strictServer {
			label = "strict-server"
		}
		t.Run(label, func(t *testing.T) {
			handler, err := ft.NewServer(ft.ServerConfig{Credentials: credentials, AllowPrivateDestinations: true, RequireProtocolNegotiation: strictServer})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(handler)
			server.EnableHTTP2 = true
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
			server.StartTLS()
			defer server.Close()
			directory := t.TempDir()
			ca := filepath.Join(directory, "cert.pem")
			if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			clientAddress := unusedAddress(t)
			start(t, clientAddress, "client", "--listen", clientAddress, "--server", server.URL, "--ca-cert", ca, "--tls-backend", "go")
			conn, err := net.DialTimeout("tcp", clientAddress, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err = conn.Write([]byte{5, 1, 0}); err != nil {
				t.Fatal(err)
			}
			var greeting [2]byte
			if _, err = io.ReadFull(conn, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
				t.Fatal("legacy SOCKS greeting", err, greeting)
			}
			port := target.Addr().(*net.TCPAddr).Port
			request := binary.BigEndian.AppendUint16([]byte{5, 1, 0, 1, 127, 0, 0, 1}, uint16(port))
			if _, err = conn.Write(request); err != nil {
				t.Fatal(err)
			}
			var response [10]byte
			if _, err = io.ReadFull(conn, response[:]); err != nil || response[0] != 5 {
				t.Fatal("legacy SOCKS reply", err, response)
			}
			if strictServer {
				if response[1] == 0 {
					t.Fatal("legacy binary bypassed strict server policy")
				}
				return
			}
			if response[1] != 0 {
				t.Fatal("legacy binary could not use compatible new server", response)
			}
			checkEcho(t, conn)

			// Reuse the local certificate to run the actual old server process.
			keyDER, err := x509.MarshalPKCS8PrivateKey(server.TLS.Certificates[0].PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(directory, "key.pem")
			if err = os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
				t.Fatal(err)
			}
			serverAddress := unusedAddress(t)
			start(t, serverAddress, "server", "--listen", serverAddress, "--cert", ca, "--key", key, "--allow-private")
			for _, strictClient := range []bool{false, true} {
				client, err := ft.NewClient(ft.ClientConfig{ServerURL: "https://" + serverAddress, Credentials: credentials, CACertFile: ca, TLSBackend: "go", RequireProtocolNegotiation: strictClient})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				stream, err := client.DialContext(ctx, "tcp", target.Addr().String())
				cancel()
				if strictClient {
					if stream != nil {
						stream.Close()
					}
					if !errors.Is(err, ft.ErrProtocolNegotiation) {
						t.Fatal("strict client did not reject actual old server", err)
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					checkEcho(t, stream)
				}
				client.Close()
			}
		})
	}
}
