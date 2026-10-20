//go:build unix

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"testing"
	"time"
)

func TestProcessSIGTERMAndCertificateSIGHUP(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(operationPair(t, cert, key, 1))
	// Reserve the test address before starting; only loopback is used.
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := reserved.Addr().String()
	reserved.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server := helperCommand(ctx, "server", "--listen", addr, "--cert", cert, "--key", key)
	server.Env = helperEnv(true)
	stderr, err := server.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { server.Process.Kill(); server.Wait() }()
	lines := make(chan string, 32)
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			default:
			}
		}
	}()
	readSerial := func() (int64, error) {
		c, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, &tls.Config{RootCAs: roots})
		if e != nil {
			return 0, e
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0].SerialNumber.Int64(), nil
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		serial, e := readSerial()
		if e == nil && serial == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server unavailable: %v", e)
		}
		time.Sleep(20 * time.Millisecond)
	}
	roots.AppendCertsFromPEM(operationPair(t, cert, key, 2))
	if err := server.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		serial, e := readSerial()
		if e == nil && serial == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("SIGHUP did not renew TLS: %v", e)
		}
		time.Sleep(10 * time.Millisecond)
	}
	os.WriteFile(key, []byte("PRIVATE-KEY-DO-NOT-LOG"), 0600)
	server.Process.Signal(syscall.SIGHUP)
	deadline = time.Now().Add(time.Second)
	rejected := false
	for !rejected && time.Now().Before(deadline) {
		select {
		case line := <-lines:
			if regexp.MustCompile("PRIVATE-KEY-DO-NOT-LOG").MatchString(line) {
				t.Fatal("key content in log")
			}
			rejected = regexp.MustCompile("TLS certificate reload rejected").MatchString(line)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !rejected {
		t.Fatal("bad renewal not rejected")
	}
	if serial, err := readSerial(); err != nil || serial != 2 {
		t.Fatalf("last valid certificate lost: %d %v", serial, err)
	}
	if err := server.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := server.Wait(); err != nil {
		t.Fatalf("SIGTERM was not a clean exit: %v", err)
	}
}

func TestClientSIGTERMClosesIncompleteSOCKS(t *testing.T) {
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := reserved.Addr().String()
	reserved.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := helperCommand(ctx, "client", "--server", "https://127.0.0.1:8443", "--listen", addr, "--tls-backend", "go")
	client.Env = helperEnv(true)
	client.Stderr = os.Stderr
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { client.Process.Kill(); client.Wait() }()
	var pending net.Conn
	deadline := time.Now().Add(3 * time.Second)
	for {
		pending, err = net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer pending.Close()
	pending.SetDeadline(time.Now().Add(2 * time.Second))
	pending.Write([]byte{5})
	if err := client.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := client.Wait(); err != nil {
		t.Fatalf("client SIGTERM was not clean: %v", err)
	}
	var b [1]byte
	if _, err := pending.Read(b[:]); err == nil {
		t.Fatal("incomplete SOCKS connection survived client exit")
	}
}
