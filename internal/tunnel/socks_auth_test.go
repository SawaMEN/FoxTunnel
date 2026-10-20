package tunnel

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestLocalSOCKSAuthCannotDowngrade(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() {
		_, _, err := socks5RequestAuth(server, "local-user", "local-password")
		done <- err
	}()
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(client, response); err != nil || !bytes.Equal(response, []byte{5, 0xff}) {
		t.Fatalf("unprotected SOCKS method accepted: %v %v", response, err)
	}
	if err := <-done; err == nil {
		t.Fatal("expected failure after missing RFC1929")
	}
}

func TestLocalSOCKSAuthValidTCPAndUDP(t *testing.T) {
	for _, command := range []byte{1, 3} {
		server, client := net.Pipe()
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		type result struct {
			command byte
			target  string
			err     error
		}
		done := make(chan result, 1)
		go func() {
			cmd, target, err := socks5RequestAuth(server, "user", "pass")
			done <- result{cmd, target, err}
		}()
		if _, err := client.Write([]byte{5, 2, 0, 2}); err != nil {
			t.Fatal(err)
		}
		var method [2]byte
		if _, err := io.ReadFull(client, method[:]); err != nil || !bytes.Equal(method[:], []byte{5, 2}) {
			t.Fatalf("auth method wrong: %v %v", method, err)
		}
		if _, err := client.Write([]byte{1, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'}); err != nil {
			t.Fatal(err)
		}
		var accepted [2]byte
		if _, err := io.ReadFull(client, accepted[:]); err != nil || !bytes.Equal(accepted[:], []byte{1, 0}) {
			t.Fatalf("credential rejection: %v %v", accepted, err)
		}
		if _, err := client.Write([]byte{5, command, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
			t.Fatal(err)
		}
		got := <-done
		if got.err != nil || got.command != command || got.target != "127.0.0.1:80" {
			t.Fatalf("authenticated SOCKS command %d failed: %+v", command, got)
		}
		client.Close()
		server.Close()
	}
}

func TestLocalSOCKSAuthRejectsWrongPassword(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() {
		_, _, err := socks5RequestAuth(server, "user", "good")
		done <- err
	}()
	_, _ = client.Write([]byte{5, 1, 2})
	var method [2]byte
	if _, err := io.ReadFull(client, method[:]); err != nil || method != [2]byte{5, 2} {
		t.Fatal("SOCKS auth was not selected", err, method)
	}
	_, _ = client.Write([]byte{1, 4, 'u', 's', 'e', 'r', 3, 'b', 'a', 'd'})
	var result [2]byte
	if _, err := io.ReadFull(client, result[:]); err != nil || result != [2]byte{1, 1} {
		t.Fatal("wrong password accepted", err, result)
	}
	if err := <-done; err == nil || strings.Contains(err.Error(), "good") {
		t.Fatal("credential error disclosed password or succeeded", err)
	}
}

func TestLocalSOCKSCredentialConfiguration(t *testing.T) {
	for _, tc := range []struct {
		user, pass string
		good       bool
	}{
		{"", "", true}, {"alice", "strong-pass", true},
		{"", "pass", false}, {"alice", "", false},
		{strings.Repeat("u", 256), "pass", false},
		{"user", strings.Repeat("p", 256), false},
		{"new\nline", "password", false},
	} {
		c := &Client{SOCKSUsername: tc.user, SOCKSPassword: tc.pass}
		if (c.ValidateSOCKSAuth() == nil) != tc.good {
			t.Fatalf("unexpected credential validation for %q", tc.user)
		}
	}
}
