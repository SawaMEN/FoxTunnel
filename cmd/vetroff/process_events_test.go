package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestProcessEventsAndEOFShutdown(t *testing.T) {
	for _, role := range []string{"client", "server"} {
		t.Run(role, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			args := []string{role, "--listen", "127.0.0.1:0", "--events-json", "--shutdown-on-stdin-eof"}
			if role == "client" {
				args = append(args, "--server", "https://localhost:9", "--tls-backend", "go")
			} else {
				dir := t.TempDir()
				cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
				operationPair(t, cert, key, 101)
				args = append(args, "--cert", cert, "--key", key, "--h3-listen", "127.0.0.1:0")
			}
			cmd := helperCommand(ctx, args...)
			cmd.Env = helperEnv(true)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cmd.Process.Kill(); cmd.Wait() }()
			decode := json.NewDecoder(stdout)
			var ready processEvent
			if err := decode.Decode(&ready); err != nil {
				t.Fatal(err)
			}
			if ready.Schema != 1 || ready.Sequence != 1 || ready.Type != "ready" || ready.Role != role || ready.TCPListen == "" {
				t.Fatal("invalid ready", ready)
			}
			if role == "server" && ready.UDPListen == "" {
				t.Fatal("missing bound H3 socket")
			}
			conn, err := net.DialTimeout("tcp", ready.TCPListen, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			stdin.Close()
			var stopped processEvent
			if err := decode.Decode(&stopped); err != nil {
				t.Fatal(err)
			}
			if stopped.Sequence != 2 || stopped.Type != "stopped" || stopped.Role != role || stopped.Outcome != "shutdown" {
				t.Fatal("invalid stopped", stopped)
			}
			var extra any
			if err := decode.Decode(&extra); err != io.EOF {
				t.Fatal("stdout was not exactly two JSON records", err)
			}
			if err := cmd.Wait(); err != nil {
				t.Fatal(err)
			}
			// No log scraping or ephemeral-port reservation race is needed by a host.
			rebound, err := net.Listen("tcp", ready.TCPListen)
			if err != nil {
				t.Fatal("listener leaked", err)
			}
			rebound.Close()
		})
	}
}

func TestProcessNeverReportsReadyAfterInvalidConfiguration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := helperCommand(ctx, "client", "--server", "https://localhost:9", "--events-json", "--shutdown-on-stdin-eof", "--link-file", "-")
	cmd.Env = helperEnv(true)
	if out, err := cmd.Output(); err == nil || len(out) != 0 {
		t.Fatal("failed configuration emitted readiness", err, string(out))
	}
}
