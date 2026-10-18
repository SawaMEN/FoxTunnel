package main

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/profile"
)

func TestShareSingleCoordinator(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := helperCommand(ctx, "share", "--server", "https://main.example", "--bond", "--discover")
	cmd.Env = helperEnv(true)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	config, err := profile.Decode(strings.TrimSpace(string(out)))
	if err != nil || !config.Discover || !config.Bond || len(config.Servers) != 1 || config.Servers[0] != "https://main.example" {
		t.Fatal("coordinator settings missing from link", err)
	}
}

// main contains exit paths; exercise it in an isolated copy of the test binary.
func TestCLIHelper(t *testing.T) {
	if os.Getenv("FOXTUNNEL_TEST_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"foxtunnel"}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	os.Exit(2)
}
func helperEnv(credentials bool) []string {
	var env []string
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "FOXTUNNEL_USER=") || strings.HasPrefix(value, "FOXTUNNEL_PASSWORD=") || strings.HasPrefix(value, "FOXTUNNEL_TEST_HELPER=") {
			continue
		}
		env = append(env, value)
	}
	env = append(env, "FOXTUNNEL_TEST_HELPER=1")
	if credentials {
		env = append(env, "FOXTUNNEL_USER=demo-user", "FOXTUNNEL_PASSWORD=example-only-password")
	}
	return env
}
func helperCommand(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestCLIHelper$", "--"}, args...)...)
}
func TestShareAndImportFromStdin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	share := helperCommand(ctx, "share", "--server", "https://a.example", "--fallback-server", "https://b.example", "--bond", "--bond-pipeline", "8")
	share.Env = helperEnv(true)
	output, err := share.Output()
	if err != nil {
		t.Fatal("share failed", err)
	}
	link := strings.TrimSpace(string(output))
	if !strings.HasPrefix(link, "vetroff://") {
		t.Fatal("wrong connection scheme")
	}
	client := helperCommand(ctx, "client", "--link-file", "-", "--listen", "127.0.0.1:0")
	client.Env = helperEnv(false)
	client.Stdin = strings.NewReader(link + "\n")
	stderr, err := client.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { client.Process.Kill(); client.Wait() }()
	line, err := bufio.NewReader(stderr).ReadString('\n')
	if err != nil || !strings.Contains(line, "SOCKS5") || strings.Contains(line, "vetroff://") || strings.Contains(line, "example-only-password") {
		t.Fatal("stdin import did not start a redacted listener", err)
	}
	conflict := helperCommand(ctx, "client", "--link", link, "--server", "https://other.example")
	conflict.Env = helperEnv(false)
	rejected, err := conflict.CombinedOutput()
	if err == nil || strings.Contains(string(rejected), link) || strings.Contains(string(rejected), "example-only-password") {
		t.Fatal("conflicting settings accepted or link disclosed")
	}
}
