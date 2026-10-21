// Package processhost supervises a FoxTunnel client without linking the tunnel
// engine or NSS into the host. The caller supplies a trusted executable bundle.
package processhost

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/contract"
)

var ErrContract = errors.New("incompatible FoxTunnel process contract")
var ErrStart = errors.New("FoxTunnel process did not become ready")
var ErrRuntime = errors.New("FoxTunnel process failed")

type ClientOptions struct {
	Executable string // Absolute path to a verified complete bundle.
	LinkFile   string // Private regular connection file; never a link in argv.
	CACertFile string
}

type event struct {
	Schema    int    `json:"schema"`
	Sequence  int    `json:"sequence"`
	Type      string `json:"type"`
	Role      string `json:"role"`
	TCPListen string `json:"tcp_listen"`
	Outcome   string `json:"outcome"`
}

// Client owns exactly one child, stdin pipe and reader. Address is a bound local
// SOCKS listener, not evidence that remote TLS/authentication has succeeded.
type Client struct {
	Address  string
	done     chan struct{}
	err      error // published before done closes
	shutdown func()
}

func (c *Client) Done() <-chan struct{} { return c.done }
func (c *Client) Wait() error           { <-c.done; return c.err }

// Close requests EOF shutdown, waits up to five seconds, then kills and reaps
// a stuck child. Canceling the StartClient context has the same lifetime scope.
func (c *Client) Close() error { c.shutdown(); return c.Wait() }

type boundedOutput struct{ data []byte }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > 8192 {
		return 0, io.ErrShortWrite
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func cleanEnv() []string {
	var env []string
	for _, v := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(v), "FOXTUNNEL_") {
			env = append(env, v)
		}
	}
	return env
}

func StartClient(ctx context.Context, options ClientOptions) (*Client, error) {
	if !filepath.IsAbs(options.Executable) || !filepath.IsAbs(options.LinkFile) {
		return nil, ErrStart
	}
	if info, err := os.Stat(options.LinkFile); err != nil || !info.Mode().IsRegular() {
		return nil, ErrStart
	}
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	version := exec.CommandContext(checkCtx, options.Executable, "version", "--json")
	version.Env = cleanEnv()
	// A descendant can inherit stdout after version itself has exited. Bound
	// pipe draining independently from CommandContext's direct-child kill.
	version.WaitDelay = time.Second
	var output boundedOutput
	version.Stdout = &output
	if err := version.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrContract
	}
	var info struct {
		Schema      int    `json:"schema"`
		Product     string `json:"product"`
		Integration int    `json:"integration_schema"`
		SDK         int    `json:"sdk_schema"`
		Process     int    `json:"process_schema"`
		Draft       string `json:"protocol_draft"`
	}
	if json.Unmarshal(output.data, &info) != nil || info.Schema != 1 || info.Product != "protocol-core" || info.Integration != 1 || info.SDK != contract.SDKSchema || info.Process != contract.ProcessSchema || info.Draft != contract.ProtocolDraft {
		return nil, ErrContract
	}
	args := []string{"client", "--link-file", options.LinkFile, "--listen", "127.0.0.1:0", "--events-json", "--shutdown-on-stdin-eof"}
	if options.CACertFile != "" {
		args = append(args, "--ca-cert", options.CACertFile)
	}
	cmd := exec.Command(options.Executable, args...)
	cmd.Env = cleanEnv()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, ErrStart
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, ErrStart
	}
	if err = cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return nil, ErrStart
	}
	c := &Client{done: make(chan struct{})}
	var once sync.Once
	c.shutdown = func() {
		once.Do(func() {
			stdin.Close()
			go func() {
				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()
				select {
				case <-c.done:
				case <-timer.C:
					cmd.Process.Kill()
					// The direct child may leave an inherited stdout pipe in
					// another process. Unblock the scanner before reaping.
					stdout.Close()
				}
			}()
		})
	}
	stop := context.AfterFunc(ctx, c.shutdown)
	ready := make(chan event, 1)
	go func() {
		defer close(c.done)
		defer stop()
		defer stdin.Close()
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1024), 4096)
		read := func(sequence int, kind string) (event, bool) {
			var e event
			if !scanner.Scan() || json.Unmarshal(scanner.Bytes(), &e) != nil {
				return e, false
			}
			return e, e.Schema == contract.ProcessSchema && e.Sequence == sequence && e.Type == kind && e.Role == "client"
		}
		e, ok := read(1, "ready")
		if ok {
			host, port, err := net.SplitHostPort(e.TCPListen)
			ip := net.ParseIP(host)
			number, portErr := strconv.Atoi(port)
			ok = err == nil && ip != nil && ip.IsLoopback() && portErr == nil && number > 0 && number <= 65535
		}
		if ok {
			ready <- e
			e, ok = read(2, "stopped")
			ok = ok && e.Outcome == "shutdown"
		}
		if ok {
			ok = !scanner.Scan() && scanner.Err() == nil
		}
		if !ok {
			c.err = ErrContract
			c.shutdown()
		}
		if err := cmd.Wait(); err != nil && c.err == nil {
			c.err = ErrRuntime
		}
	}()
	startup, finishStartup := context.WithTimeout(ctx, 10*time.Second)
	defer finishStartup()
	select {
	case e := <-ready:
		if ctx.Err() != nil {
			c.Close()
			return nil, ctx.Err()
		}
		c.Address = e.TCPListen
		return c, nil
	case <-c.done:
		return nil, ErrStart
	case <-startup.Done():
		c.Close()
		return nil, startup.Err()
	}
}
