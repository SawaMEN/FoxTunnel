package firefox

import (
	"context"
	"encoding/json"
	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestGeckoPackagedLauncher(t *testing.T) {
	bundle := os.Getenv("FOXTUNNEL_BUNDLE")
	if bundle == "" {
		t.Skip("set FOXTUNNEL_BUNDLE to the packaged launcher/runtime")
	}
	for _, mode := range []string{"h2-connect", "h3-connect"} {
		t.Run(mode, func(t *testing.T) {
			cfg := nativeProxy(t, mode, &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true})
			data, _ := json.Marshal(cfg)
			config := filepath.Join(t.TempDir(), "client.json")
			if e := os.WriteFile(config, data, 0600); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, filepath.Join(bundle, "foxtunnel-necko"), "--bundle", bundle, "--config", config)
			cmd.Dir = t.TempDir()
			stderr := new(lockedBuffer)
			cmd.Stderr = stderr
			stdout, e := cmd.StdoutPipe()
			if e != nil {
				t.Fatal(e)
			}
			if e := cmd.Start(); e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			stopped := false
			t.Cleanup(func() {
				if !stopped {
					cmd.Process.Signal(syscall.SIGTERM)
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						cancel()
						<-done
					}
				}
			})
			var ready operationalStats
			if e := json.NewDecoder(stdout).Decode(&ready); e != nil || ready.Type != "ready" {
				t.Fatalf("packaged helper startup: %v\n%s", e, stderr.text())
			}
			h := &operationalHelper{listen: ready.Listen}
			if e := operationalRound(h, nativeEcho(t), 42); e != nil {
				t.Fatal(e)
			}
			if e := cmd.Process.Signal(syscall.SIGTERM); e != nil {
				t.Fatal(e)
			}
			select {
			case e := <-done:
				stopped = true
				if e != nil {
					t.Fatalf("SIGTERM shutdown: %v %s", e, stderr.text())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("packaged launcher did not stop")
			}
			if c, e := net.DialTimeout("tcp", ready.Listen, time.Second); e == nil {
				c.Close()
				t.Fatal("packaged shutdown left SOCKS listener open")
			}
			if _, e := os.Stat(filepath.Join(os.TempDir(), ready.ProcessTag)); !os.IsNotExist(e) {
				t.Fatal("packaged shutdown left private profile")
			}
		})
	}
}
