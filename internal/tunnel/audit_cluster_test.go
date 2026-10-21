package tunnel

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditSmartBondRecognizesCoordinatorAliases(t *testing.T) {
	for _, pair := range [][2]string{{"https://hub.example", "https://HUB.example:0443"}, {"https://[2001:db8::1]", "https://[2001:0db8:0:0:0:0:0:1]:443"}} {
		a, _ := url.Parse(pair[0])
		b, _ := url.Parse(pair[1])
		if !sameBondOrigin(a, b) {
			t.Errorf("same coordinator classified as a relay: %q / %q", pair[0], pair[1])
		}
	}
}

func TestAuditPinnedClientRejectsDynamicDiscoveryBeforeIO(t *testing.T) {
	c, err := NewClient("https://node.example", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	file := filepath.Join(t.TempDir(), "pins.json")
	pin := "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	data := []byte(`{"v":1,"nodes":[{"url":"https://node.example","pin_sha256":"` + pin + `"}]}`)
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.SetNodePinsFile(file); err != nil {
		t.Fatal(err)
	}
	transport := &auditTransport{}
	pool := c.transport.(*identityPool)
	pool.entries["https://node.example||"+pin] = identityEntry{transport: transport, touched: time.Now()}
	if err := c.EnableBondDiscovery(context.Background()); err == nil {
		t.Fatal("incompatible trust modes combined")
	}
	if transport.called {
		t.Fatal("dynamic discovery started despite immutable per-node pins")
	}
}
