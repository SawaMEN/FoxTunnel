package bootstrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/SawaMEN/FoxTunnel/internal/cluster"
)

func TestAuditSetupAdvertisedPort(t *testing.T) {
	for _, transport := range []string{"h2-connect", "h3-post"} {
		t.Run(transport, func(t *testing.T) {
			o := fixture(t, "main.example")
			o.Server += ":8443"
			o.Transport = transport
			if err := Generate(o); err != nil {
				t.Fatal(err)
			}
			c, err := ReadServer(filepath.Join(o.Output, "server.json"))
			if err != nil {
				t.Fatal(err)
			}
			if c.Listen != ":8443" || (transport == "h3-post" && c.H3Listen != ":8443") {
				t.Fatalf("advertised 8443, listens TCP=%q H3=%q", c.Listen, c.H3Listen)
			}
		})
	}
}

func TestAuditJoinRejectsPublicSecretFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode check")
	}
	main := fixture(t, "main.example")
	if err := Generate(main); err != nil {
		t.Fatal(err)
	}
	join := fixture(t, "relay.example")
	join.JoinLinkFile = filepath.Join(main.Output, "connection.txt")
	if err := os.Chmod(join.JoinLinkFile, 0644); err != nil {
		t.Fatal(err)
	}
	if err := Generate(join); err == nil {
		t.Fatal("join accepted world-readable credentials")
	}
}

func TestAuditJoinCannotPublishOriginalSecret(t *testing.T) {
	main := fixture(t, "main.example")
	if err := Generate(main); err != nil {
		t.Fatal(err)
	}
	join := fixture(t, "relay.example")
	join.WebRoot = t.TempDir()
	join.JoinLinkFile = filepath.Join(join.WebRoot, "access-link.txt")
	data, err := os.ReadFile(filepath.Join(main.Output, "connection.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(join.JoinLinkFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Generate(join); err == nil {
		t.Fatal("join published its original credential file in the cover root")
	}
}

func TestAuditSetupRejectsNonDirectorySite(t *testing.T) {
	o := fixture(t, "main.example")
	o.WebRoot = filepath.Join(t.TempDir(), "site.html")
	if err := os.WriteFile(o.WebRoot, []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Generate(o); err == nil {
		t.Fatal("generated a server whose website root is not a directory")
	}
}

func TestAuditAddNodeReplacesEquivalentOrigin(t *testing.T) {
	o := fixture(t, "main.example")
	if err := Generate(o); err != nil {
		t.Fatal(err)
	}
	node := cluster.Node{URL: "https://MAIN.example:0443/", Weight: 9}
	data, _ := json.Marshal(node)
	path := filepath.Join(t.TempDir(), "node.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := AddNode(filepath.Join(o.Output, "server.json"), path); err != nil {
		t.Fatal("equivalent origin must replace existing node:", err)
	}
	f, err := os.Open(filepath.Join(o.Output, "cluster.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := cluster.DecodeConfig(f)
	if err != nil || len(c.Nodes) != 1 || c.Nodes[0].Weight != 9 {
		t.Fatal("alias created duplicate or lost node update", c, err)
	}
}
