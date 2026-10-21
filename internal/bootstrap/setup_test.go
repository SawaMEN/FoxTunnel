package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/cluster"
	"github.com/SawaMEN/FoxTunnel/internal/profile"
)

func fixture(t *testing.T, name string) Options {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600) != nil || os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600) != nil {
		t.Fatal("fixture write")
	}
	return Options{Server: "https://" + name, Certificate: certPath, PrivateKey: keyPath, CACertFile: certPath, Output: filepath.Join(dir, "generated")}
}

func TestSetupAndJoinProduceUsablePrivateProfiles(t *testing.T) {
	main := fixture(t, "main.example")
	if err := Generate(main); err != nil {
		t.Fatal(err)
	}
	serverPath := filepath.Join(main.Output, "server.json")
	server, err := ReadServer(serverPath)
	if err != nil || !server.BondHub || server.BondUpstream != "" || server.MaxConnections != 512 {
		t.Fatal("main config", err)
	}
	secret, err := base64.RawURLEncoding.DecodeString(server.Password)
	if err != nil || len(secret) != 32 {
		t.Fatal("weak generated secret")
	}
	for _, name := range []string{"server.json", "connection.txt", "cluster.json", "node.json"} {
		stat, err := os.Stat(filepath.Join(main.Output, name))
		if err != nil || stat.Mode().Perm()&0077 != 0 {
			t.Fatal("configuration readable by other users", name)
		}
	}
	f, err := os.Open(filepath.Join(main.Output, "connection.txt"))
	if err != nil {
		t.Fatal(err)
	}
	link, err := profile.Read(f)
	f.Close()
	if err != nil || link.SNI != "main.example" || link.PinSHA256 == "" || link.Encryption != "tls13" || link.Password != server.Password || !link.Discover {
		t.Fatal("incomplete generated link", err)
	}
	if err := Generate(main); err == nil {
		t.Fatal("existing secrets overwritten")
	}
	unchanged, _ := ReadServer(serverPath)
	if unchanged.Password != server.Password {
		t.Fatal("failed setup changed secret")
	}
	node := fixture(t, "node.example")
	node.JoinLinkFile = filepath.Join(main.Output, "connection.txt")
	if err := Generate(node); err != nil {
		t.Fatal(err)
	}
	joined, err := ReadServer(filepath.Join(node.Output, "server.json"))
	if err != nil || joined.BondHub || joined.Password != server.Password || joined.BondUpstream != "https://main.example" || joined.BondSNI != link.SNI || joined.BondPin != link.PinSHA256 {
		t.Fatal("joined node not pinned to main", err)
	}
	nodeFile := filepath.Join(node.Output, "node.json")
	if err := AddNode(serverPath, nodeFile); err != nil {
		t.Fatal(err)
	}
	if err := AddNode(serverPath, nodeFile); err != nil {
		t.Fatal("idempotent update", err)
	}
	f, err = os.Open(server.ClusterFile)
	if err != nil {
		t.Fatal(err)
	}
	config, err := cluster.DecodeConfig(f)
	f.Close()
	if err != nil || len(config.Nodes) != 2 || config.Nodes[1].SNI != "node.example" || config.Nodes[1].PinSHA256 == "" {
		t.Fatal("node identity missing", err)
	}
	publicNode, _ := os.ReadFile(nodeFile)
	if strings.Contains(string(publicNode), server.Password) || strings.Contains(string(publicNode), "PRIVATE KEY") {
		t.Fatal("secret in public node file")
	}
}

func TestSetupNativeTransports(t *testing.T) {
	for _, mode := range []string{"h2-connect", "h2-post", "wss", "h3-post", "h3-connect", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) {
			o := fixture(t, "main.example")
			o.Transport = mode
			if err := Generate(o); err != nil {
				t.Fatal(err)
			}
			config, err := ReadServer(filepath.Join(o.Output, "server.json"))
			if err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(filepath.Join(o.Output, "connection.txt"))
			if err != nil {
				t.Fatal(err)
			}
			p, err := profile.Read(f)
			f.Close()
			if err != nil || p.Transport != mode || (config.H3Listen != "") != (mode == "h3-post" || mode == "h3-connect") {
				t.Fatal("inconsistent native profile", err)
			}
			join := fixture(t, "relay.example")
			join.JoinLinkFile = filepath.Join(o.Output, "connection.txt")
			if err := Generate(join); err != nil {
				t.Fatal(err)
			}
			relay, err := ReadServer(filepath.Join(join.Output, "server.json"))
			if err != nil || (relay.H3Listen != "") != (mode == "h3-post" || mode == "h3-connect") {
				t.Fatal("joined transport listener", err)
			}
		})
	}
	o := fixture(t, "main.example")
	o.Transport = "h3-post"
	o.TLSBackend = "nss"
	if err := Generate(o); err == nil {
		t.Fatal("NSS silently changed to Go QUIC")
	}
	if _, err := os.Stat(o.Output); !os.IsNotExist(err) {
		t.Fatal("invalid combination wrote secrets")
	}
}

func TestSetupRejectsBadIdentityBeforeWriting(t *testing.T) {
	o := fixture(t, "main.example")
	o.SNI = "other.example"
	if Generate(o) == nil {
		t.Fatal("wrong certificate name accepted")
	}
	if _, err := os.Stat(o.Output); !os.IsNotExist(err) {
		t.Fatal("invalid setup left files")
	}
	o.SNI = ""
	o.CACertFile = ""
	if Generate(o) == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if _, err := os.Stat(o.Output); !os.IsNotExist(err) {
		t.Fatal("untrusted setup left files")
	}
	o.CACertFile = o.Certificate
	o.WebRoot = filepath.Dir(o.Output)
	if Generate(o) == nil {
		t.Fatal("private output inside public site accepted")
	}
}

func TestServerConfigRejectsSecretsInUnknownOrDuplicateFields(t *testing.T) {
	o := fixture(t, "main.example")
	if err := Generate(o); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(o.Output, "server.json")
	valid, _ := os.ReadFile(path)
	for _, field := range []string{`"password":"another",`, `"Password":"another",`, `"insecure":true,`} {
		bad := "{" + field + strings.TrimPrefix(string(valid), "{")
		os.WriteFile(path, []byte(bad), 0600)
		if _, err := ReadServer(path); err == nil {
			t.Fatal("ambiguous server config accepted")
		}
	}
}

func TestSetupXHTTPRouteInheritance(t *testing.T) {
	for _, mode := range []string{"xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) {
			main := fixture(t, "main.example")
			main.Transport = mode
			main.XHTTPPath = "/api/cluster"
			main.XHTTPHost = "Route.Example"
			if err := Generate(main); err != nil {
				t.Fatal(err)
			}
			config, err := ReadServer(filepath.Join(main.Output, "server.json"))
			if err != nil || config.XHTTPPath != "/api/cluster/" || config.XHTTPHost != "route.example" {
				t.Fatal("main route", err)
			}
			join := fixture(t, "node.example")
			join.JoinLinkFile = filepath.Join(main.Output, "connection.txt")
			if err := Generate(join); err != nil {
				t.Fatal(err)
			}
			joined, err := ReadServer(filepath.Join(join.Output, "server.json"))
			if err != nil || joined.XHTTPPath != config.XHTTPPath || joined.XHTTPHost != config.XHTTPHost || joined.BondSNI != "main.example" {
				t.Fatal("joined route/identity", err)
			}
			join.Output = filepath.Join(filepath.Dir(join.Output), "conflict")
			join.XHTTPPath = "/other"
			if err := Generate(join); err == nil {
				t.Fatal("conflicting join route ignored")
			}
			if _, err := os.Stat(join.Output); !os.IsNotExist(err) {
				t.Fatal("failed join wrote secrets")
			}
		})
	}
}

func TestSetupXHTTPAutomaticRoute(t *testing.T) {
	first := fixture(t, "main.example")
	first.Transport = "xhttp-stream-up"
	second := fixture(t, "second.example")
	second.Transport = "xhttp-packet-up"
	if err := Generate(first); err != nil {
		t.Fatal(err)
	}
	if err := Generate(second); err != nil {
		t.Fatal(err)
	}
	a, _ := ReadServer(filepath.Join(first.Output, "server.json"))
	b, _ := ReadServer(filepath.Join(second.Output, "server.json"))
	if !strings.HasPrefix(a.XHTTPPath, "/api/") || a.XHTTPPath == b.XHTTPPath || a.XHTTPHost != "" {
		t.Fatal("automatic route missing, repeated or confused with Host")
	}
	join := fixture(t, "node.example")
	join.JoinLinkFile = filepath.Join(first.Output, "connection.txt")
	if err := Generate(join); err != nil {
		t.Fatal(err)
	}
	c, _ := ReadServer(filepath.Join(join.Output, "server.json"))
	if c.XHTTPPath != a.XHTTPPath {
		t.Fatal("join generated a different route")
	}
}
