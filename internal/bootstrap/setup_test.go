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
