// Package bootstrap creates private, reviewable local configuration bundles.
// It does not install software, modify system trust, DNS or firewall settings.
package bootstrap

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/authheader"
	"github.com/SawaMEN/FoxTunnel/internal/cluster"
	"github.com/SawaMEN/FoxTunnel/internal/contract"
	"github.com/SawaMEN/FoxTunnel/internal/profile"
	"github.com/SawaMEN/FoxTunnel/internal/safejson"
	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
	"github.com/SawaMEN/FoxTunnel/internal/xhttp"
)

type ServerConfig struct {
	ProtocolPolicy contract.ProtocolPolicy `json:"protocol_policy,omitempty"`
	UsersFile      string                  `json:"users_file,omitempty"`
	UsersState     string                  `json:"users_state,omitempty"`
	XHTTPPath      string                  `json:"xhttp_path,omitempty"`
	XHTTPHost      string                  `json:"xhttp_host,omitempty"`
	Version        int                     `json:"v"`
	H3Listen       string                  `json:"h3_listen,omitempty"`
	EnableUDP      bool                    `json:"enable_udp,omitempty"`
	Listen         string                  `json:"listen"`
	Certificate    string                  `json:"cert"`
	PrivateKey     string                  `json:"key"`
	Username       string                  `json:"username"`
	Password       string                  `json:"password"`
	WebRoot        string                  `json:"web_root,omitempty"`
	ClusterFile    string                  `json:"cluster_file,omitempty"`
	BondHub        bool                    `json:"bond_hub,omitempty"`
	BondUpstream   string                  `json:"bond_upstream,omitempty"`
	BondCA         string                  `json:"bond_ca,omitempty"`
	BondSNI        string                  `json:"bond_sni,omitempty"`
	BondPin        string                  `json:"bond_pin_sha256,omitempty"`
	MaxTunnels     int                     `json:"max_tunnels"`
	MaxConnections int                     `json:"max_connections"`
}
type Options struct {
	ProtocolPolicy                                                                                  contract.ProtocolPolicy
	Server, Certificate, PrivateKey, Output, SNI, CACertFile, JoinLinkFile, UpstreamCAFile, WebRoot string
	TLSBackend, Transport, XHTTPPath, XHTTPHost                                                     string
	EnableUDP                                                                                       bool
}

var ErrConfig = errors.New("invalid server configuration")
var ErrSetup = errors.New("setup failed; verify certificates, names and output directory")

func validCredentials(c ServerConfig) bool {
	if c.UsersFile != "" || c.UsersState != "" {
		return c.UsersFile != "" && c.UsersState != "" && c.Username == "" && c.Password == ""
	}
	return authheader.ValidCredentials(c.Username, c.Password)
}

func ReadServer(path string) (ServerConfig, error) {
	var c ServerConfig
	f, err := os.Open(path)
	if err != nil {
		return c, ErrConfig
	}
	defer f.Close()
	if safejson.Decode(f, 32<<10, &c) != nil || c.Version != 1 || c.Certificate == "" || c.PrivateKey == "" || !validCredentials(c) || c.MaxTunnels < 1 || c.MaxTunnels > 65536 || c.MaxConnections < 1 || c.MaxConnections > 65536 {
		return ServerConfig{}, ErrConfig
	}
	if c.ProtocolPolicy.Validate() != nil || c.ProtocolPolicy == contract.ProtocolStrict && (c.BondHub || c.BondUpstream != "" || c.ClusterFile != "") {
		return ServerConfig{}, ErrConfig
	}
	if c.XHTTPPath != "" || c.XHTTPHost != "" {
		settings, err := xhttp.Normalize(c.XHTTPPath, c.XHTTPHost)
		if err != nil {
			return ServerConfig{}, ErrConfig
		}
		c.XHTTPPath, c.XHTTPHost = settings.Path, settings.Host
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return ServerConfig{}, ErrConfig
	}
	if c.H3Listen != "" {
		if _, _, err := net.SplitHostPort(c.H3Listen); err != nil {
			return ServerConfig{}, ErrConfig
		}
	}
	if c.BondHub && c.BondUpstream != "" || c.ClusterFile != "" && !c.BondHub {
		return ServerConfig{}, ErrConfig
	}
	if c.BondUpstream != "" {
		if _, err := cluster.Origin(c.BondUpstream); err != nil {
			return ServerConfig{}, ErrConfig
		}
	}
	if _, err := tlsidentity.Normalize(c.BondSNI, c.BondPin); err != nil {
		return ServerConfig{}, ErrConfig
	}
	return c, nil
}

func Generate(o Options) error {
	if o.ProtocolPolicy.Validate() != nil || o.ProtocolPolicy == contract.ProtocolStrict && o.JoinLinkFile != "" {
		return ErrSetup
	}
	if o.ProtocolPolicy == contract.ProtocolLegacy {
		o.ProtocolPolicy = "" // Preserve the old default JSON/profile format.
	}
	if o.JoinLinkFile != "" && (o.XHTTPPath != "" || o.XHTTPHost != "") {
		return ErrSetup
	}
	u, err := cluster.Origin(o.Server)
	if err != nil {
		return ErrSetup
	}
	policy, err := tlsidentity.Normalize(o.SNI, "")
	if err != nil {
		return ErrSetup
	}
	name := u.Hostname()
	if policy.SNI != "" {
		name = policy.SNI
	} else if net.ParseIP(name) == nil {
		policy.SNI = strings.ToLower(name)
	}
	pair, err := tls.LoadX509KeyPair(o.Certificate, o.PrivateKey)
	if err != nil || len(pair.Certificate) == 0 {
		return ErrSetup
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return ErrSetup
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return ErrSetup
	}
	if o.CACertFile != "" {
		data, err := os.ReadFile(o.CACertFile)
		if err != nil || !roots.AppendCertsFromPEM(data) {
			return ErrSetup
		}
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return ErrSetup
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil || time.Until(leaf.NotAfter) < 24*time.Hour {
		return ErrSetup
	}
	policy.PinSHA256 = tlsidentity.Pin(leaf)
	certPath, err := filepath.Abs(o.Certificate)
	if err != nil {
		return ErrSetup
	}
	keyPath, err := filepath.Abs(o.PrivateKey)
	if err != nil {
		return ErrSetup
	}
	out, err := filepath.Abs(o.Output)
	if err != nil {
		return ErrSetup
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(out))
	if err != nil {
		return ErrSetup
	}
	out = filepath.Join(parent, filepath.Base(out))
	port := u.Port()
	if port == "" {
		port = "443"
	}
	listen := net.JoinHostPort("", port)
	config := ServerConfig{EnableUDP: o.EnableUDP, Version: 1, Listen: listen, Certificate: certPath, PrivateKey: keyPath, Username: "vetroff", MaxTunnels: 256, MaxConnections: 512}
	config.ProtocolPolicy = o.ProtocolPolicy
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return ErrSetup
	}
	config.Password = base64.RawURLEncoding.EncodeToString(secret[:])
	linkConfig := profile.Config{Version: 1, Servers: []string{u.String()}, Username: config.Username, Password: config.Password, SNI: policy.SNI, PinSHA256: policy.PinSHA256, Encryption: "tls13", TLSBackend: o.TLSBackend, Transport: o.Transport, XHTTPPath: o.XHTTPPath, XHTTPHost: o.XHTTPHost, Bond: true, Discover: true}
	linkConfig.ProtocolPolicy = o.ProtocolPolicy
	if o.ProtocolPolicy == contract.ProtocolStrict {
		linkConfig.Bond, linkConfig.Discover = false, false
	}
	if o.WebRoot != "" {
		config.WebRoot, err = filepath.Abs(o.WebRoot)
		if err != nil {
			return ErrSetup
		}
		public, err := filepath.EvalSymlinks(config.WebRoot)
		if err != nil {
			return ErrSetup
		}
		info, err := os.Stat(public)
		if err != nil || !info.IsDir() {
			return ErrSetup
		}
		for _, private := range []string{out, keyPath, o.JoinLinkFile} {
			if private == "" {
				continue
			}
			private, err = filepath.Abs(private)
			if err != nil {
				return ErrSetup
			}
			if resolved, err := filepath.EvalSymlinks(private); err == nil {
				private = resolved
			}
			rel, err := filepath.Rel(public, private)
			if err != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
				return ErrSetup
			}
		}
	}
	if o.JoinLinkFile != "" {
		joined, err := profile.ReadSecretFile(o.JoinLinkFile)
		if err != nil || !joined.Discover {
			return ErrSetup
		}
		config.Username, config.Password = joined.Username, joined.Password
		config.BondUpstream = joined.Servers[0]
		config.BondSNI, config.BondPin = joined.SNI, joined.PinSHA256
		if o.UpstreamCAFile != "" {
			config.BondCA, err = filepath.Abs(o.UpstreamCAFile)
			if err != nil {
				return ErrSetup
			}
		}
		linkConfig = joined
	} else if o.ProtocolPolicy != contract.ProtocolStrict {
		config.BondHub = true
		config.ClusterFile = filepath.Join(out, "cluster.json")
	}
	if linkConfig.Transport == "h3-post" || linkConfig.Transport == "h3-connect" {
		config.H3Listen = listen
	}
	if o.JoinLinkFile == "" && xhttp.IsMode(linkConfig.Transport) && linkConfig.XHTTPPath == "" {
		// The route is independent of the access secret. Joined/legacy profiles
		// retain their existing route rather than silently generating a new one.
		var route [16]byte
		if _, err := rand.Read(route[:]); err != nil {
			return ErrSetup
		}
		linkConfig.XHTTPPath = "/api/" + base64.RawURLEncoding.EncodeToString(route[:]) + "/"
	}
	if linkConfig.XHTTPPath != "" || linkConfig.XHTTPHost != "" {
		settings, err := xhttp.Normalize(linkConfig.XHTTPPath, linkConfig.XHTTPHost)
		if err != nil {
			return ErrSetup
		}
		linkConfig.XHTTPPath, linkConfig.XHTTPHost = settings.Path, settings.Host
		config.XHTTPPath, config.XHTTPHost = settings.Path, settings.Host
	}
	link, err := profile.Encode(linkConfig)
	if err != nil {
		return ErrSetup
	}
	node := cluster.Node{URL: u.String(), Weight: 1, SNI: policy.SNI, PinSHA256: policy.PinSHA256}
	// Refuse existing directories: no key, credential or link is overwritten.
	if os.Mkdir(out, 0700) != nil {
		return ErrSetup
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(out)
		}
	}()
	writeJSON := func(name string, value any) error {
		b, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(out, name), append(b, '\n'), 0600)
	}
	if writeJSON("server.json", config) != nil || writeJSON("node.json", node) != nil || os.WriteFile(filepath.Join(out, "connection.txt"), []byte(link+"\n"), 0600) != nil {
		return ErrSetup
	}
	if config.BondHub && writeJSON("cluster.json", cluster.Config{Version: 1, Nodes: []cluster.Node{node}}) != nil {
		return ErrSetup
	}
	success = true
	return nil
}

// AddNode changes only topology. The node file contains public identity, never
// credentials/private keys. Replacement is atomic in the coordinator directory.
func AddNode(serverFile, nodeFile string) error {
	server, err := ReadServer(serverFile)
	if err != nil || !server.BondHub || server.ClusterFile == "" {
		return ErrConfig
	}
	lock, err := os.OpenFile(server.ClusterFile+".lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrConfig
	}
	defer func() { lock.Close(); os.Remove(lock.Name()) }()
	f, err := os.Open(nodeFile)
	if err != nil {
		return ErrConfig
	}
	var node cluster.Node
	err = safejson.Decode(f, cluster.MaxBytes, &node)
	f.Close()
	if err != nil {
		return ErrConfig
	}
	encoded, _ := json.Marshal(cluster.Config{Version: 1, Nodes: []cluster.Node{node}})
	one, err := cluster.DecodeConfig(strings.NewReader(string(encoded)))
	if err != nil {
		return ErrConfig
	}
	node = one.Nodes[0]
	f, err = os.Open(server.ClusterFile)
	if err != nil {
		return ErrConfig
	}
	config, err := cluster.DecodeConfig(f)
	f.Close()
	if err != nil {
		return ErrConfig
	}
	replaced := false
	newOrigin, _ := cluster.Origin(node.URL)
	for i, n := range config.Nodes {
		oldOrigin, _ := cluster.Origin(n.URL)
		if cluster.OriginKey(oldOrigin) == cluster.OriginKey(newOrigin) {
			config.Nodes[i] = node
			replaced = true
		}
	}
	if !replaced {
		config.Nodes = append(config.Nodes, node)
	}
	encoded, _ = json.MarshalIndent(config, "", "  ")
	if _, err := cluster.DecodeConfig(strings.NewReader(string(encoded))); err != nil {
		return ErrConfig
	}
	tmp, err := os.CreateTemp(filepath.Dir(server.ClusterFile), ".cluster-*")
	if err != nil {
		return ErrConfig
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(append(encoded, '\n')); err != nil {
		tmp.Close()
		return ErrConfig
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return ErrConfig
	}
	if err = tmp.Close(); err != nil {
		return ErrConfig
	}
	if os.Rename(tmp.Name(), server.ClusterFile) != nil {
		return ErrConfig
	}
	return nil
}
