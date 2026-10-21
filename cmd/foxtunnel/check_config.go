package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/access"
	"github.com/SawaMEN/FoxTunnel/internal/bootstrap"
	"github.com/SawaMEN/FoxTunnel/internal/buildinfo"
	"github.com/SawaMEN/FoxTunnel/internal/cluster"
	"github.com/SawaMEN/FoxTunnel/internal/profile"
	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
	"github.com/SawaMEN/FoxTunnel/internal/transportengine"
	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
)

var errCheckConfig = errors.New("configuration check failed")

// Reports deliberately contain neither input paths nor arbitrary parser errors.
// Even unknown JSON fields and filesystem errors can contain credentials.
type configCheck struct {
	Code    string `json:"code"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type configReport struct {
	Schema   int            `json:"schema"`
	Role     string         `json:"role"`
	OK       bool           `json:"ok"`
	Checks   []configCheck  `json:"checks"`
	Settings map[string]any `json:"settings,omitempty"`
}

func (r *configReport) add(code, message string, err error) {
	r.Checks = append(r.Checks, configCheck{Code: code, OK: err == nil, Message: message})
	if err != nil {
		r.OK = false
	}
}

func checkConfigCommand(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("foxtunnel check-config", flag.ContinueOnError)
	// Flag parser errors echo user input; return fixed messages instead.
	fs.SetOutput(io.Discard)
	server := fs.String("config", "", "private server JSON file")
	link := fs.String("link-file", "", "private client profile file (stdin is not supported)")
	ca := fs.String("ca-cert", "", "additional client trusted certificate PEM")
	engine := fs.String("engine", "legacy", "client engine: legacy or mozilla")
	jsonOutput := fs.Bool("json", false, "print a schema-1 JSON report")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(out)
			fmt.Fprintln(out, "usage: foxtunnel check-config (--config FILE | --link-file FILE) [--json]")
			fs.PrintDefaults()
			return nil
		}
		return errors.New("invalid check-config arguments; use --help")
	}
	if fs.NArg() != 0 || (*server == "") == (*link == "") || *link == "-" {
		return errors.New("choose exactly one --config or --link-file regular file")
	}
	if *server != "" {
		conflict := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "engine" || f.Name == "ca-cert" {
				conflict = true
			}
		})
		if conflict {
			return errors.New("client options cannot be combined with --config")
		}
	}
	r := configReport{Schema: 1, OK: true, Checks: []configCheck{}}
	if *server != "" {
		r.Role = "server"
		checkServerConfig(*server, &r)
	} else {
		r.Role = "client"
		checkClientConfig(*link, *ca, *engine, &r)
	}
	if *jsonOutput {
		if err := json.NewEncoder(out).Encode(r); err != nil {
			return errors.New("cannot write configuration report")
		}
	} else {
		for _, check := range r.Checks {
			status := "PASS"
			if !check.OK {
				status = "FAIL"
			}
			if _, err := fmt.Fprintf(out, "%s %s: %s\n", status, check.Code, check.Message); err != nil {
				return errors.New("cannot write configuration report")
			}
		}
	}
	if !r.OK {
		return errCheckConfig
	}
	return nil
}

func regularConfigFile(path string) error {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return errCheckConfig
	}
	return nil
}

func numericListen(address string) error {
	_, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return errCheckConfig
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return errCheckConfig
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n > 65535 {
		return errCheckConfig
	}
	return nil
}

func checkServerConfig(path string, r *configReport) {
	err := regularConfigFile(path)
	var c bootstrap.ServerConfig
	if err == nil {
		c, err = bootstrap.ReadServer(path)
	}
	r.add("server_config", "readable server JSON, known unique fields, valid limits and compatible options", err)
	if err != nil {
		return
	}
	err = numericListen(c.Listen)
	if err == nil && c.H3Listen != "" {
		err = numericListen(c.H3Listen)
	}
	r.add("listen", "listener syntax and numeric ports in range 0..65535; no bind or DNS lookup", err)
	err = regularConfigFile(c.Certificate)
	if err == nil {
		err = regularConfigFile(c.PrivateKey)
	}
	if err == nil {
		_, err = tlsidentity.NewCertificateStore(c.Certificate, c.PrivateKey)
	}
	r.add("certificate", "readable matching TLS certificate/key within the validity period", err)
	if c.UsersFile != "" {
		err = checkAccessPaths(c.UsersFile, c.UsersState)
		if err == nil {
			_, err = readAccessPolicy(c.UsersFile, c.BondUpstream != "")
		}
		r.add("access_policy", "private access policy, separate ledger path and supported relay quotas", err)
		_, err = access.ReadUsage(c.UsersState)
		r.add("access_state", "existing ledger is readable and valid; a missing ledger is allowed", err)
	}
	if c.WebRoot != "" {
		err = tunnel.CheckPublicRoot(c.WebRoot, c.PrivateKey, path, c.ClusterFile, c.UsersFile, c.UsersState)
		if err == nil {
			_, err = tunnel.NewCover(c.WebRoot)
		}
		r.add("web_root", "public directory exists and does not overlap private configuration", err)
	}
	if c.ClusterFile != "" {
		err = regularConfigFile(c.ClusterFile)
		if err == nil {
			f, openErr := os.Open(c.ClusterFile)
			err = openErr
			if err == nil {
				_, err = cluster.DecodeConfig(f)
				f.Close()
			}
		}
		r.add("cluster", "readable bounded cluster document with valid node identities", err)
	}
	if c.BondUpstream != "" {
		user, password := c.Username, c.Password
		if c.UsersFile != "" {
			user, password = "transport-only", "not-forwarded"
		}
		var relayErr error
		if c.BondCA != "" {
			relayErr = regularConfigFile(c.BondCA)
		}
		if relayErr == nil {
			var closeRelay func()
			_, closeRelay, relayErr = tunnel.NewBondRelayIdentity(c.BondUpstream, user, password, c.BondCA, c.BondSNI, c.BondPin)
			if relayErr == nil {
				closeRelay()
			}
		}
		r.add("relay", "local relay identity and trust configuration can be initialized", relayErr)
	}
	if r.OK {
		r.Settings = map[string]any{"h3": c.H3Listen != "", "udp": c.EnableUDP, "managed_users": c.UsersFile != "", "bond_hub": c.BondHub, "bond_relay": c.BondUpstream != "", "max_tunnels": c.MaxTunnels, "max_connections": c.MaxConnections}
	}
}

func checkClientConfig(path, ca, engine string, r *configReport) {
	c, err := profile.ReadSecretFile(path)
	r.add("client_profile", "private regular connection file, valid profile and compatible options", err)
	if err != nil {
		return
	}
	plan, err := transportengine.Resolve(transportengine.Config{Engine: engine, Transport: c.Transport, TLSBackend: c.TLSBackend})
	r.add("engine", "requested engine is compatible with this build and profile", err)
	if err != nil {
		return
	}
	if ca != "" {
		err = regularConfigFile(ca)
		r.add("ca_file", "additional trust file is a readable regular file", err)
		if err != nil {
			return
		}
	}
	client, err := tunnel.NewClient(c.Servers[0], c.Username, c.Password, ca)
	r.add("client_trust", "local trust store and client backend can be initialized", err)
	if err != nil {
		return
	}
	defer client.Close()
	err = plan.Apply(client, c.SNI, c.PinSHA256)
	if err == nil {
		err = client.SetXHTTPSettings(c.XHTTPPath, c.XHTTPHost)
	}
	if err == nil {
		err = client.SetFallbackServers(c.Servers[1:])
	}
	if err == nil {
		err = client.SetBalance(c.Balance)
	}
	if err == nil && c.Bond && !c.Discover {
		client.Padding = c.Padding
		client.FallbackAttemptTimeout, _ = time.ParseDuration(c.AttemptTimeout)
		err = client.EnableBond()
	}
	r.add("client_transport", "selected transport, profiles and configured nodes can be initialized", err)
	if r.OK {
		status := client.TransportStatus()
		r.Settings = map[string]any{"engine": status.Engine, "transport": status.Transport, "tls_backend": status.TLSBackend, "quic_backend": status.QUICBackend, "servers": len(c.Servers), "bond": c.Bond, "discover": c.Discover, "padding": c.Padding, "balance": c.Balance, "connect_timeout": c.ConnectTimeout, "attempt_timeout": c.AttemptTimeout, "nss_available": buildinfo.NSSAvailable}
	}
}
