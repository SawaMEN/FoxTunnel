package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/SawaMEN/FoxTunnel/internal/i18n"
	"github.com/SawaMEN/FoxTunnel/internal/nativetun"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/access"
	"github.com/SawaMEN/FoxTunnel/internal/bootstrap"
	"github.com/SawaMEN/FoxTunnel/internal/buildinfo"
	"github.com/SawaMEN/FoxTunnel/internal/profile"
	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
	"github.com/SawaMEN/FoxTunnel/internal/transportengine"
	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
	"github.com/SawaMEN/FoxTunnel/internal/xhttp"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	args, err := i18n.SelectLanguage(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	os.Args = append([]string{os.Args[0]}, args...)
	if len(os.Args) < 2 {
		usage()
	}
	user := os.Getenv("FOXTUNNEL_USER")
	password := os.Getenv("FOXTUNNEL_PASSWORD")

	switch os.Args[1] {
	case "access":
		if err := accessCommand(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	case "version":
		fs := i18n.NewFlagSet("foxtunnel version")
		asJSON := fs.Bool("json", false, i18n.Text("print machine-readable build information"))
		i18n.Parse(fs, os.Args[2:])
		info := buildinfo.Current()
		if *asJSON {
			if err := json.NewEncoder(os.Stdout).Encode(info); err != nil {
				log.Fatal(err)
			}
		} else {
			fmt.Printf("FoxTunnel %s (%s %s/%s, %s, %s)\n", info.Version, info.Commit, info.GOOS, info.GOARCH, info.BuildFlavor, info.ProtocolDraft)
		}

	case "setup":
		fs := i18n.NewFlagSet("foxtunnel setup")
		xhttpPath := fs.String("xhttp-path", "", i18n.Text("XHTTP path prefix (setup generates a random route by default)"))
		xhttpHost := fs.String("xhttp-host", "", i18n.Text("outer XHTTP Host override (does not change TLS SNI)"))
		server := fs.String("server", "", i18n.Text("remote HTTPS proxy URL"))
		cert := fs.String("cert", "", i18n.Text("TLS certificate PEM"))
		key := fs.String("key", "", i18n.Text("TLS private key PEM"))
		out := fs.String("out", "vetroff-config", i18n.Text("new private configuration directory (must not exist)"))
		transport := fs.String("transport", "h2-connect", i18n.Text("native transport: h2-connect, h2-post, h3-post, wss, xhttp-stream-one, xhttp-stream-up or xhttp-packet-up (no external proxy)"))
		backend := fs.String("tls-backend", "auto", i18n.Text("TLS backend: auto (NSS for TCP on tagged Linux, Go for H3), go, or nss"))
		sni := fs.String("sni", "", i18n.Text("verified TLS server name (default: URL hostname)"))
		ca := fs.String("ca-cert", "", i18n.Text("additional trusted certificate PEM"))
		join := fs.String("join-link-file", "", i18n.Text("join a main node using its connection file"))
		upstreamCA := fs.String("bond-ca-cert", "", i18n.Text("additional trusted PEM for the common exit"))
		web := fs.String("web-root", "", i18n.Text("public website directory for ordinary requests and rejected probes"))
		enableUDP := fs.Bool("enable-udp", false, i18n.Text("experimental SOCKS5 UDP request/response relay on generated server"))
		i18n.Parse(fs, os.Args[2:])
		if err := bootstrap.Generate(bootstrap.Options{Server: *server, Certificate: *cert, PrivateKey: *key, Output: *out, SNI: *sni, CACertFile: *ca, JoinLinkFile: *join, UpstreamCAFile: *upstreamCA, WebRoot: *web, TLSBackend: *backend, Transport: *transport, XHTTPPath: *xhttpPath, XHTTPHost: *xhttpHost, EnableUDP: *enableUDP}); err != nil {
			log.Fatal(i18n.Text(err.Error()))
		}
		fmt.Println(i18n.Text("configuration created: server.json, connection.txt and node.json (secrets not printed)"))
		return
	case "cluster-add":
		fs := i18n.NewFlagSet("foxtunnel cluster-add")
		config := fs.String("config", "", i18n.Text("private server configuration JSON"))
		node := fs.String("node-file", "", i18n.Text("public node identity JSON to add or update"))
		i18n.Parse(fs, os.Args[2:])
		if err := bootstrap.AddNode(*config, *node); err != nil {
			log.Fatal(i18n.Text(err.Error()))
		}
		fmt.Println(i18n.Text("cluster updated; new sessions receive the change on refresh"))
		return
	case "server":
		fs := i18n.NewFlagSet("foxtunnel server")
		xhttpPath := fs.String("xhttp-path", "", i18n.Text("XHTTP path prefix (default: built-in route)"))
		xhttpHost := fs.String("xhttp-host", "", i18n.Text("outer XHTTP Host override (does not change TLS SNI)"))
		configFile := fs.String("config", "", i18n.Text("private server configuration JSON"))
		usersFile := fs.String("users-file", "", i18n.Text("private access policy JSON; reload with SIGHUP"))
		usersState := fs.String("users-state", "", i18n.Text("durable access ledger in a private directory"))
		h3Listen := fs.String("h3-listen", "", i18n.Text("optional native HTTP/3 UDP listening address"))
		listen := fs.String("listen", "127.0.0.1:8443", i18n.Text("HTTPS listening address"))
		cert := fs.String("cert", "", i18n.Text("TLS certificate PEM"))
		key := fs.String("key", "", i18n.Text("TLS private key PEM"))
		padding := fs.Bool("padding", false, i18n.Text("enable experimental negotiated initial-record padding"))
		bondHub := fs.Bool("bond-hub", false, i18n.Text("enable experimental common exit for bonded streams"))
		bondRelay := fs.String("bond-upstream", "", i18n.Text("trusted HTTPS common exit; run this server as a bond relay"))
		bondCA := fs.String("bond-ca-cert", "", i18n.Text("additional trusted PEM for the common exit"))
		bondSNI := fs.String("bond-sni", "", i18n.Text("verified TLS server name for the common exit"))
		bondPin := fs.String("bond-pin-sha256", "", i18n.Text("additional SPKI pin for the common exit"))
		clusterFile := fs.String("cluster-file", "", i18n.Text("cluster JSON file served by the common exit (requires --bond-hub)"))
		maxTunnels := fs.Int("max-tunnels", 256, i18n.Text("maximum active authenticated tunnels, including destination dialing"))
		maxConnections := fs.Int("max-connections", 512, i18n.Text("maximum accepted sockets including incomplete TLS handshakes"))
		webRoot := fs.String("web-root", "", i18n.Text("public website directory for ordinary requests and rejected probes"))
		allowPrivate := fs.Bool("allow-private", false, i18n.Text("permit private/loopback destination IPs (unsafe on public deployments)"))
		enableUDP := fs.Bool("enable-udp", false, i18n.Text("enable experimental authenticated UDP relay (one request/response per HTTPS POST)"))
		i18n.Parse(fs, os.Args[2:])
		if *configFile != "" {
			conflict := false
			fs.Visit(func(f *flag.Flag) {
				if f.Name != "config" && f.Name != "lang" {
					conflict = true
				}
			})
			if conflict {
				log.Fatal(i18n.Text("server config cannot be combined with server-setting flags"))
			}
			config, err := bootstrap.ReadServer(*configFile)
			if err != nil {
				log.Fatal(i18n.Text(err.Error()))
			}
			user, password = config.Username, config.Password
			*usersFile, *usersState = config.UsersFile, config.UsersState
			*listen, *cert, *key = config.Listen, config.Certificate, config.PrivateKey
			*h3Listen = config.H3Listen
			*enableUDP = config.EnableUDP
			*xhttpPath, *xhttpHost = config.XHTTPPath, config.XHTTPHost
			*webRoot, *clusterFile = config.WebRoot, config.ClusterFile
			*bondHub, *bondRelay, *bondCA = config.BondHub, config.BondUpstream, config.BondCA
			*bondSNI, *bondPin = config.BondSNI, config.BondPin
			*maxTunnels, *maxConnections = config.MaxTunnels, config.MaxConnections
		}
		var controller *access.Controller
		if *usersFile != "" || *usersState != "" {
			if *usersFile == "" || *usersState == "" || user != "" || password != "" {
				log.Fatal("users-file and users-state require exclusive access mode")
			}
			if err := checkAccessPaths(*usersFile, *usersState); err != nil {
				log.Fatal(err)
			}
			policy, err := readAccessPolicy(*usersFile, *bondRelay != "")
			if err != nil {
				log.Fatal(err)
			}
			controller, err = access.New(policy, *usersState)
			if err != nil {
				log.Fatal(err)
			}
			defer controller.Close()
		} else if user == "" || password == "" {
			log.Fatal(i18n.Text("set FOXTUNNEL_USER and FOXTUNNEL_PASSWORD (nonempty)"))
		}

		if *maxTunnels <= 0 {
			log.Fatal(i18n.Text("--max-tunnels must be positive"))
		}
		if *maxConnections <= 0 || *maxConnections > 65536 {
			log.Fatal(i18n.Text("invalid connection limit"))
		}
		if *cert == "" || *key == "" {
			log.Fatal(i18n.Text("--cert and --key are required"))
		}
		var cover http.Handler
		if *webRoot != "" {
			if err := tunnel.CheckPublicRoot(*webRoot, *key, *configFile, *clusterFile, *usersFile, *usersState); err != nil {
				log.Fatal(i18n.Text("public website overlaps private configuration"))
			}
			var err error
			cover, err = tunnel.NewCover(*webRoot)
			if err != nil {
				log.Fatal(err)
			}
		}
		if *bondHub && *bondRelay != "" {
			log.Fatal(i18n.Text("choose either --bond-hub or --bond-upstream"))
		}
		carrierSettings, err := xhttp.Normalize(*xhttpPath, *xhttpHost)
		if err != nil {
			log.Fatal(i18n.Text("invalid XHTTP path or Host"))
		}
		handler := &tunnel.Server{Access: controller, BondRelayOnly: controller != nil && *bondRelay != "", XHTTPSettings: carrierSettings, Username: user, Password: password, AllowPrivate: *allowPrivate, EnableUDP: *enableUDP, Cover: cover, Padding: *padding, MaxTunnels: *maxTunnels}
		if *bondHub {
			hub := handler.NewBondHub()
			defer hub.Close()
			handler.Bond = hub
		}
		if *bondRelay != "" {
			relayUser, relayPassword := user, password
			if controller != nil {
				relayUser, relayPassword = "transport-only", "not-forwarded"
			}
			relay, closeRelay, err := tunnel.NewBondRelayIdentity(*bondRelay, relayUser, relayPassword, *bondCA, *bondSNI, *bondPin)
			if err != nil {
				log.Fatal(err)
			}
			defer closeRelay()
			handler.Bond = relay
		}
		if *clusterFile != "" {
			if err := handler.ConfigureCluster(*clusterFile); err != nil {
				log.Fatal(err)
			}
		}
		if controller != nil {
			stop := watchAccess(controller, *usersFile, *bondRelay != "")
			defer stop()
		}
		certificates, err := tlsidentity.NewCertificateStore(*cert, *key)
		if err != nil {
			log.Fatal(err)
		}
		stopCertificates := watchCertificate(certificates.Reload)
		defer stopCertificates()
		ctx, stopProcess := processContext()
		defer stopProcess()
		server := &http.Server{
			Addr:              *listen,
			Handler:           handler,
			TLSConfig:         serverTLS(certificates.Get),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       90 * time.Second,
			MaxHeaderBytes:    32 << 10,
		}
		log.Printf(i18n.Text("HTTPS CONNECT listener: %s"), *listen)
		listener, err := net.Listen("tcp", *listen)
		if err != nil {
			log.Fatal(err)
		}
		var udp net.PacketConn
		if *h3Listen != "" {
			udp, err = net.ListenPacket("udp", *h3Listen)
			if err != nil {
				listener.Close()
				log.Fatal(err)
			}
		}
		if err := serveListeners(ctx, server, handler, listener, udp, *maxConnections); err != nil {
			log.Fatal(err)
		}
		return

	case "client", "share":
		fs := i18n.NewFlagSet("foxtunnel " + os.Args[1])
		xhttpPath := fs.String("xhttp-path", "", i18n.Text("XHTTP path prefix (default: built-in route)"))
		xhttpHost := fs.String("xhttp-host", "", i18n.Text("outer XHTTP Host override (does not change TLS SNI)"))
		link := fs.String("link", "", i18n.Text("vetroff connection link (prefer --link-file for secrets)"))
		linkFile := fs.String("link-file", "", i18n.Text("read vetroff connection link from file or - for stdin"))
		shareOut := new(string)
		if os.Args[1] == "share" {
			fs.StringVar(shareOut, "out", "", i18n.Text("create private mode-0600 connection link file instead of printing credentials"))
		}
		enableUDP := new(bool)
		udpStream := new(bool)
		udpMultiNode := new(bool)
		if os.Args[1] == "client" {
			fs.BoolVar(enableUDP, "enable-udp", false, i18n.Text("enable experimental SOCKS5 UDP ASSOCIATE"))
			fs.BoolVar(udpStream, "udp-stream", false, i18n.Text("opt in to persistent multiplexed UDP stream v2 (requires --enable-udp)"))
			fs.BoolVar(udpMultiNode, "udp-multi-node", false, i18n.Text("opt in to per-destination UDP v2 stream sharding across explicit trusted servers"))
		}
		listen := fs.String("listen", "127.0.0.1:1080", i18n.Text("local SOCKS5 listening address"))
		tunName := new(string)
		tunMTU := new(uint)
		if os.Args[1] == "client" {
			fs.StringVar(tunName, "tun", "", i18n.Text("experimental native Linux TUN device name (requires UDP streaming; does not configure routes or firewall)"))
			fs.UintVar(tunMTU, "tun-mtu", 1400, i18n.Text("native TUN MTU 1280-9000"))
		}
		maxConnections := fs.Int("max-connections", 256, i18n.Text("maximum local SOCKS sockets including incomplete handshakes"))
		server := fs.String("server", "", i18n.Text("remote HTTPS proxy URL"))
		var fallbacks serverURLs
		fs.Var(&fallbacks, "fallback-server", i18n.Text("explicit trusted HTTPS proxy fallback (repeat up to seven times)"))
		bondPipeline := fs.String("bond-pipeline", "auto", i18n.Text("bond pipeline: auto, 4 or 8 (higher depth uses more memory)"))
		bondLanes := new(bool)
		bondRoute := new(string)
		bondAdaptive := new(bool)
		bondAutoTune := new(bool)
		bondTraffic := new(string)
		*bondTraffic = "legacy"
		if os.Args[1] == "client" {
			fs.BoolVar(bondLanes, "bond-lanes", false, i18n.Text("experimental persistent bond channels and small-write batching (requires --bond)"))
			fs.StringVar(bondRoute, "bond-route", "legacy", i18n.Text("bond path scheduling: legacy or smart (requires --bond --discover and direct hub entry)"))
			fs.BoolVar(bondAdaptive, "bond-adaptive", false, i18n.Text("experimental ACKed-data throughput and queue-aware bond scheduling (requires --bond)"))
			fs.BoolVar(bondAutoTune, "bond-autotune", false, i18n.Text("conservative 4/8-slot tuning from ACKed throughput (requires --bond --bond-adaptive)"))
			fs.StringVar(bondTraffic, "bond-traffic", "legacy", i18n.Text("opt-in Bond TCP traffic scheduling: legacy, auto, latency, throughput (requires --bond-adaptive)"))
		}
		bonded := fs.Bool("bond", false, i18n.Text("experimental multi-node stream bonding; nodes must share one hub"))
		discover := fs.Bool("discover", false, i18n.Text("obtain trusted bond nodes and capacity weights from the main HTTPS node"))
		balance := fs.String("balance", "failover", i18n.Text("new-stream scheduling: failover, round-robin, least-active, adaptive"))
		attemptTimeout := fs.Duration("fallback-attempt-timeout", 5*time.Second, i18n.Text("setup time per endpoint when fallbacks are configured"))
		padding := fs.Bool("padding", false, i18n.Text("require experimental initial-record padding (server must enable it)"))
		engine := new(string)
		if os.Args[1] == "client" {
			fs.StringVar(engine, "engine", "legacy", i18n.Text("local transport engine: legacy (default) or mozilla (NSS/Neqo build required)"))
		}
		nativeTransport := fs.String("transport", "h2-connect", i18n.Text("native transport: h2-connect, h2-post, h3-post, wss, xhttp-stream-one, xhttp-stream-up, xhttp-packet-up, or auto with --engine mozilla"))
		tlsBackend := fs.String("tls-backend", "auto", i18n.Text("TLS backend: auto (NSS for TCP on tagged Linux, Go for H3), go, or nss"))
		quicBackend, h3Fallback := new(string), new(string)
		quicTimeout := new(time.Duration)
		engineStatusInterval := new(time.Duration)
		nodeStatusInterval := new(time.Duration)
		bondMetricsInterval := new(time.Duration)
		if os.Args[1] == "client" {
			fs.DurationVar(engineStatusInterval, "engine-status-interval", 0, i18n.Text("optional local engine status JSON log interval; 0 disables, minimum 1s"))
			fs.DurationVar(nodeStatusInterval, "node-status-interval", 0, i18n.Text("optional local passive node metrics JSON log interval; 0 disables, minimum 1s"))
			fs.DurationVar(bondMetricsInterval, "bond-metrics-interval", 0, i18n.Text("optional local Bond path goodput and queue JSON log interval; 0 disables, minimum 1s"))
		}
		*quicBackend = "quic-go"
		*h3Fallback = "none"
		if os.Args[1] == "client" {
			fs.StringVar(quicBackend, "quic-backend", "quic-go", i18n.Text("QUIC client: quic-go or experimental neqo (h3-post only)"))
			fs.StringVar(h3Fallback, "h3-fallback", "none", i18n.Text("Neqo handshake fallback: none or h2 (before sending a request)"))
			fs.DurationVar(quicTimeout, "quic-handshake-timeout", 0, i18n.Text("Neqo handshake budget (default 2s; 100ms through 10s)"))
		}
		tlsProfile := new(string)
		*tlsProfile = "default"
		if os.Args[1] == "client" {
			fs.StringVar(tlsProfile, "tls-client-profile", "default", i18n.Text("TLS client profile: default or experimental firefox-158 (NSS 3.130)"))
		}
		h2Profile := fs.String("h2-receive-profile", "default", i18n.Text("HTTP/2 receive profile: default or experimental firefox-158"))
		sni := fs.String("sni", "", i18n.Text("verified TLS server name (default: URL hostname)"))
		pin := fs.String("pin-sha256", "", i18n.Text("additional server SPKI pin: sha256/base64"))
		encryption := fs.String("encryption", "tls13", i18n.Text("encryption: tls13 (secure negotiation only)"))
		connectTimeout := fs.Duration("connect-timeout", 15*time.Second, i18n.Text("maximum CONNECT setup time (does not limit stream lifetime)"))
		ca := fs.String("ca-cert", "", i18n.Text("additional trusted certificate PEM"))
		nodePinsFile := new(string)
		allowPublicSOCKS := new(bool)
		if os.Args[1] == "client" {
			fs.StringVar(nodePinsFile, "node-pins-file", "", i18n.Text("owner-only JSON with separate SPKI pins for each explicit trusted HTTPS server"))
			fs.BoolVar(allowPublicSOCKS, "socks-allow-lan", false, i18n.Text("explicitly permit non-loopback SOCKS5; requires local SOCKS password and a secure network"))
		}
		i18n.Parse(fs, os.Args[2:])
		if *link != "" || *linkFile != "" {
			if *link != "" && *linkFile != "" {
				log.Fatal(i18n.Text("choose either --link or --link-file"))
			}
			conflict := false
			fs.Visit(func(f *flag.Flag) {
				switch f.Name {
				case "listen", "ca-cert", "lang", "link", "link-file", "enable-udp", "udp-stream", "udp-multi-node", "tun", "tun-mtu", "max-connections", "h2-receive-profile", "tls-client-profile", "bond-lanes", "quic-backend", "h3-fallback", "quic-handshake-timeout", "engine", "engine-status-interval", "node-pins-file", "socks-allow-lan", "bond-route", "bond-adaptive", "bond-autotune", "bond-traffic", "bond-metrics-interval", "node-status-interval":
				default:
					conflict = true
				}
			})
			if conflict {
				log.Fatal(i18n.Text("connection link cannot be combined with connection-setting flags"))
			}
			var imported profile.Config
			var importErr error
			if *link != "" {
				imported, importErr = profile.Decode(*link)
			} else if *linkFile == "-" {
				imported, importErr = profile.Read(os.Stdin)
			} else {
				imported, importErr = profile.ReadSecretFile(*linkFile)
			}
			if importErr != nil {
				log.Fatal(importErr)
			}
			user, password = imported.Username, imported.Password
			*server = imported.Servers[0]
			fallbacks = serverURLs(imported.Servers[1:])
			*tlsBackend = imported.TLSBackend
			*nativeTransport = imported.Transport
			*xhttpPath, *xhttpHost = imported.XHTTPPath, imported.XHTTPHost
			*sni, *pin, *encryption = imported.SNI, imported.PinSHA256, imported.Encryption
			*balance = imported.Balance
			*bonded = imported.Bond
			*discover = imported.Discover
			*bondPipeline = imported.Pipeline
			*padding = imported.Padding
			*connectTimeout, _ = time.ParseDuration(imported.ConnectTimeout)
			*attemptTimeout, _ = time.ParseDuration(imported.AttemptTimeout)
		}
		if os.Args[1] == "share" {
			if user == "" || password == "" {
				log.Fatal(i18n.Text("set FOXTUNNEL_USER and FOXTUNNEL_PASSWORD (nonempty)"))
			}
			exported, err := profile.Encode(profile.Config{Version: 1, Servers: append([]string{*server}, fallbacks...), Username: user, Password: password, TLSBackend: *tlsBackend, Transport: *nativeTransport, XHTTPPath: *xhttpPath, XHTTPHost: *xhttpHost, SNI: *sni, PinSHA256: *pin, Encryption: *encryption, Balance: *balance, Bond: *bonded, Discover: *discover, Pipeline: *bondPipeline, Padding: *padding, ConnectTimeout: connectTimeout.String(), AttemptTimeout: attemptTimeout.String()})
			if err != nil {
				log.Fatal(err)
			}
			if *shareOut != "" {
				if err := profile.WriteSecretFile(*shareOut, exported); err != nil {
					log.Fatal(err)
				}
				fmt.Println("private connection link saved")
			} else {
				fmt.Println(exported)
			}
			return
		}
		if user == "" || password == "" {
			log.Fatal(i18n.Text("set FOXTUNNEL_USER and FOXTUNNEL_PASSWORD (nonempty)"))
		}
		if *encryption != "tls13" {
			log.Fatal(i18n.Text("unsupported encryption (use tls13)"))
		}
		if *maxConnections <= 0 || *maxConnections > 65536 {
			log.Fatal(i18n.Text("invalid connection limit"))
		}
		if *attemptTimeout <= 0 {
			log.Fatal(i18n.Text("--fallback-attempt-timeout must be positive"))
		}
		if *connectTimeout <= 0 {
			log.Fatal(i18n.Text("--connect-timeout must be positive"))
		}
		if *enableUDP && *bonded {
			log.Fatal("--enable-udp is not supported with bond/discovery")
		}
		if *udpStream && !*enableUDP {
			log.Fatal("--udp-stream requires --enable-udp")
		}
		if *udpMultiNode && (!*enableUDP || !*udpStream || *bonded || *discover || len(fallbacks) == 0) {
			log.Fatal("--udp-multi-node requires --enable-udp --udp-stream and at least two explicit trusted servers, without --bond or --discover")
		}
		if *udpMultiNode && *tunName != "" {
			log.Fatal("--udp-multi-node is not yet supported with --tun")
		}
		if *engineStatusInterval < 0 || (*engineStatusInterval > 0 && *engineStatusInterval < time.Second) {
			log.Fatal("--engine-status-interval must be 0 or at least 1s")
		}
		if *nodeStatusInterval < 0 || (*nodeStatusInterval > 0 && *nodeStatusInterval < time.Second) {
			log.Fatal("--node-status-interval must be 0 or at least 1s")
		}
		if *bondRoute != "" && *bondRoute != "legacy" && *bondRoute != "smart" {
			log.Fatal("--bond-route must be legacy or smart")
		}
		if *bondMetricsInterval < 0 || (*bondMetricsInterval > 0 && *bondMetricsInterval < time.Second) {
			log.Fatal("--bond-metrics-interval must be 0 or at least 1s")
		}
		if *bondMetricsInterval > 0 && !*bonded {
			log.Fatal("--bond-metrics-interval requires --bond")
		}
		switch *bondTraffic {
		case "legacy":
		case "auto", "latency", "throughput":
			if !*bonded || !*bondAdaptive {
				log.Fatal("--bond-traffic requires --bond --bond-adaptive")
			}
		default:
			log.Fatal("--bond-traffic must be legacy, auto, latency, or throughput")
		}
		if *bondAutoTune && (!*bonded || !*bondAdaptive) {
			log.Fatal("--bond-autotune requires --bond --bond-adaptive")
		}
		if *bondAdaptive && !*bonded {
			log.Fatal("--bond-adaptive requires --bond")
		}
		if *bondRoute == "smart" && (!*bonded || !*discover) {
			log.Fatal("--bond-route smart requires --bond --discover")
		}
		if *bonded && *balance == "adaptive" {
			log.Fatal("--balance adaptive is not supported with --bond; bond has its own scheduler")
		}
		if *bondLanes && !*bonded {
			log.Fatal(i18n.Text("bond lanes require --bond"))
		}
		if *discover && !*bonded {
			log.Fatal(i18n.Text("cluster discovery requires --bond"))
		}
		client, err := tunnel.NewClient(*server, user, password, *ca)
		if err != nil {
			log.Fatal(err)
		}
		intent := transportengine.Config{
			Engine: *engine, Transport: *nativeTransport,
			TLSBackend: *tlsBackend, QUICBackend: *quicBackend,
			H3Fallback: *h3Fallback, QUICHandshakeTimeout: *quicTimeout,
			TLSClientProfile: *tlsProfile, HTTP2ReceiveProfile: *h2Profile,
		}
		if *engine == "mozilla" {
			explicit := map[string]bool{}
			fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
			// A connection link pins a server-selected carrier; do not
			// overwrite it with speculative H3 discovery.
			if !explicit["transport"] && *link == "" && *linkFile == "" {
				intent.Transport = "auto"
			}
			if !explicit["quic-backend"] {
				intent.QUICBackend = ""
			}
			if !explicit["h3-fallback"] {
				intent.H3Fallback = ""
			}
		}
		plan, err := transportengine.Resolve(intent)
		if err != nil {
			log.Fatal(err)
		}
		if err := plan.Apply(client, *sni, *pin); err != nil {
			log.Fatal(err)
		}
		if err := client.SetXHTTPSettings(*xhttpPath, *xhttpHost); err != nil {
			log.Fatal(err)
		}
		client.MaxConnections = *maxConnections
		client.SOCKSUsername = os.Getenv("FOXTUNNEL_SOCKS_USER")
		client.SOCKSPassword = os.Getenv("FOXTUNNEL_SOCKS_PASSWORD")
		if err := client.ValidateSOCKSAuth(); err != nil {
			log.Fatal(err)
		}
		if *tunName != "" && client.SOCKSUsername != "" {
			log.Fatal("--tun currently uses a local no-auth SOCKS5 connector; local SOCKS credentials are not yet supported with TUN")
		}
		client.EnableUDP = *enableUDP
		client.UDPStreaming = *udpStream
		client.UDPMultiNode = *udpMultiNode
		if err := client.SetFallbackServers(fallbacks); err != nil {
			log.Fatal(err)
		}
		if err := client.SetBalance(*balance); err != nil {
			log.Fatal(err)
		}
		if *nodePinsFile != "" {
			if *discover {
				log.Fatal("--node-pins-file requires explicit configured nodes; use verified discovery identity policies for --discover")
			}
			if err := client.SetNodePinsFile(*nodePinsFile); err != nil {
				log.Fatal(err)
			}
		}
		client.AllowPublicSOCKS = *allowPublicSOCKS
		client.FallbackAttemptTimeout = *attemptTimeout
		client.ConnectTimeout = *connectTimeout
		client.Padding = *padding
		switch *bondPipeline {
		case "auto":
		case "4":
			client.BondPipeline = 4
		case "8":
			client.BondPipeline = 8
		default:
			log.Fatal(i18n.Text("bond pipeline must be auto, 4 or 8"))
		}
		client.BondLanes = *bondLanes
		client.BondRoute = *bondRoute
		client.BondAdaptive = *bondAdaptive
		client.BondAutoTune = *bondAutoTune
		client.BondTraffic = *bondTraffic
		if *bonded {
			var err error
			if *discover {
				err = client.EnableBondDiscovery(context.Background())
			} else {
				err = client.EnableBond()
			}
			if err != nil {
				log.Fatal(err)
			}
		}
		defer client.Close()
		if *engineStatusInterval > 0 {
			ticker := time.NewTicker(*engineStatusInterval)
			defer ticker.Stop()
			done := make(chan struct{})
			defer close(done)
			go func() {
				for {
					select {
					case <-done:
						return
					case <-ticker.C:
						if data, err := json.Marshal(client.TransportStatus()); err == nil {
							log.Printf("engine_status=%s", data)
						}
					}
				}
			}()
		}
		if *nodeStatusInterval > 0 {
			ticker := time.NewTicker(*nodeStatusInterval)
			defer ticker.Stop()
			done := make(chan struct{})
			defer close(done)
			go func() {
				for {
					select {
					case <-done:
						return
					case <-ticker.C:
						if data, err := json.Marshal(client.NodeStatus()); err == nil {
							log.Printf("node_status=%s", data)
						}
					}
				}
			}()
		}
		if *bondMetricsInterval > 0 {
			ticker := time.NewTicker(*bondMetricsInterval)
			defer ticker.Stop()
			done := make(chan struct{})
			defer close(done)
			go func() {
				for {
					select {
					case <-done:
						return
					case <-ticker.C:
						if data, err := json.Marshal(client.BondMetrics()); err == nil {
							log.Printf("bond_metrics=%s", data)
						}
					}
				}
			}()
		}
		ctx, stopProcess := processContext()
		defer stopProcess()
		listener, err := net.Listen("tcp", *listen)
		if err != nil {
			log.Fatal(err)
		}
		defer listener.Close()
		if addr, ok := listener.Addr().(*net.TCPAddr); !ok || !addr.IP.IsLoopback() {
			if !client.AllowPublicSOCKS || client.SOCKSUsername == "" {
				log.Fatal("non-loopback SOCKS5 requires explicit --socks-allow-lan plus FOXTUNNEL_SOCKS_USER/PASSWORD; SOCKS5 passwords are plaintext on the local network")
			}
		}
		if *tunName != "" {
			if !*enableUDP || !*udpStream || *bonded {
				log.Fatal("--tun requires --enable-udp --udp-stream without --bond")
			}
			options := nativetun.Options{Name: *tunName, MTU: uint32(*tunMTU), SOCKS: listener.Addr().String()}
			if err := nativetun.Validate(options); err != nil {
				log.Fatal(err)
			}
			runner, err := nativetun.Start(ctx, options)
			if err != nil {
				log.Fatal(err)
			}
			defer runner.Close()
			log.Printf("native Linux TUN ready: %s (routes, DNS and firewall MUST be configured separately)", *tunName)
		}
		log.Printf(i18n.Text("SOCKS5 listener: %s"), listener.Addr())
		if err := client.ServeContext(ctx, listener); err != nil {
			log.Fatal(err)
		}
		return
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, i18n.Text("usage: foxtunnel <version|setup|server|client|share|cluster-add|access> [flags] (credentials: environment or vetroff link)"))
	os.Exit(2)
}

type serverURLs []string

func (s *serverURLs) String() string         { return strings.Join(*s, ",") }
func (s *serverURLs) Set(value string) error { *s = append(*s, value); return nil }
