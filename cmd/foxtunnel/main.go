package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/SawaMEN/FoxTunnel/internal/i18n"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/profile"
	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
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
	case "server":
		fs := i18n.NewFlagSet("foxtunnel server")
		listen := fs.String("listen", "127.0.0.1:8443", i18n.Text("HTTPS listening address"))
		cert := fs.String("cert", "", i18n.Text("TLS certificate PEM"))
		key := fs.String("key", "", i18n.Text("TLS private key PEM"))
		padding := fs.Bool("padding", false, i18n.Text("enable experimental negotiated initial-record padding"))
		bondHub := fs.Bool("bond-hub", false, i18n.Text("enable experimental common exit for bonded streams"))
		bondRelay := fs.String("bond-upstream", "", i18n.Text("trusted HTTPS common exit; run this server as a bond relay"))
		bondCA := fs.String("bond-ca-cert", "", i18n.Text("additional trusted PEM for the common exit"))
		clusterFile := fs.String("cluster-file", "", i18n.Text("cluster JSON file served by the common exit (requires --bond-hub)"))
		maxTunnels := fs.Int("max-tunnels", 256, i18n.Text("maximum active authenticated tunnels, including destination dialing"))
		webRoot := fs.String("web-root", "", i18n.Text("public website directory for ordinary requests and rejected probes"))
		allowPrivate := fs.Bool("allow-private", false, i18n.Text("permit private/loopback destination IPs (unsafe on public deployments)"))
		i18n.Parse(fs, os.Args[2:])
		if user == "" || password == "" {
			log.Fatal(i18n.Text("set FOXTUNNEL_USER and FOXTUNNEL_PASSWORD (nonempty)"))
		}
		if *maxTunnels <= 0 {
			log.Fatal(i18n.Text("--max-tunnels must be positive"))
		}
		if *cert == "" || *key == "" {
			log.Fatal(i18n.Text("--cert and --key are required"))
		}
		var cover http.Handler
		if *webRoot != "" {
			var err error
			cover, err = tunnel.NewCover(*webRoot)
			if err != nil {
				log.Fatal(err)
			}
		}
		if *bondHub && *bondRelay != "" {
			log.Fatal(i18n.Text("choose either --bond-hub or --bond-upstream"))
		}
		handler := &tunnel.Server{Username: user, Password: password, AllowPrivate: *allowPrivate, Cover: cover, Padding: *padding, MaxTunnels: *maxTunnels}
		if *bondHub {
			hub := handler.NewBondHub()
			defer hub.Close()
			handler.Bond = hub
		}
		if *bondRelay != "" {
			relay, closeRelay, err := tunnel.NewBondRelay(*bondRelay, user, password, *bondCA)
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
		server := &http.Server{
			Addr:              *listen,
			Handler:           handler,
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}},
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       90 * time.Second,
			MaxHeaderBytes:    32 << 10,
		}
		log.Printf(i18n.Text("HTTPS CONNECT listener: %s"), *listen)
		log.Fatal(server.ListenAndServeTLS(*cert, *key))
	case "client", "share":
		fs := i18n.NewFlagSet("foxtunnel " + os.Args[1])
		link := fs.String("link", "", i18n.Text("vetroff connection link (prefer --link-file for secrets)"))
		linkFile := fs.String("link-file", "", i18n.Text("read vetroff connection link from file or - for stdin"))
		listen := fs.String("listen", "127.0.0.1:1080", i18n.Text("local SOCKS5 listening address"))
		server := fs.String("server", "", i18n.Text("remote HTTPS proxy URL"))
		var fallbacks serverURLs
		fs.Var(&fallbacks, "fallback-server", i18n.Text("explicit trusted HTTPS proxy fallback (repeat up to seven times)"))
		bondPipeline := fs.String("bond-pipeline", "auto", i18n.Text("bond pipeline: auto, 4 or 8 (higher depth uses more memory)"))
		bonded := fs.Bool("bond", false, i18n.Text("experimental multi-node stream bonding; nodes must share one hub"))
		discover := fs.Bool("discover", false, i18n.Text("obtain trusted bond nodes and capacity weights from the main HTTPS node"))
		balance := fs.String("balance", "failover", i18n.Text("new-stream scheduling: failover, round-robin, least-active"))
		attemptTimeout := fs.Duration("fallback-attempt-timeout", 5*time.Second, i18n.Text("setup time per endpoint when fallbacks are configured"))
		padding := fs.Bool("padding", false, i18n.Text("require experimental initial-record padding (server must enable it)"))
		tlsBackend := fs.String("tls-backend", "go", i18n.Text("TLS backend: go or experimental nss (requires -tags nss build)"))
		connectTimeout := fs.Duration("connect-timeout", 15*time.Second, i18n.Text("maximum CONNECT setup time (does not limit stream lifetime)"))
		ca := fs.String("ca-cert", "", i18n.Text("additional trusted certificate PEM"))
		i18n.Parse(fs, os.Args[2:])
		if *link != "" || *linkFile != "" {
			if *link != "" && *linkFile != "" {
				log.Fatal(i18n.Text("choose either --link or --link-file"))
			}
			conflict := false
			fs.Visit(func(f *flag.Flag) {
				switch f.Name {
				case "listen", "ca-cert", "lang", "link", "link-file":
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
				file, err := os.Open(*linkFile)
				if err != nil {
					log.Fatal(i18n.Text("cannot read connection link file"))
				}
				imported, importErr = profile.Read(file)
				file.Close()
			}
			if importErr != nil {
				log.Fatal(importErr)
			}
			user, password = imported.Username, imported.Password
			*server = imported.Servers[0]
			fallbacks = serverURLs(imported.Servers[1:])
			*tlsBackend = imported.TLSBackend
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
			exported, err := profile.Encode(profile.Config{Version: 1, Servers: append([]string{*server}, fallbacks...), Username: user, Password: password, TLSBackend: *tlsBackend, Balance: *balance, Bond: *bonded, Discover: *discover, Pipeline: *bondPipeline, Padding: *padding, ConnectTimeout: connectTimeout.String(), AttemptTimeout: attemptTimeout.String()})
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(exported)
			return
		}
		if user == "" || password == "" {
			log.Fatal(i18n.Text("set FOXTUNNEL_USER and FOXTUNNEL_PASSWORD (nonempty)"))
		}
		if *attemptTimeout <= 0 {
			log.Fatal(i18n.Text("--fallback-attempt-timeout must be positive"))
		}
		if *connectTimeout <= 0 {
			log.Fatal(i18n.Text("--connect-timeout must be positive"))
		}
		if *discover && !*bonded {
			log.Fatal(i18n.Text("cluster discovery requires --bond"))
		}
		client, err := tunnel.NewClient(*server, user, password, *ca)
		if err != nil {
			log.Fatal(err)
		}
		if err := client.SetTLSBackend(*tlsBackend); err != nil {
			log.Fatal(err)
		}
		if err := client.SetFallbackServers(fallbacks); err != nil {
			log.Fatal(err)
		}
		if err := client.SetBalance(*balance); err != nil {
			log.Fatal(err)
		}
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
		listener, err := net.Listen("tcp", *listen)
		if err != nil {
			log.Fatal(err)
		}
		defer listener.Close()
		log.Printf(i18n.Text("SOCKS5 listener: %s"), listener.Addr())
		log.Fatal(client.Serve(listener))
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, i18n.Text("usage: foxtunnel <server|client|share> [flags] (credentials: environment or vetroff link)"))
	os.Exit(2)
}

type serverURLs []string

func (s *serverURLs) String() string         { return strings.Join(*s, ",") }
func (s *serverURLs) Set(value string) error { *s = append(*s, value); return nil }
