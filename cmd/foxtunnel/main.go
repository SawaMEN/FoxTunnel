package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if len(os.Args) < 2 {
		usage()
	}
	user := os.Getenv("FOXTUNNEL_USER")
	password := os.Getenv("FOXTUNNEL_PASSWORD")
	if user == "" || password == "" {
		log.Fatal("set FOXTUNNEL_USER and FOXTUNNEL_PASSWORD (nonempty)")
	}
	switch os.Args[1] {
	case "server":
		fs := flag.NewFlagSet("server", flag.ExitOnError)
		listen := fs.String("listen", "127.0.0.1:8443", "HTTPS listening address")
		cert := fs.String("cert", "", "TLS certificate PEM")
		key := fs.String("key", "", "TLS private key PEM")
		padding := fs.Bool("padding", false, "enable experimental negotiated initial-record padding")
		webRoot := fs.String("web-root", "", "public website directory for ordinary requests and rejected probes")
		allowPrivate := fs.Bool("allow-private", false, "permit private/loopback destination IPs (unsafe on public deployments)")
		_ = fs.Parse(os.Args[2:])
		if *cert == "" || *key == "" {
			log.Fatal("--cert and --key are required")
		}
		var cover http.Handler
		if *webRoot != "" {
			var err error
			cover, err = tunnel.NewCover(*webRoot)
			if err != nil {
				log.Fatal(err)
			}
		}
		server := &http.Server{
			Addr:              *listen,
			Handler:           &tunnel.Server{Username: user, Password: password, AllowPrivate: *allowPrivate, Cover: cover, Padding: *padding},
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}},
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       90 * time.Second,
			MaxHeaderBytes:    32 << 10,
		}
		log.Printf("HTTPS CONNECT listener: %s", *listen)
		log.Fatal(server.ListenAndServeTLS(*cert, *key))
	case "client":
		fs := flag.NewFlagSet("client", flag.ExitOnError)
		listen := fs.String("listen", "127.0.0.1:1080", "local SOCKS5 listening address")
		server := fs.String("server", "", "remote HTTPS proxy URL")
		padding := fs.Bool("padding", false, "require experimental initial-record padding (server must enable it)")
		tlsBackend := fs.String("tls-backend", "go", "TLS backend: go or experimental nss (requires -tags nss build)")
		connectTimeout := fs.Duration("connect-timeout", 15*time.Second, "maximum CONNECT setup time (does not limit stream lifetime)")
		ca := fs.String("ca-cert", "", "additional trusted certificate PEM")
		_ = fs.Parse(os.Args[2:])
		if *connectTimeout <= 0 {
			log.Fatal("--connect-timeout must be positive")
		}
		client, err := tunnel.NewClient(*server, user, password, *ca)
		if err != nil {
			log.Fatal(err)
		}
		if err := client.SetTLSBackend(*tlsBackend); err != nil {
			log.Fatal(err)
		}
		client.ConnectTimeout = *connectTimeout
		client.Padding = *padding
		defer client.Close()
		listener, err := net.Listen("tcp", *listen)
		if err != nil {
			log.Fatal(err)
		}
		defer listener.Close()
		log.Printf("SOCKS5 listener: %s", listener.Addr())
		log.Fatal(client.Serve(listener))
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: foxtunnel <server|client> [flags] (FOXTUNNEL_USER and FOXTUNNEL_PASSWORD must be set)")
	os.Exit(2)
}
