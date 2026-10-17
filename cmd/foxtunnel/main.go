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
		allowPrivate := fs.Bool("allow-private", false, "permit private/loopback destination IPs (unsafe on public deployments)")
		_ = fs.Parse(os.Args[2:])
		if *cert == "" || *key == "" {
			log.Fatal("--cert and --key are required")
		}
		server := &http.Server{
			Addr:              *listen,
			Handler:           &tunnel.Server{Username: user, Password: password, AllowPrivate: *allowPrivate},
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}},
			ReadHeaderTimeout: 10 * time.Second,
		}
		log.Printf("HTTPS CONNECT listener: %s", *listen)
		log.Fatal(server.ListenAndServeTLS(*cert, *key))
	case "client":
		fs := flag.NewFlagSet("client", flag.ExitOnError)
		listen := fs.String("listen", "127.0.0.1:1080", "local SOCKS5 listening address")
		server := fs.String("server", "", "remote HTTPS proxy URL")
		ca := fs.String("ca-cert", "", "additional trusted certificate PEM")
		_ = fs.Parse(os.Args[2:])
		client, err := tunnel.NewClient(*server, user, password, *ca)
		if err != nil {
			log.Fatal(err)
		}
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
