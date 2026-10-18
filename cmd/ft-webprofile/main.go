// ft-webprofile is a loopback-only Firefox/FoxTunnel measurement fixture.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"crypto/x509"
	"github.com/SawaMEN/FoxTunnel/internal/h2profile"
	"github.com/SawaMEN/FoxTunnel/internal/nsstls"
	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
	"github.com/SawaMEN/FoxTunnel/internal/webprofile"
	"golang.org/x/net/proxy"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "webprofile:", err)
		os.Exit(1)
	}
}
func run() error {
	fs := flag.NewFlagSet("ft-webprofile", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8443", "explicit loopback address")
	cert := fs.String("cert", "", "fixture PEM certificate (localhost SAN)")
	key := fs.String("key", "", "fixture PEM private key")
	out := fs.String("out", "", "JSON output, otherwise stdout")
	source := fs.String("source", "", "browser/backend version, OS and scenario label")
	duration := fs.Duration("duration", 3*time.Second, "post-handshake observation, at most 30s")
	sample := fs.String("sample", "", "optional real FoxTunnel client: go or nss")
	clientProfile := fs.String("tls-client-profile", "default", "NSS preferences: default or firefox-158 (NSS 3.130)")
	scenario := fs.String("scenario", "tunnel", "sample workload: tunnel or page (direct H2 GET)")
	comparisonOut := fs.String("comparison-out", "", "write field-by-field comparison JSON (requires --compare)")
	receiveProfile := fs.String("h2-receive-profile", "default", "outer H2 receive profile: default or firefox-158")
	transport := fs.String("transport", "xhttp-packet-up", "sample native H2/XHTTP transport (no WSS/H3)")
	input := fs.String("input", "", "compare an existing report instead of capturing")
	compare := fs.String("compare", "", "reference report; compare TLS and initial HTTP/2 metadata")
	strict := fs.Bool("strict", false, "fail when compared fields differ")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *comparisonOut != "" && *compare == "" {
		return errors.New("--comparison-out requires --compare")
	}
	if *scenario != "tunnel" && *scenario != "page" {
		return errors.New("scenario must be tunnel or page")
	}
	if *comparisonOut != "" && *out != "" {
		a, e := filepath.Abs(*comparisonOut)
		if e != nil {
			return e
		}
		b, e := filepath.Abs(*out)
		if e != nil {
			return e
		}
		if a == b {
			return errors.New("comparison and profile output must use different files")
		}
	}
	if *scenario == "page" {
		transportFlag := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "transport" {
				transportFlag = true
			}
		})
		if transportFlag {
			return errors.New("page scenario uses direct H2; --transport is for tunnel sampling")
		}
	}
	var p webprofile.Profile
	var err error
	if *input != "" {
		if *sample != "" {
			return errors.New("--input conflicts with --sample")
		}
		p, err = load(*input)
	} else {
		if *source == "" || len(*source) > 256 {
			return errors.New("--source is required (max 256 bytes)")
		}
		if *duration <= 0 || *duration > 30*time.Second {
			return errors.New("duration must be within (0,30s]")
		}
		if *sample != "" && *sample != "go" && *sample != "nss" {
			return errors.New("sample must be go or nss")
		}
		if *transport != "h2-connect" && *transport != "h2-post" && *transport != "xhttp-stream-one" && *transport != "xhttp-stream-up" && *transport != "xhttp-packet-up" {
			return errors.New("unsupported fixture transport")
		}
		pair, e := tls.LoadX509KeyPair(*cert, *key)
		if e != nil {
			return e
		}
		addr, e := net.ResolveTCPAddr("tcp", *listen)
		if e != nil {
			return e
		}
		if addr.IP == nil || !addr.IP.IsLoopback() {
			return errors.New("listen requires an explicit loopback IP")
		}
		l, e := net.ListenTCP("tcp", addr)
		if e != nil {
			return e
		}
		defer l.Close()
		_ = l.SetDeadline(time.Now().Add(60 * time.Second))
		origin := "https://localhost:" + fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
		fmt.Fprintln(os.Stderr, "fixture:", origin, "(isolated browser profile only)")
		website := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = io.WriteString(w, "<!doctype html><html><head><title>Local measurement</title></head><body><h1>Local measurement</h1><p>Controlled HTTPS fixture.</p></body></html>")
		})
		handler := &tunnel.Server{Username: "fixture", Password: "local-only", AllowPrivate: true, Cover: website}
		var done chan error
		if *sample != "" {
			done = make(chan error, 1)
			go func() {
				var e error
				if *scenario == "page" {
					e = samplePage(origin, *cert, *sample, *receiveProfile, *clientProfile)
				} else {
					e = sampleClient(origin, *cert, *sample, *transport, *receiveProfile, *clientProfile)
				}
				if e != nil {
					_ = l.Close()
				}
				done <- e
			}()
		}
		p, err = webprofile.Capture(l, &tls.Config{Certificates: []tls.Certificate{pair}}, handler, *source, *duration)
		if done != nil {
			select {
			case e := <-done:
				if e != nil {
					err = e
				}
			case <-time.After(15 * time.Second):
				if err == nil {
					err = errors.New("sample did not terminate")
				}
			}
		}
	}
	if err != nil {
		return err
	}
	different := false
	if *compare != "" {
		ref, e := load(*compare)
		if e != nil {
			return e
		}

		result := webprofile.Compare(ref, p)
		different = !result.InitialMetadataEqual
		for _, f := range result.Checks {
			if !f.Equal {
				fmt.Fprintf(os.Stderr, "DIFF %s\n  reference: %v\n  candidate: %v\n", f.Field, f.Reference, f.Candidate)
			}
		}
		if *comparisonOut != "" {
			data, e := json.MarshalIndent(result, "", "  ")
			if e != nil {
				return e
			}
			if e = os.WriteFile(*comparisonOut, append(data, '\n'), 0600); e != nil {
				return e
			}
		}

		fmt.Fprintln(os.Stderr, "TLS/H2 comparison does not establish browsing-flow or censorship equivalence; record timing depends on workload.")
	}
	b, e := json.MarshalIndent(p, "", "  ")
	if e != nil {
		return e
	}
	b = append(b, '\n')
	if *out != "" {
		err = os.WriteFile(*out, b, 0600)
	} else {
		_, err = os.Stdout.Write(b)
	}
	if err != nil {
		return err
	}
	if *strict && different {
		return errors.New("profiles differ")
	}
	return nil
}
func load(path string) (webprofile.Profile, error) {
	var p webprofile.Profile
	f, e := os.Open(path)
	if e != nil {
		return p, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return p, e
	}
	if info.Size() > 1<<20 {
		return p, errors.New("profile exceeds 1 MiB")
	}
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	e = d.Decode(&p)
	if e == nil {
		var extra any
		if d.Decode(&extra) != io.EOF {
			return p, errors.New("trailing profile data")
		}
	}
	if e == nil && p.Schema != 1 {
		e = errors.New("unsupported profile schema")
	}
	return p, e
}

// Exercise the public Client/SOCKS API, including the selected real outer
// transport, inner H2, authentication and destination relay. No external hosts.
func sampleClient(origin, cert, backend, mode, receiveProfile, clientProfile string) error {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer echo.Close()
	go func() {
		c, e := echo.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = io.Copy(c, c)
	}()
	client, err := tunnel.NewClient(origin, "fixture", "local-only", cert)
	if err != nil {
		return err
	}
	defer client.Close()
	if err = client.SetTLSBackend(backend); err != nil {
		return err
	}
	if err = client.SetTransport(mode); err != nil {
		return err
	}
	if err = client.SetTLSClientProfile(clientProfile); err != nil {
		return err
	}
	if err = client.SetHTTP2ReceiveProfile(receiveProfile); err != nil {
		return err
	}
	socks, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	served := make(chan error, 1)
	go func() { served <- client.Serve(socks) }()
	defer func() { socks.Close(); <-served }()
	dial, err := proxy.SOCKS5("tcp", socks.Addr().String(), nil, &net.Dialer{Timeout: 10 * time.Second})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := dial.(proxy.ContextDialer).DialContext(ctx, "tcp", echo.Addr().String())
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	payload := bytes.Repeat([]byte("fixture payload\n"), 4096)
	write := make(chan error, 1)
	go func() { _, e := io.Copy(c, bytes.NewReader(payload)); write <- e }()
	received := make([]byte, len(payload))
	_, err = io.ReadFull(c, received)
	if err != nil {
		c.Close()
		<-write
		return err
	}
	if err = <-write; err != nil {
		return err
	}
	if !bytes.Equal(received, payload) {
		return errors.New("sample echo mismatch")
	}
	return nil
}

// samplePage isolates the outer stack: the same public HTML GET as Firefox,
// without SOCKS/inner H2 or echo traffic. Browser headers/lifecycle still differ.
func samplePage(origin, cert, backend, receiveProfile, clientProfile string) error {
	pem, e := os.ReadFile(cert)
	if e != nil {
		return e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("invalid page CA")
	}
	config := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}}
	var transport interface {
		http.RoundTripper
		CloseIdleConnections()
	}
	if backend == "nss" {
		transport, e = nsstls.NewTransportWithProfiles(config, receiveProfile, clientProfile)
	} else {
		if clientProfile != "" && clientProfile != "default" {
			return errors.New("TLS client profile requires NSS")
		}
		t := &http.Transport{TLSClientConfig: config, ForceAttemptHTTP2: true, DisableCompression: true}
		e = h2profile.Configure(t, receiveProfile)
		transport = t
	}
	if e != nil {
		return e
	}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "GET", origin+"/", nil)
	if e != nil {
		return e
	}
	response, e := transport.RoundTrip(req)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	if response.ProtoMajor != 2 || response.StatusCode != 200 {
		return errors.New("page requires H2 and HTTP 200")
	}
	data, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil {
		return e
	}
	if len(data) > 65536 || !bytes.Contains(data, []byte("Controlled HTTPS fixture.")) {
		return errors.New("unexpected fixture page")
	}
	return nil
}
