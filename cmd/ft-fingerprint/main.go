// ft-fingerprint captures only non-secret TLS ClientHello metadata. The
// capture listener does not complete TLS and must not be exposed publicly.
package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/fingerprint"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fingerprint:", err)
		os.Exit(1)
	}
}
func run() error {
	listen := flag.String("listen", "", "listen on loopback for one ClientHello (closes before TLS completes)")
	goSample := flag.Bool("sample-go", false, "capture the current Go TLS ClientHello without using network")
	input := flag.String("input", "", "read fingerprint from JSON file")
	output := flag.String("out", "", "write JSON to file (otherwise stdout)")
	reference := flag.String("compare", "", "reference fingerprint JSON for a detailed comparison")
	strict := flag.Bool("strict", false, "return nonzero if any compared field differs")
	flag.Parse()
	modes := 0
	if *listen != "" {
		modes++
	}
	if *goSample {
		modes++
	}
	if *input != "" {
		modes++
	}
	if modes != 1 {
		return errors.New("choose exactly one of --listen, --sample-go, --input")
	}
	var h fingerprint.Hello
	var err error
	switch {
	case *goSample:
		h, err = captureGo()
	case *input != "":
		err = readJSON(*input, &h)
	default:
		addr, e := net.ResolveTCPAddr("tcp", *listen)
		if e != nil {
			return e
		}
		if addr.IP == nil || !addr.IP.IsLoopback() {
			return errors.New("--listen must bind to an explicit loopback IP")
		}
		var l net.Listener
		l, e = net.ListenTCP("tcp", addr)
		if e != nil {
			return e
		}
		defer l.Close()
		fmt.Fprintln(os.Stderr, "capture listening on", l.Addr(), "(one handshake; TLS failure on browser is expected)")
		tcp := l.(*net.TCPListener)
		_ = tcp.SetDeadline(time.Now().Add(60 * time.Second))
		conn, e := tcp.Accept()
		if e != nil {
			return e
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		h, err = fingerprint.ReadClientHello(conn)
	}
	if err != nil {
		return err
	}
	different := false
	if *reference != "" {
		var ref fingerprint.Hello
		if err := readJSON(*reference, &ref); err != nil {
			return err
		}
		for _, f := range []struct {
			name string
			a, b any
		}{
			{"legacy_version", ref.LegacyVersion, h.LegacyVersion}, {"cipher_suites", ref.CipherSuites, h.CipherSuites},
			{"extensions", ref.Extensions, h.Extensions}, {"supported_groups", ref.SupportedGroups, h.SupportedGroups},
			{"ec_point_formats", ref.ECPointFormats, h.ECPointFormats}, {"supported_versions", ref.SupportedVersions, h.SupportedVersions},
			{"signature_algorithms", ref.SignatureAlgorithms, h.SignatureAlgorithms}, {"key_share_groups", ref.KeyShareGroups, h.KeyShareGroups},
			{"alpn", ref.ALPN, h.ALPN}, {"sni_present", ref.SNI, h.SNI},
		} {
			if !reflect.DeepEqual(f.a, f.b) {
				different = true
				fmt.Fprintln(os.Stderr, "DIFF", f.name, ": reference", f.a, "candidate", f.b)
			}
		}
		if ref.JA3 == h.JA3 {
			fmt.Fprintln(os.Stderr, "JA3: equal (not proof of browser equivalence)")
		} else {
			fmt.Fprintln(os.Stderr, "JA3: different")
			different = true
		}
	}
	data, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if *output == "" {
		_, err = os.Stdout.Write(data)
	} else {
		err = os.WriteFile(*output, data, 0600)
	}
	if err != nil {
		return err
	}
	if *strict && different {
		return errors.New("fingerprints differ")
	}
	return nil
}
func readJSON(path string, target *fingerprint.Hello) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 64<<10))
	dec.DisallowUnknownFields()
	return dec.Decode(target)
}
func captureGo() (fingerprint.Hello, error) {
	left, right := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer left.Close()
		c := tls.Client(left, &tls.Config{ServerName: "example.org", NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS13})
		_ = c.Handshake()
		_ = c.Close()
	}()
	_ = right.SetReadDeadline(time.Now().Add(5 * time.Second))
	hello, err := fingerprint.ReadClientHello(right)
	_ = right.Close()
	<-done
	return hello, err
}
