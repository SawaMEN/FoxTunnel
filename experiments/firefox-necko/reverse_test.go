package firefox

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// The response FIN must not close the request half of a classic CONNECT.
// Use independent protocol peers: net/http handlers normally finish both
// halves on return, so an ordinary echo handler cannot test this contract.
func TestGeckoReverseHalfClose(t *testing.T) {
	runtime := os.Getenv("FOXTUNNEL_XPCSHELL")
	if runtime == "" {
		t.Skip("set FOXTUNNEL_XPCSHELL to a real Gecko runtime")
	}
	for _, mode := range []string{"h2-connect", "h3-connect"} {
		t.Run(mode, func(t *testing.T) {
			for _, scenario := range reverseResponseCases() {
				t.Run(scenario.name, func(t *testing.T) {
					payload := bytes.Repeat([]byte{0, 255, 13, 10, 42, 1}, 22000)
					result := make(chan error, 1)
					cfg := reverseProxy(t, mode, payload, scenario.body, result)
					listen, stderr := startTestHelper(t, runtime, cfg)
					conn, err := nativeSOCKS(listen, "127.0.0.1:443")
					if err != nil {
						t.Fatalf("CONNECT: %v\n%s", err, stderr.text())
					}
					defer conn.Close()
					received, err := io.ReadAll(conn)
					if err != nil || !bytes.Equal(received, scenario.body) {
						t.Fatalf("response bytes + FIN: received %d of %d: %v\n%s", len(received), len(scenario.body), err, stderr.text())
					}
					// Intentionally upload only after receiving EOF, across several
					// flow-control windows, then require the peer to see upload FIN.
					if _, err := conn.Write(payload); err != nil {
						t.Fatalf("upload after response FIN: %v\n%s", err, stderr.text())
					}
					if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
						t.Fatal(err)
					}
					select {
					case err := <-result:
						if err != nil {
							t.Fatalf("peer upload after response FIN: %v\n%s", err, stderr.text())
						}
					case <-time.After(12 * time.Second):
						t.Fatalf("peer never received upload FIN\n%s", stderr.text())
					}
				})
			}
		})
	}
}

// Validate the directional-EOF fixtures with independent Go clients before
// attributing a failed native gate to Gecko.
func TestReverseHalfClosePeers(t *testing.T) {
	for _, mode := range []string{"h2-connect", "h3-connect"} {
		t.Run(mode, func(t *testing.T) {
			for _, scenario := range reverseResponseCases() {
				t.Run(scenario.name, func(t *testing.T) {
					payload := bytes.Repeat([]byte{0, 255, 13, 10, 42, 1}, 22000)
					result := make(chan error, 1)
					cfg := reverseProxy(t, mode, payload, scenario.body, result)
					client := independentPeerTransport(t, cfg, mode)
					ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
					defer cancel()
					reader, writer := io.Pipe()
					defer reader.Close()
					defer writer.Close()
					req, err := http.NewRequestWithContext(ctx, "CONNECT", cfg.Server, reader)
					if err != nil {
						t.Fatal(err)
					}
					req.Host = "127.0.0.1:443"
					response, err := client.RoundTrip(req)
					if err != nil {
						t.Fatal(err)
					}
					defer response.Body.Close()
					if response.StatusCode != 200 {
						t.Fatal(response.Status)
					}
					received, err := io.ReadAll(response.Body)
					if err != nil || !bytes.Equal(received, scenario.body) {
						t.Fatal("peer response bytes + FIN", len(received), err)
					}
					if _, err := writer.Write(payload); err != nil {
						t.Fatal("peer upload", err)
					}
					if err := writer.Close(); err != nil {
						t.Fatal(err)
					}
					select {
					case err := <-result:
						if err != nil {
							t.Fatal(err)
						}
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				})
			}
		})
	}
}

func reverseResponseCases() []struct {
	name string
	body []byte
} {
	body := make([]byte, 8192)
	for i := range body {
		body[i] = byte(i)
	}
	return []struct {
		name string
		body []byte
	}{{name: "empty"}, {name: "buffered", body: body}}
}

func independentPeerTransport(t *testing.T, cfg Config, mode string) http.RoundTripper {
	t.Helper()
	ca, err := os.ReadFile(cfg.CACert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid fixture CA")
	}
	tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	if mode == "h2-connect" {
		transport := &http2.Transport{TLSClientConfig: tlsConfig}
		t.Cleanup(transport.CloseIdleConnections)
		return transport
	}
	transport := &http3.Transport{TLSClientConfig: tlsConfig}
	t.Cleanup(func() { transport.Close() })
	return transport
}

func reverseProxy(t *testing.T, mode string, payload, response []byte, result chan<- error) Config {
	t.Helper()
	if mode == "h2-connect" {
		return reverseH2Proxy(t, payload, response, result)
	}
	return nativeProxy(t, mode, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.ProtoMajor != 3 || r.Host != "127.0.0.1:443" || r.URL.Path != "" {
			reportReverseResult(result, fmt.Errorf("unexpected request: %s %s %s", r.Method, r.Proto, r.Host))
			return
		}
		stream := w.(http3.HTTPStreamer).HTTPStream()
		stream.SetDeadline(time.Now().Add(10 * time.Second))
		if len(response) > 0 {
			if _, err := stream.Write(response); err != nil {
				reportReverseResult(result, err)
				return
			}
		}
		if err := stream.Close(); err != nil { // QUIC send FIN, retain receive half.
			reportReverseResult(result, err)
			return
		}
		data, err := io.ReadAll(io.LimitReader(stream, int64(len(payload)+1)))
		reportReverseResult(result, checkReverseUpload(data, payload, err))
	}))
}

func reportReverseResult(result chan<- error, err error) {
	// A retry or an unexpected extra connection must not block server cleanup
	// after the first result has already ended the test.
	select {
	case result <- err:
	default:
	}
}

func checkReverseUpload(data, want []byte, err error) error {
	if err != nil || !bytes.Equal(data, want) {
		return fmt.Errorf("received %d of %d upload bytes: %v", len(data), len(want), err)
	}
	return nil
}

func reverseH2Proxy(t *testing.T, payload, response []byte, result chan<- error) Config {
	t.Helper()
	certificate, ca := testCertificate(t)
	server := httptest.NewUnstartedServer(nil)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	server.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
		"h2": func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
			reportReverseResult(result, receiveReverseH2(conn, payload, response))
		},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca}), 0600); err != nil {
		t.Fatal(err)
	}
	return Config{Server: server.URL, Username: "u", Password: "p", Transport: "h2-connect", Listen: "127.0.0.1:0", CACert: caPath}
}

func receiveReverseH2(conn *tls.Conn, payload, response []byte) error {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return err
	}
	if string(preface) != http2.ClientPreface {
		return fmt.Errorf("invalid H2 preface")
	}
	f := http2.NewFramer(conn, conn)
	f.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := f.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20}); err != nil {
		return err
	}
	if err := f.WriteWindowUpdate(0, 1<<20); err != nil {
		return err
	}
	var id uint32
	var upload []byte
	for {
		frame, err := f.ReadFrame()
		if err != nil {
			return fmt.Errorf("read upload frame (%d bytes): %w", len(upload), err)
		}
		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			if !frame.IsAck() {
				if err := f.WriteSettingsAck(); err != nil {
					return err
				}
			}
		case *http2.PingFrame:
			if !frame.IsAck() {
				if err := f.WritePing(true, frame.Data); err != nil {
					return err
				}
			}
		case *http2.MetaHeadersFrame:
			if id != 0 || frame.PseudoValue("method") != "CONNECT" || frame.PseudoValue("authority") != "127.0.0.1:443" || frame.PseudoValue("path") != "" {
				return fmt.Errorf("unexpected H2 CONNECT headers")
			}
			id = frame.StreamID
			if err := f.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: []byte{0x88}, EndHeaders: true}); err != nil {
				return err
			}
			if err := f.WriteData(id, true, response); err != nil {
				return err
			}
		case *http2.DataFrame:
			if id == 0 || frame.StreamID != id {
				return fmt.Errorf("unexpected H2 DATA stream %d", frame.StreamID)
			}
			upload = append(upload, frame.Data()...)
			if len(upload) > len(payload) {
				return fmt.Errorf("excess upload bytes")
			}
			if frame.StreamEnded() {
				return checkReverseUpload(upload, payload, nil)
			}
		case *http2.RSTStreamFrame:
			return fmt.Errorf("stream reset after %d upload bytes: %s", len(upload), frame.ErrCode)
		case *http2.GoAwayFrame:
			return fmt.Errorf("connection ended after %d upload bytes: %s", len(upload), frame.ErrCode)
		}
	}
}
