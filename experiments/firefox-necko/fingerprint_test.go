package firefox

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Full Firefox and the helper share libxul, target, proxy, trust, payload and
// reconnect policy. This measures Firefox's native raw CONNECT API; a browser
// page navigation has a different workload and is not claimed equivalent.
func TestGeckoBrowserFingerprint(t *testing.T) { browserFingerprint(t, false) }

// Firefox versus Firefox supplies a control for scheduling and TLS randomness.
func TestGeckoFirefoxSelfComparison(t *testing.T) { browserFingerprint(t, true) }

func browserFingerprint(t *testing.T, self bool) {
	runtime := os.Getenv("FOXTUNNEL_XPCSHELL")
	if runtime == "" {
		t.Skip("set FOXTUNNEL_XPCSHELL to a real Gecko runtime")
	}
	runtime, err := filepath.Abs(runtime)
	if err != nil {
		t.Fatal(err)
	}
	digest := func(path string) string {
		f, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		defer f.Close()
		h := sha256.New()
		if _, e := io.Copy(h, f); e != nil {
			t.Fatal(e)
		}
		return hex.EncodeToString(h.Sum(nil))
	}
	hashes, sources := map[string]string{}, map[string]string{}
	for _, name := range []string{"firefox", "xpcshell", "libxul.so", "libnss3.so", "platform.ini"} {
		hashes[name] = digest(filepath.Join(filepath.Dir(runtime), name))
	}
	for _, name := range []string{"client.js", "gecko.lock.json", "fingerprint/browser.py", "fingerprint/browser.js", "fingerprint_test.go", "fingerprint_capture_test.go", "fingerprint_quic_test.go", "fingerprint_decoder_test.go", "fingerprint/rfc9001-initial.json"} {
		sources[name] = digest(name)
	}
	for _, mode := range []string{"h2-connect", "h3-connect"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			payload := make([]byte, 132000)
			for i := range payload {
				payload[i] = byte(i % 256)
			}
			echo, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer echo.Close()
			go func() {
				for {
					c, e := echo.Accept()
					if e != nil {
						return
					}
					go func() {
						defer c.Close()
						c.SetDeadline(time.Now().Add(15 * time.Second))
						data, _ := io.ReadAll(io.LimitReader(c, int64(len(payload)+1)))
						if bytes.Equal(data, payload) {
							c.Write(data)
						}
					}()
				}
			}()
			cert, ca := testCertificate(t)
			caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca})
			caPath := filepath.Join(t.TempDir(), "ca.pem")
			if e := os.WriteFile(caPath, caPEM, 0600); e != nil {
				t.Fatal(e)
			}
			capture := &fpCapture{}
			server := &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true}
			handler := capture.handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "CONNECT" || r.Host != echo.Addr().String() {
					http.Error(w, "fixture CONNECT required", 400)
					return
				}
				server.ServeHTTP(w, r)
			}))
			config := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}}
			var ticket [32]byte
			if _, e := rand.Read(ticket[:]); e != nil {
				t.Fatal(e)
			}
			config.SetSessionTicketKeys([][32]byte{ticket})
			var address string
			if mode == "h2-connect" {
				listener, e := net.Listen("tcp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer listener.Close()
				address = listener.Addr().String()
				go capture.serveH2(ctx, listener, config, handler)
			} else {
				socket, e := net.ListenPacket("udp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer socket.Close()
				address = socket.LocalAddr().String()
				packets := &fpPackets{PacketConn: socket, capture: capture, initial: map[string]*fpInitial{}}
				h3 := capture.h3Server(config, handler, packets)
				defer h3.Close()
				go h3.Serve(packets)
			}
			_, portText, _ := net.SplitHostPort(address)
			port, _ := strconv.Atoi(portText)
			var browserVersion string
			subjects := []string{"firefox", "foxtunnel"}
			if self {
				subjects = []string{"firefox-a", "firefox-b"}
			}
			for _, subject := range subjects {
				capture.Lock()
				capture.subject = subject
				capture.Unlock()
				if self || subject == "firefox" {
					cfg := map[string]any{"runtime": filepath.Join(filepath.Dir(runtime), "firefox"), "transport": mode, "proxy_host": "127.0.0.1", "proxy_port": port, "authorization": "Basic dTpw", "ca_pem": string(caPEM), "target": "http://" + echo.Addr().String() + "/", "rounds": 4, "payload": base64.StdEncoding.EncodeToString(payload)}
					data, _ := json.Marshal(cfg)
					cmd := exec.CommandContext(ctx, "python3", "fingerprint/browser.py")
					cmd.Stdin = bytes.NewReader(data)
					out, e := cmd.CombinedOutput()
					if e != nil {
						t.Fatalf("reference: %v\n%s", e, out)
					}
					var result struct {
						Version string `json:"browser_version"`
						Result  struct {
							OK       bool `json:"ok"`
							Requests []struct {
								Bytes    int    `json:"bytes"`
								OK       bool   `json:"body_ok"`
								Protocol string `json:"protocol"`
							} `json:"requests"`
						} `json:"result"`
					}
					if e := json.Unmarshal(out, &result); e != nil || !result.Result.OK || len(result.Result.Requests) != 4 {
						t.Fatalf("reference workload failed: %s", out)
					}
					browserVersion = result.Version
					for _, r := range result.Result.Requests {
						if !r.OK || r.Bytes != len(payload) || r.Protocol != mode[:2] {
							t.Fatalf("reference payload/protocol mismatch: %s", out)
						}
					}
				} else {
					helperCtx, stop := context.WithCancel(ctx)
					defer stop()
					cfg := Config{Server: "https://" + address, Username: "u", Password: "p", Transport: mode, Listen: "127.0.0.1:0", CACert: caPath}
					var listen string
					stderr := new(lockedBuffer)
					var finished <-chan struct{}
					var dial func(string) (net.Conn, error)
					if bundle := os.Getenv("FOXTUNNEL_FINGERPRINT_BUNDLE"); bundle != "" {
						managed, e := NewManaged(bundle, cfg)
						if e != nil {
							t.Fatal(e)
						}
						defer managed.Close()
						previousStop := stop
						stop = func() { previousStop(); managed.Close() }
						closed := make(chan struct{})
						close(closed)
						finished = closed
						dial = func(target string) (net.Conn, error) { return managed.DialContext(helperCtx, "tcp", target) }
					} else {
						listen, stderr, finished = startTestHelperContext(t, helperCtx, runtime, cfg)
						dial = func(target string) (net.Conn, error) { return nativeSOCKS(listen, target) }
					}
					for round := 0; round < 4; round++ {
						if round == 2 {
							time.Sleep(700 * time.Millisecond)
						}
						conn, e := dial(echo.Addr().String())
						if e != nil {
							stop()
							t.Fatalf("candidate CONNECT: %v\n%s", e, stderr.text())
						}
						if _, e = conn.Write(payload); e == nil {
							e = conn.(*net.TCPConn).CloseWrite()
						}
						if e != nil {
							conn.Close()
							stop()
							t.Fatal(e)
						}
						data, e := io.ReadAll(io.LimitReader(conn, int64(len(payload)+1)))
						conn.Close()
						if e != nil || !bytes.Equal(data, payload) {
							stop()
							t.Fatalf("candidate payload mismatch: %d %v\n%s", len(data), e, stderr.text())
						}
						time.Sleep(100 * time.Millisecond)
					}
					stop()
					<-finished
				}
				time.Sleep(250 * time.Millisecond)
			}
			capture.Lock()
			defer capture.Unlock()
			counts := map[string]int{}
			for _, p := range capture.connections {
				counts[p.Subject] += p.Requests
				fins := map[uint64]bool{}
				for _, stream := range p.Fins {
					fins[stream] = true
				}
				if p.Requests != 2 || len(fins) != 2 || p.Error != "" || p.Truncated || p.Hello == nil || p.ALPN != mode[:2] || len(p.Settings) == 0 || p.Requests != p.Completed {
					t.Fatalf("incomplete observation: %+v", p)
				}
			}
			if len(capture.connections) != 4 || counts[subjects[0]] != 4 || counts[subjects[1]] != 4 {
				t.Fatalf("request counts: %v", counts)
			}
			result := map[string]any{"schema": 1, "kind": "necko-firefox-connect-comparison", "transport": mode, "browser_version": browserVersion, "runtime_sha256": hashes, "source_sha256": sources, "payload_bytes": len(payload), "rounds_per_subject": 4, "connections": capture.connections,
				"scope":                "Full Firefox native CONNECT API versus xpcshell SOCKS adapter; same patched libxul and raw binary workload. Not normal navigation or stock Firefox equivalence.",
				"reconnect_policy":     "server closes each connection 200ms after its second tunnel completes; both clients pause before request three; process TLS cache remains alive",
				"quic_parameter_scope": "selected effective peer parameters including decoder defaults; no raw parameter order/presence claim",
				"limitations":          []string{"TLS 1.3-only loopback fixture; explicit H3 proxy and custom lab root", "Both clients disable socket process because raw handoff requires it", "ClientHello excludes randoms, SNI value, tickets and key bytes; QUIC record_version is zero", "HPACK digests cover fixture header bytes; credentials and destination values are not serialized", "H3 decoded headers/settings are recorded; QPACK instruction bytes are not measured", "FIN packets may be retransmitted; frame counts are not packet-shape parity", "No DPI indistinguishability or production-readiness claim"}}
			if !self && os.Getenv("FOXTUNNEL_FINGERPRINT_BUNDLE") != "" {
				result["candidate_mode"] = "managed-bundle"
			}
			if self {
				result["kind"] = "firefox-self-connect-comparison"
				result["scope"] = "Two fresh full Firefox processes; same patched libxul, proxy and workload. Control for scheduling and TLS randomness."
			}
			encoded, e := json.MarshalIndent(result, "", "  ")
			if e != nil {
				t.Fatal(e)
			}
			if out := os.Getenv("FOXTUNNEL_FINGERPRINT_OUT"); out != "" {
				if self {
					out = filepath.Join(out, "firefox-self")
				}
				if e := os.MkdirAll(out, 0700); e != nil {
					t.Fatal(e)
				}
				path := filepath.Join(out, mode+"-"+strconv.FormatInt(time.Now().UnixNano(), 10)+".json")
				if e := os.WriteFile(path, append(encoded, '\n'), 0600); e != nil {
					t.Fatal(e)
				}
				t.Log("saved", path)
			}
			t.Logf("%s: %d complete connections, four verified binary transfers per subject, Firefox %s", mode, len(capture.connections), browserVersion)
		})
	}
}
