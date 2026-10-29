package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/VetroffProxy/internal/bootstrap"
	"github.com/SawaMEN/VetroffProxy/internal/contract"
	"github.com/SawaMEN/VetroffProxy/internal/profile"
	"github.com/SawaMEN/VetroffProxy/internal/tunnel"
)

func startPolicyProcess(t *testing.T, args []string, credentials bool) processEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	cmd := helperCommand(ctx, append(args, "--events-json", "--shutdown-on-stdin-eof")...)
	cmd.Env = helperEnv(credentials)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); cancel(); cmd.Process.Kill(); cmd.Wait() })
	var ready processEvent
	if err := json.NewDecoder(stdout).Decode(&ready); err != nil || ready.Type != "ready" {
		t.Fatalf("policy process did not start: %v, %+v", err, ready)
	}
	return ready
}

func policyCLIServer(t *testing.T, policy string, fromConfig bool) (processEvent, string) {
	t.Helper()
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	operationPair(t, cert, key, 301)
	args := []string{"server"}
	if fromConfig {
		c := bootstrap.ServerConfig{ProtocolPolicy: contract.ProtocolPolicy(policy), Version: 1, Listen: "127.0.0.1:0", H3Listen: "127.0.0.1:0", Certificate: cert, PrivateKey: key,
			Username: "demo-user", Password: "example-only-password", EnableUDP: true, MaxTunnels: 32, MaxConnections: 64}
		path := filepath.Join(dir, "server.json")
		saveCheckServer(t, path, c)
		args = append(args, "--config", path)
	} else {
		args = append(args, "--listen", "127.0.0.1:0", "--h3-listen", "127.0.0.1:0", "--cert", cert, "--key", key, "--protocol-policy", policy, "--enable-udp", "--allow-private")
	}
	return startPolicyProcess(t, args, !fromConfig), cert
}

func policySOCKS(t *testing.T, listen, target string, queuedPayload bool) (net.Conn, byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", listen, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var hello [2]byte
	if _, err := io.ReadFull(c, hello[:]); err != nil || hello != [2]byte{5, 0} {
		t.Fatal("SOCKS greeting failed", err)
	}
	_, port, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(port)
	request := []byte{5, 1, 0, 1, 127, 0, 0, 1, byte(n >> 8), byte(n)}
	if queuedPayload {
		request = append(request, []byte("must-not-leak-before-confirmation")...)
	}
	if _, err := c.Write(request); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatal("SOCKS result missing", err)
	}
	return c, reply[1]
}

func TestProtocolPolicyCLITransportMatrix(t *testing.T) {
	ready, ca := policyCLIServer(t, "strict", false)
	target, _ := doctorTCPDestination(t, "echo")
	for _, mode := range []string{"h2-connect", "h2-post", "h3-post", "wss", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) {
			serverURL := "https://" + ready.TCPListen
			if mode == "h3-post" {
				serverURL = "https://" + ready.UDPListen
			}
			args := []string{"client", "--listen", "127.0.0.1:0", "--ca-cert", ca}
			// Exercise both CLI flags and stored profiles on real subprocesses.
			if mode == "h2-connect" || mode == "h3-post" {
				args = append(args, "--server", serverURL, "--transport", mode, "--tls-backend", "go", "--protocol-policy", "strict")
			} else {
				path := filepath.Join(t.TempDir(), "connection.txt")
				link, err := profile.Encode(profile.Config{ProtocolPolicy: contract.ProtocolStrict, Version: 1, Servers: []string{serverURL}, Username: "demo-user", Password: "example-only-password", Transport: mode, TLSBackend: "go"})
				if err != nil {
					t.Fatal(err)
				}
				if err := profile.WriteSecretFile(path, link); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--link-file", path)
			}
			client := startPolicyProcess(t, args, true)
			conn, code := policySOCKS(t, client.TCPListen, target, false)
			if code != 0 {
				t.Fatal("strict CLI could not open a negotiated tunnel", code)
			}
			payload := []byte(strings.Repeat("s", doctorPayloadBytes))
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != string(payload) {
				t.Fatal("negotiated CLI payload failed", err)
			}
			conn.Close()
		})
	}
}

func TestProtocolPolicyServerJSONAndFlagAdmission(t *testing.T) {
	for _, fromConfig := range []bool{false, true} {
		for _, policy := range []string{"builtin", "strict"} {
			t.Run(policy+"/config="+strconv.FormatBool(fromConfig), func(t *testing.T) {
				ready, ca := policyCLIServer(t, policy, fromConfig)
				roots := x509.NewCertPool()
				data, _ := os.ReadFile(ca)
				if !roots.AppendCertsFromPEM(data) {
					t.Fatal("invalid test CA")
				}
				tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
				defer tr.CloseIdleConnections()
				closed, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				target := closed.Addr().String()
				closed.Close()
				for _, offer := range []string{"", contract.ProtocolDraft, "vetroff-draft-999"} {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+ready.TCPListen, nil)
					req.Host = target // Never resolve/dial an external target.
					req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("demo-user:example-only-password")))
					if offer != "" {
						req.Header.Set("X-Vetroff-Version", offer)
						req.Header.Set("X-Vetroff-Require", "tcp")
					}
					resp, err := tr.RoundTrip(req)
					if err != nil {
						cancel()
						t.Fatal(err)
					}
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					cancel()
					if offer == "vetroff-draft-999" || policy == "strict" && offer == "" {
						if resp.StatusCode != http.StatusUpgradeRequired {
							t.Fatal("missing/future version was not rejected", resp.StatusCode)
						}
					} else if resp.StatusCode == http.StatusUpgradeRequired {
						t.Fatal("compatible/builtin request was rejected as incompatible")
					}
					if offer == contract.ProtocolDraft && resp.Header.Get("X-Vetroff-Version") != contract.ProtocolDraft {
						t.Fatal("server lost compatible version confirmation")
					}
				}
			})
		}
	}
}

func TestProtocolPolicyShareAndSetupCLI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	share := helperCommand(ctx, "share", "--server", "https://strict.example", "--protocol-policy", "strict")
	share.Env = helperEnv(true)
	data, err := share.Output()
	if err != nil {
		t.Fatal(err)
	}
	p, err := profile.Decode(strings.TrimSpace(string(data)))
	if err != nil || p.ProtocolPolicy != contract.ProtocolStrict {
		t.Fatal("share did not store strict policy", err)
	}
	path := filepath.Join(t.TempDir(), "connection.txt")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	share = helperCommand(ctx, "share", "--link-file", path)
	share.Env = helperEnv(false)
	data, err = share.Output()
	if err != nil {
		t.Fatal(err)
	}
	p, err = profile.Decode(strings.TrimSpace(string(data)))
	if err != nil || p.ProtocolPolicy != contract.ProtocolStrict {
		t.Fatal("share silently downgraded imported policy", err)
	}
	c, _ := checkServerFixture(t)
	out := filepath.Join(t.TempDir(), "strict-setup")
	setup := helperCommand(ctx, "setup", "--server", "https://127.0.0.1", "--cert", c.Certificate, "--key", c.PrivateKey, "--ca-cert", c.Certificate, "--out", out, "--protocol-policy", "strict")
	setup.Env = helperEnv(false)
	if output, err := setup.CombinedOutput(); err != nil || strings.Contains(string(output), "vetroff://") {
		t.Fatalf("strict setup CLI failed or disclosed a link: %v, %s", err, output)
	}
	generated, err := bootstrap.ReadServer(filepath.Join(out, "server.json"))
	if err != nil || generated.ProtocolPolicy != contract.ProtocolStrict || generated.BondHub {
		t.Fatal("setup did not persist strict server policy", err)
	}
	r, err, _ := runConfigReport(t, "--config", filepath.Join(out, "server.json"))
	if err != nil || r.Settings["protocol_policy"] != "strict" {
		t.Fatal("server check-config lost strict policy", err)
	}
}

func TestProtocolPolicyCLINeverDowngradesOrLeaksQueuedPayload(t *testing.T) {
	for _, confirmation := range []string{"missing", "future", "missing-capability"} {
		t.Run(confirmation, func(t *testing.T) {
			var calls, fallbacks, bodyBytes atomic.Int64
			finished := make(chan struct{}, 1)
			peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("X-Vetroff-Version") != contract.ProtocolDraft {
					t.Error("CLI did not send a strict offer")
				}
				if confirmation != "missing" {
					version, capabilities := contract.ProtocolDraft, "tcp"
					if confirmation == "future" {
						version = "vetroff-draft-999"
					} else {
						capabilities = "udp-v1"
					}
					w.Header().Set("X-Vetroff-Version", version)
					w.Header().Set("X-Vetroff-Capabilities", capabilities)
				}
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				n, _ := io.Copy(io.Discard, r.Body)
				bodyBytes.Add(n)
				finished <- struct{}{}
			}))
			peer.EnableHTTP2 = true
			peer.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
			peer.StartTLS()
			defer peer.Close()
			fallback := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { fallbacks.Add(1) }))
			defer fallback.Close()
			ca := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peer.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			client := startPolicyProcess(t, []string{"client", "--server", peer.URL, "--fallback-server", fallback.URL, "--listen", "127.0.0.1:0", "--ca-cert", ca, "--tls-backend", "go", "--protocol-policy", "strict"}, true)
			conn, code := policySOCKS(t, client.TCPListen, "127.0.0.1:1", true)
			conn.Close()
			select {
			case <-finished:
			case <-time.After(2 * time.Second):
				t.Fatal("strict rejection did not close peer upload")
			}
			if code == 0 || calls.Load() != 1 || fallbacks.Load() != 0 || bodyBytes.Load() != 0 {
				t.Fatal("strict CLI downgraded, retried or sent queued application bytes", code, calls.Load(), fallbacks.Load(), bodyBytes.Load())
			}
		})
	}
}

func TestProtocolPolicyDoctorAndCheckConfig(t *testing.T) {
	for _, mode := range []string{"h2-connect", "h3-post"} {
		t.Run(mode, func(t *testing.T) {
			f := newDoctorFixture(t, mode, "go", &tunnel.Server{Username: "private-user-marker", Password: "private-password-marker-012345", AllowPrivate: true, EnableUDP: true, RequireProtocolNegotiation: true})
			f.config.ProtocolPolicy = contract.ProtocolStrict
			f.save(t)
			r, err, _ := runConfigReport(t, "--link-file", f.path, "--ca-cert", f.ca)
			if err != nil || r.Settings["protocol_policy"] != "strict" {
				t.Fatal("check-config lost protocol policy", err)
			}
			target, _ := doctorTCPDestination(t, "echo")
			if r, err, _ := callDoctor(t, f, target); err != nil || r.ProtocolPolicy != contract.ProtocolStrict {
				t.Fatalf("strict TCP doctor failed: %+v, %v", r, err)
			}
			udp, _ := doctorUDPDestination(t, false)
			if r, err, _ := callDoctor(t, f, udp, "--network", "udp"); err != nil || !r.OK {
				t.Fatalf("strict UDP doctor failed: %+v, %v", r, err)
			}
			f.config.ProtocolPolicy = ""
			f.save(t)
			report, err, _ := callDoctor(t, f, target)
			if err == nil || report.OK || report.Checks[len(report.Checks)-1].Reason != "protocol_negotiation_failed" {
				t.Fatal("builtin doctor accepted a strict server")
			}
		})
	}
}

func TestProtocolPolicyCLIRejectsTyposConflictsAndBond(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, role := range []string{"server", "client", "share", "setup"} {
		cmd := helperCommand(ctx, role, "--protocol-policy", "private-policy-typo")
		cmd.Env = helperEnv(true)
		if out, err := cmd.CombinedOutput(); err == nil || strings.Contains(string(out), "private-policy-typo") {
			t.Fatal("invalid policy was accepted or echoed", role)
		}
	}
	f := newDoctorFixture(t, "h2-connect", "go", nil)
	f.config.ProtocolPolicy = contract.ProtocolStrict
	f.save(t)
	for _, args := range [][]string{
		{"client", "--link-file", f.path, "--protocol-policy", "builtin"},
		{"share", "--link-file", f.path, "--protocol-policy", "builtin"},
		{"client", "--server", f.node.URL, "--protocol-policy", "strict", "--bond", "--discover"},
		{"server", "--protocol-policy", "strict", "--bond-hub"},
	} {
		cmd := helperCommand(ctx, args...)
		cmd.Env = helperEnv(true)
		if out, err := cmd.CombinedOutput(); err == nil || strings.Contains(string(out), f.config.Password) {
			t.Fatal("strict policy was overridden or combined with an unnegotiated extension")
		}
	}
}
