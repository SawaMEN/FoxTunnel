package firefox

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
	"github.com/SawaMEN/FoxTunnel/internal/xhttp"
)

// The CONNECT operational test measures a different lifetime: its socket handoff
// has no repeated native HTTP IPC bodies. Exercise those bodies and persistent
// UDP associations here, keeping one verified helper alive throughout each case.
func TestGeckoManagedSoak(t *testing.T) {
	bundle, raw := os.Getenv("FOXTUNNEL_NECKO_BUNDLE"), os.Getenv("FOXTUNNEL_MANAGED_SOAK_SECONDS")
	if bundle == "" || raw == "" {
		t.Skip("verified bundle and FOXTUNNEL_MANAGED_SOAK_SECONDS required")
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds < 10 || seconds > 3600 {
		t.Fatal("managed soak duration must be 10..3600 seconds")
	}
	for _, mode := range []string{"h2-post", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up", "bond-lanes", "udp-v2", "udp-multi-node"} {
		t.Run(mode, func(t *testing.T) {
			udp := strings.HasPrefix(mode, "udp-")
			server := &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true, EnableUDP: udp}
			if mode == "bond-lanes" {
				hub := server.NewBondHub()
				defer hub.Close()
				server.Bond = hub
			}
			server.Padding = mode == "h2-post" || xhttp.IsMode(mode)
			var laneRequests atomic.Int32
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-FoxTunnel-Bond-Lane") != "" {
					laneRequests.Add(1)
				}
				server.ServeHTTP(w, r)
			})
			cfg := nativeProxy(t, "h2-connect", handler)
			var secondary string
			if mode == "bond-lanes" || mode == "udp-multi-node" {
				other := nativeProxy(t, "h2-connect", handler)
				first, e := os.ReadFile(cfg.CACert)
				if e != nil {
					t.Fatal(e)
				}
				second, e := os.ReadFile(other.CACert)
				if e != nil {
					t.Fatal(e)
				}
				cfg.CACert = filepath.Join(t.TempDir(), "roots.pem")
				if e = os.WriteFile(cfg.CACert, append(first, second...), 0600); e != nil {
					t.Fatal(e)
				}
				secondary = other.Server
			}
			c, err := tunnel.NewClient(cfg.Server, "u", "p", cfg.CACert)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			transport := mode
			if mode == "bond-lanes" || udp {
				transport = "h2-connect"
			}
			var managed *Managed
			c.SetManagedHTTPTransport(transport, func() (tunnel.ManagedTransport, error) {
				var e error
				managed, e = NewManaged(bundle, cfg)
				return managed, e
			})
			c.ConnectTimeout = 10 * time.Second
			c.Padding, c.RequireProtocolNegotiation = server.Padding, server.Padding
			if secondary != "" {
				if err = c.SetFallbackServers([]string{secondary}); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "bond-lanes" {
				c.BondAdaptive, c.BondAutoTune, c.BondLanes = true, true, true
				if err = c.EnableBond(); err != nil {
					t.Fatal(err)
				}
			}
			c.EnableUDP, c.UDPStreaming, c.UDPMultiNode = udp, udp, mode == "udp-multi-node"
			if err = c.Prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			managed.mu.Lock()
			tag := managed.profileTag
			managed.mu.Unlock()
			pid := managedSoakPID(t, tag)
			idle, err := sampleProcess(pid, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			dial := func(target string) (net.Conn, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				return c.DialContext(ctx, "tcp", target)
			}
			finishTraffic := func() {}
			if mode == "bond-lanes" {
				listen, stop := managedSoakListener(t, c)
				finishTraffic = stop
				dial = func(target string) (net.Conn, error) { return nativeSOCKS(listen, target) }
			}
			var round func(int) error
			if !udp && mode != "bond-lanes" {
				target := nativeEcho(t)
				round = func(seed int) error { return managedSoakTCPRound(dial, target, seed) }
			}
			parallel, payloadBytes := 4, 128<<10
			if mode == "bond-lanes" {
				round, finishTraffic = managedSoakPersistent(t, dial, nativeEcho(t), parallel, finishTraffic)
			}
			if udp {
				round, finishTraffic = managedSoakUDP(t, c)
				parallel, payloadBytes = 1, 1024
			}
			defer finishTraffic()
			batch := func(seed int) error {
				errs := make(chan error, parallel)
				for i := range parallel {
					go func(n int) { errs <- round(n) }(seed + i)
				}
				var failure error
				for range parallel {
					if e := <-errs; e != nil {
						failure = e
					}
				}
				return failure
			}
			for i := 0; i < 4; i++ {
				if err = batch(-16 + i*parallel); err != nil {
					t.Fatal("warmup:", err)
				}
			}
			start := time.Now()
			first, err := sampleProcess(pid, start)
			if err != nil {
				t.Fatal(err)
			}
			samples := []processSample{first}
			rounds := 0
			sampledAt := start
			for time.Since(start) < time.Duration(seconds)*time.Second {
				if err = batch(rounds); err != nil {
					t.Fatal("managed soak:", err)
				}
				rounds += parallel
				if time.Since(sampledAt) >= time.Second {
					s, e := sampleProcess(pid, start)
					if e != nil {
						t.Fatal(e)
					}
					samples = append(samples, s)
					sampledAt = time.Now()
				}
				time.Sleep(20 * time.Millisecond)
			}
			finishTraffic()
			// Allow the bounded idle GC/CC cadence and asynchronous native
			// owners to settle. Sample with the helper alive: Close must not
			// hide retained resources. Preserve the unchanged FD/RSS limits.
			const settleSeconds = 6
			time.Sleep(settleSeconds * time.Second)
			last, err := sampleProcess(pid, start)
			if err != nil {
				t.Fatal(err)
			}
			samples = append(samples, last)
			resourceBoundsPassed := last.FDs <= idle.FDs+16 && last.RSSKB <= first.RSSKB+192*1024
			if !resourceBoundsPassed {
				// Retain samples and shutdown evidence even when the resource gate
				// fails; otherwise CI discards the workload that needs diagnosis.
				t.Errorf("managed resource growth: first=%+v last=%+v", first, last)
			}
			if mode == "bond-lanes" && laneRequests.Load() == 0 {
				t.Fatal("soak did not use native Bond lanes")
			}
			c.Close()
			if _, e := os.Stat(filepath.Join(os.TempDir(), tag)); !os.IsNotExist(e) {
				t.Fatal("native profile survived shutdown")
			}
			if raw, e := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline")); e == nil && bytes.Contains(raw, []byte("/"+tag+"/client.js")) {
				t.Fatal("native process survived shutdown")
			}
			ticks, err := exec.Command("getconf", "CLK_TCK").Output()
			if err != nil {
				t.Fatal(err)
			}
			rate, err := strconv.ParseFloat(strings.TrimSpace(string(ticks)), 64)
			if err != nil || rate <= 0 {
				t.Fatal("invalid CPU clock rate")
			}
			if out := os.Getenv("FOXTUNNEL_MANAGED_SOAK_OUT"); out != "" {
				if err = os.MkdirAll(out, 0700); err != nil {
					t.Fatal(err)
				}
				report := map[string]any{"schema": 1, "kind": "managed-necko-soak", "transport": mode, "duration_seconds": seconds, "settle_seconds": settleSeconds, "observed_seconds": float64(last.AtMS) / 1000, "rounds": rounds, "parallel_streams": parallel, "payload_bytes_per_round": payloadBytes, "verified_app_bytes": 2 * int64(rounds) * int64(payloadBytes), "samples": samples, "idle_fds": idle.FDs, "resource_bounds_passed": resourceBoundsPassed, "fd_growth_limit": 16, "rss_growth_limit_kib": 192 * 1024, "cpu_ticks_per_second": rate, "cpu_seconds": float64(last.CPUTicks-first.CPUTicks) / rate, "profile_removed": true, "process_joined": true, "client_js_sha256": digestBytes(clientScript), "source_lock_sha256": digestBytes(sourceLock), "ci_run_id": os.Getenv("GITHUB_RUN_ID"), "scope": "helper-only process resources on loopback; not whole-client or WAN throughput"}
				data, e := json.MarshalIndent(report, "", "  ")
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(out, mode+"-managed-soak.json"), append(data, '\n'), 0600); e != nil {
					t.Fatal(e)
				}
			}
			t.Logf("%s: %d verified rounds, RSS %d -> %d KiB, FDs %d -> %d", mode, rounds, first.RSSKB, last.RSSKB, first.FDs, last.FDs)
		})
	}
}

func managedSoakPID(t *testing.T, tag string) int {
	t.Helper()
	if !strings.HasPrefix(tag, "foxtunnel-firefox-") || strings.ContainsAny(tag, "/\\") {
		t.Fatal("invalid native process tag")
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err == nil && bytes.Contains(raw, []byte("/"+tag+"/client.js")) {
			return pid
		}
	}
	t.Fatal("owned native process not found")
	return 0
}

func managedSoakTCPRound(dial func(string) (net.Conn, error), target string, seed int) error {
	conn, err := dial(target)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := make([]byte, 128<<10)
	for i := range payload {
		payload[i] = byte(i + seed)
	}
	sent := make(chan error, 1)
	go func() {
		_, e := conn.Write(payload)
		if e == nil {
			e = conn.(interface{ CloseWrite() error }).CloseWrite()
		}
		sent <- e
	}()
	got, err := io.ReadAll(io.LimitReader(conn, int64(len(payload)+1)))
	if err != nil || !bytes.Equal(got, payload) {
		conn.Close()
		return fmt.Errorf("binary EOF: received %d: %v", len(got), err)
	}
	select {
	case err = <-sent:
		return err
	case <-time.After(10 * time.Second):
		return fmt.Errorf("native upload worker did not finish")
	}
}

func managedSoakListener(t *testing.T, c *tunnel.Client) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.ServeContext(ctx, listener) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			listener.Close()
			select {
			case err := <-done:
				if err != nil {
					t.Error("SOCKS server shutdown:", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("SOCKS workers survived close")
			}
		})
	}
	t.Cleanup(stop)
	return listener.Addr().String(), stop
}

func managedSoakUDP(t *testing.T, c *tunnel.Client) (func(int) error, func()) {
	t.Helper()
	listen, stop := managedSoakListener(t, c)
	var control net.Conn
	var socket *net.UDPConn
	var once sync.Once
	finish := func() {
		once.Do(func() {
			if control != nil {
				control.Close()
			}
			if socket != nil {
				socket.Close()
			}
			stop()
		})
	}
	t.Cleanup(finish)
	var err error
	control, err = net.DialTimeout("tcp", listen, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	control.SetDeadline(time.Now().Add(10 * time.Second))
	control.Write([]byte{5, 1, 0})
	var greeting [2]byte
	if _, err = io.ReadFull(control, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatal("UDP greeting", err)
	}
	control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	var bind [10]byte
	if _, err = io.ReadFull(control, bind[:]); err != nil || bind[1] != 0 || bind[3] != 1 {
		t.Fatal("UDP association", err)
	}
	control.SetDeadline(time.Time{})
	socket, err = net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IP(bind[4:8]), Port: int(binary.BigEndian.Uint16(bind[8:]))})
	if err != nil {
		t.Fatal(err)
	}
	targets := []*net.UDPConn{managedUDPEcho(t), managedUDPEcho(t)}
	return func(seed int) error {
		target := targets[int(uint32(seed))%len(targets)]
		payload := make([]byte, 1024)
		for i := range payload {
			payload[i] = byte(i + seed)
		}
		wire, e := udpproto.Encode(udpproto.Packet{Host: "127.0.0.1", Port: uint16(target.LocalAddr().(*net.UDPAddr).Port), Data: payload})
		if e != nil {
			return e
		}
		socket.SetDeadline(time.Now().Add(10 * time.Second))
		if _, e = socket.Write(wire); e != nil {
			return e
		}
		var response [udpproto.MaxDatagram + 1]byte
		n, e := socket.Read(response[:])
		if e != nil {
			return e
		}
		packet, e := udpproto.Parse(response[:n])
		if e != nil || packet.Port != uint16(target.LocalAddr().(*net.UDPAddr).Port) || !bytes.Equal(packet.Data, payload) {
			return fmt.Errorf("UDP response changed destination/bytes: %v", e)
		}
		return nil
	}, finish
}

// Each worker retains its own Bond stream; do not turn a long-lane test into
// repeated setup/teardown of short sessions. The shared finish closes all four
// upload directions and verifies response EOF before stopping the SOCKS server.
func managedSoakPersistent(t *testing.T, dial func(string) (net.Conn, error), target string, parallel int, stop func()) (func(int) error, func()) {
	t.Helper()
	var connections []net.Conn
	var once sync.Once
	finish := func() {
		once.Do(func() {
			for _, conn := range connections {
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err == nil {
					tail, e := io.ReadAll(io.LimitReader(conn, 1))
					if !t.Failed() && (e != nil || len(tail) != 0) {
						t.Errorf("persistent Bond FIN: trailing=%d error=%v", len(tail), e)
					}
				}
				conn.Close()
			}
			stop()
		})
	}
	t.Cleanup(finish)
	for range parallel {
		conn, err := dial(target)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
	}
	return func(seed int) error {
		conn := connections[int(uint32(seed))%len(connections)]
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		payload := make([]byte, 128<<10)
		for i := range payload {
			payload[i] = byte(i + seed)
		}
		sent := make(chan error, 1)
		go func() { sent <- writeHTTPBytes(conn, payload) }()
		got := make([]byte, len(payload))
		_, err := io.ReadFull(conn, got)
		if err != nil || !bytes.Equal(got, payload) {
			conn.Close()
			return fmt.Errorf("persistent Bond round: %v", err)
		}
		select {
		case err = <-sent:
			return err
		case <-time.After(10 * time.Second):
			return fmt.Errorf("persistent Bond upload worker blocked")
		}
	}, finish
}
