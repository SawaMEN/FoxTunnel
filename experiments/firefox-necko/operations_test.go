package firefox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type operationalStats struct {
	Connected    int    `json:"connected"`
	OldestMS     int64  `json:"oldest_ms"`
	IdleLimit    int    `json:"idle_limit"`
	Type         string `json:"type"`
	Listen       string `json:"listen"`
	PID          int    `json:"pid"`
	ProcessTag   string `json:"process_tag"`
	Active       int    `json:"active"`
	Draining     int    `json:"draining"`
	Completed    int    `json:"completed"`
	Rejected     int    `json:"rejected"`
	IdleExpired  int    `json:"idle_expired"`
	DrainExpired int    `json:"drain_expired"`
	Upload       int64  `json:"upload_bytes"`
	Download     int64  `json:"download_bytes"`
}
type operationalHelper struct {
	sync.Mutex
	latest   operationalStats
	listen   string
	pid      int
	stderr   lockedBuffer
	finished chan struct{}
	cancel   context.CancelFunc
}

func startOperationalHelper(t *testing.T, parent context.Context, cfg Config) *operationalHelper {
	t.Helper()
	runtime := os.Getenv("FOXTUNNEL_XPCSHELL")
	if runtime == "" {
		t.Skip("set FOXTUNNEL_XPCSHELL to a real Gecko runtime")
	}
	ctx, cancel := context.WithCancel(parent)
	h := &operationalHelper{cancel: cancel, finished: make(chan struct{})}
	cfg.StatsIntervalMS = 100
	read, write := io.Pipe()
	ready := make(chan operationalStats, 1)
	go func() {
		defer close(h.finished)
		e := Run(ctx, runtime, cfg, write, &h.stderr)
		if e != nil && ctx.Err() == nil {
			h.stderr.Write([]byte(fmt.Sprintf("helper failure: %v", e)))
		}
		write.CloseWithError(e)
	}()
	go func() {
		d := json.NewDecoder(read)
		for {
			var m operationalStats
			if e := d.Decode(&m); e != nil {
				return
			}
			if m.Type == "ready" {
				ready <- m
			} else if m.Type == "stats" {
				h.Lock()
				h.latest = m
				h.Unlock()
			}
		}
	}()
	t.Cleanup(func() { cancel(); read.Close(); <-h.finished })
	select {
	case r := <-ready:
		h.listen, h.pid = r.Listen, r.PID
		// /proc may be mounted from the host PID namespace in containers.
		// Match only our unique helper script argument; never inspect env data.
		entries, _ := os.ReadDir("/proc")
		for _, entry := range entries {
			if _, e := strconv.Atoi(entry.Name()); e == nil {
				raw, e := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
				if e == nil && bytes.Contains(raw, []byte("/"+r.ProcessTag+"/client.js")) {
					h.pid, _ = strconv.Atoi(entry.Name())
					break
				}
			}
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("helper startup: %s", h.stderr.text())
	case <-h.finished:
		t.Fatalf("helper exited: %s", h.stderr.text())
	}
	return h
}
func (h *operationalHelper) stats() operationalStats { h.Lock(); defer h.Unlock(); return h.latest }
func awaitOperational(t *testing.T, h *operationalHelper, accept func(operationalStats) bool) operationalStats {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s := h.stats()
		select {
		case <-h.finished:
			t.Fatalf("helper exited: %s", h.stderr.text())
		default:
		}
		if accept(s) {
			return s
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("metrics condition failed: %+v\n%s", h.stats(), h.stderr.text())
	return operationalStats{}
}
func operationalRound(h *operationalHelper, target string, seed int) error {
	c, e := nativeSOCKS(h.listen, target)
	if e != nil {
		return e
	}
	defer c.Close()
	payload := make([]byte, 128<<10)
	for i := range payload {
		payload[i] = byte(i + seed)
	}
	if _, e = c.Write(payload); e != nil {
		return e
	}
	if e = c.(*net.TCPConn).CloseWrite(); e != nil {
		return e
	}
	data, e := io.ReadAll(io.LimitReader(c, int64(len(payload)+1)))
	if e != nil || !bytes.Equal(payload, data) {
		return fmt.Errorf("binary EOF: received %d: %w", len(data), e)
	}
	return nil
}
func TestGeckoIdleAndDrainLimits(t *testing.T) {
	if os.Getenv("FOXTUNNEL_XPCSHELL") == "" {
		t.Skip("native runtime required")
	}
	for _, mode := range []string{"h2-connect", "h3-connect"} {
		t.Run(mode, func(t *testing.T) {
			echo := nativeEcho(t)
			cfg := nativeProxy(t, mode, &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true})
			cfg.MaxConnections = 1
			cfg.MaxRetainedConnections = 1
			cfg.IdleTimeoutMS = 300
			cfg.DrainTimeoutMS = 800
			h := startOperationalHelper(t, context.Background(), cfg)
			idle, e := nativeSOCKS(h.listen, echo)
			if e != nil {
				t.Fatal(e)
			}
			defer idle.Close()
			idle.SetReadDeadline(time.Now().Add(3 * time.Second))
			var b [1]byte
			if _, e := idle.Read(b[:]); e == nil {
				t.Fatal("idle tunnel remained usable")
			} else if n, ok := e.(net.Error); ok && n.Timeout() {
				t.Fatal("idle watchdog did not close tunnel")
			}
			awaitOperational(t, h, func(s operationalStats) bool { return s.IdleExpired == 1 && s.Active == 0 })
			if e := operationalRound(h, echo, 1); e != nil {
				t.Fatalf("post-idle transfer: %v\n%s", e, h.stderr.text())
			}
			awaitOperational(t, h, func(s operationalStats) bool { return s.Completed == 1 && s.Draining == 1 })
			if c, e := nativeSOCKS(h.listen, echo); e == nil {
				c.Close()
				t.Fatal("retained-session budget ignored")
			}
			awaitOperational(t, h, func(s operationalStats) bool { return s.Rejected >= 1 && s.Draining == 0 && s.DrainExpired == 1 })
			if e := operationalRound(h, echo, 2); e != nil {
				t.Fatalf("did not recover retained slot: %v", e)
			}
		})
	}
}

type processSample struct {
	RSSKB    uint64 `json:"rss_kib"`
	CPUTicks uint64 `json:"cpu_ticks"`
	FDs      int    `json:"fds"`
	AtMS     int64  `json:"at_ms"`
}

func sampleProcess(pid int, start time.Time) (processSample, error) {
	var s processSample
	s.AtMS = time.Since(start).Milliseconds()
	root := filepath.Join("/proc", strconv.Itoa(pid))
	status, e := os.ReadFile(filepath.Join(root, "status"))
	if e != nil {
		return s, e
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fmt.Sscanf(line, "VmRSS: %d kB", &s.RSSKB)
		}
	}
	raw, e := os.ReadFile(filepath.Join(root, "stat"))
	if e != nil {
		return s, e
	}
	end := strings.LastIndex(string(raw), ")")
	if end < 0 {
		return s, fmt.Errorf("invalid proc stat")
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 13 {
		return s, fmt.Errorf("short proc stat")
	}
	u, e := strconv.ParseUint(fields[11], 10, 64)
	if e != nil {
		return s, e
	}
	v, e := strconv.ParseUint(fields[12], 10, 64)
	if e != nil {
		return s, e
	}
	s.CPUTicks = u + v
	fds, e := os.ReadDir(filepath.Join(root, "fd"))
	if e != nil {
		return s, e
	}
	s.FDs = len(fds)
	return s, nil
}

// Opt-in sustained native gate. Resource figures are observations on the test
// host; thresholds detect unbounded growth, not Internet throughput claims.
func TestGeckoSoak(t *testing.T) {
	duration := os.Getenv("FOXTUNNEL_SOAK_SECONDS")
	if duration == "" {
		t.Skip("set FOXTUNNEL_SOAK_SECONDS for sustained native load")
	}
	seconds, e := strconv.Atoi(duration)
	if e != nil || seconds < 10 || seconds > 3600 {
		t.Fatal("soak seconds must be 10..3600")
	}
	for _, mode := range []string{"h2-connect", "h3-connect"} {
		t.Run(mode, func(t *testing.T) {
			echo := nativeEcho(t)
			cfg := nativeProxy(t, mode, &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true})
			cfg.DrainTimeoutMS = 1000
			cfg.IdleTimeoutMS = 5000
			cfg.MaxConnections = 16
			cfg.MaxRetainedConnections = 128
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds+30)*time.Second)
			defer cancel()
			h := startOperationalHelper(t, ctx, cfg)
			start := time.Now()
			for i := 0; i < 16; i++ {
				if e := operationalRound(h, echo, -i); e != nil {
					t.Fatalf("warmup transfer: %v", e)
				}
			}
			awaitOperational(t, h, func(s operationalStats) bool { return s.Completed == 16 && s.Active == 0 && s.Draining == 0 })
			ticksRaw, e := exec.Command("getconf", "CLK_TCK").Output()
			if e != nil {
				t.Fatal(e)
			}
			ticksPerSecond, e := strconv.ParseFloat(strings.TrimSpace(string(ticksRaw)), 64)
			if e != nil || ticksPerSecond <= 0 {
				t.Fatal("invalid CLK_TCK")
			}
			first, e := sampleProcess(h.pid, start)
			if e != nil {
				t.Fatal(e)
			}
			samples := []processSample{first}
			var rounds int
			deadline := time.Now().Add(time.Duration(seconds) * time.Second)
			for time.Now().Before(deadline) {
				errs := make(chan error, 8)
				for i := 0; i < 8; i++ {
					go func(seed int) { errs <- operationalRound(h, echo, seed) }(rounds + i)
				}
				for i := 0; i < 8; i++ {
					if e := <-errs; e != nil {
						t.Fatalf("soak transfer: %v\n%s", e, h.stderr.text())
					}
				}
				rounds += 8
				s, e := sampleProcess(h.pid, start)
				if e != nil {
					t.Fatal(e)
				}
				samples = append(samples, s)
				time.Sleep(100 * time.Millisecond)
			}
			final := awaitOperational(t, h, func(s operationalStats) bool { return s.Completed == rounds+16 && s.Active == 0 && s.Draining == 0 })
			last, e := sampleProcess(h.pid, start)
			if e != nil {
				t.Fatal(e)
			}
			samples = append(samples, last)
			if out := os.Getenv("FOXTUNNEL_OPERATIONS_OUT"); out != "" {
				os.MkdirAll(out, 0700)
				data, _ := json.MarshalIndent(map[string]any{"schema": 1, "transport": mode, "duration_seconds": seconds, "rounds": rounds, "payload_bytes_per_round": 128 << 10, "parallel_streams": 8, "warmup_tunnels": 16, "samples": samples, "counters": final, "cpu_ticks_per_second": ticksPerSecond, "cpu_seconds": float64(last.CPUTicks-first.CPUTicks) / ticksPerSecond, "average_cpu_percent": 100000 * float64(last.CPUTicks-first.CPUTicks) / ticksPerSecond / float64(last.AtMS-first.AtMS), "scope": "loopback churn plus binary half-close; not a production throughput benchmark"}, "", "  ")
				if e := os.WriteFile(filepath.Join(out, mode+"-soak.json"), append(data, '\n'), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if final.Completed != rounds+16 || final.Rejected != 0 || final.IdleExpired != 0 || final.Upload != int64(rounds+16)*(128<<10) || final.Download != int64(rounds+16)*(128<<10) {
				t.Fatalf("soak counters: %+v rounds=%d", final, rounds)
			}
			if last.FDs > first.FDs+32 || last.RSSKB > first.RSSKB+192*1024 {
				t.Fatalf("resource growth: first=%+v last=%+v", first, last)
			}
			t.Logf("%s: %d verified tunnels, RSS %d -> %d KiB, FDs %d -> %d, CPU +%d ticks", mode, rounds, first.RSSKB, last.RSSKB, first.FDs, last.FDs, last.CPUTicks-first.CPUTicks)
		})
	}
}
