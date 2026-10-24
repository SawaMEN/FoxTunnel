package tunnel

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

func TestUDPIngressStableAcrossFlowPackets(t *testing.T) {
	for _, tc := range []struct {
		host  string
		port  uint16
		nodes int
	}{
		{"example.org", 443, 2},
		{"EXAMPLE.ORG", 443, 8},
		{"2001:db8::1", 53, 4},
	} {
		want := udpIngressIndex(tc.host, tc.port, tc.nodes)
		if want < 0 || want >= tc.nodes {
			t.Fatalf("out of range: %v -> %d", tc, want)
		}
		for range 100 {
			if got := udpIngressIndex(tc.host, tc.port, tc.nodes); got != want {
				t.Fatalf("unstable flow mapping: %v: %d instead of %d", tc, got, want)
			}
		}
	}
	if udpIngressIndex("EXAMPLE.org", 443, 8) != udpIngressIndex("example.org", 443, 8) {
		t.Fatal("DNS hostname case changed UDP egress")
	}
	if got := udpIngressIndex("any.example", 53, 0); got != 0 {
		t.Fatal("zero-node guard")
	}
	used := map[int]bool{}
	for p := uint16(10000); p < 10100; p++ {
		used[udpIngressIndex("127.0.0.1", p, 8)] = true
	}
	if len(used) != 8 {
		t.Fatalf("flow hashing cannot use all eight exits: %d", len(used))
	}
}

func udpMultiNodeFixture(t *testing.T, secondaryEnabled bool) (*Client, *[2]atomic.Int64) {
	t.Helper()
	var opened [2]atomic.Int64
	var config *tls.Config
	var endpoints [2]string
	var pemFile string
	for i := range 2 {
		server := &Server{Username: "alice", Password: "secret", EnableUDP: secondaryEnabled || i == 0, AllowPrivate: true}
		index := i
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == udpStreamPath {
				opened[index].Add(1)
			}
			server.ServeHTTP(w, r)
		})
		httpServer := httptest.NewUnstartedServer(handler)
		httpServer.EnableHTTP2 = true
		if i == 0 {
			httpServer.TLS = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}}
		} else {
			httpServer.TLS = config.Clone()
		}
		httpServer.StartTLS()
		t.Cleanup(httpServer.Close)
		endpoints[i] = httpServer.URL
		if i == 0 {
			config = httpServer.TLS
			pemFile = filepath.Join(t.TempDir(), "shared-ingress.pem")
			cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: httpServer.Certificate().Raw})
			if err := os.WriteFile(pemFile, cert, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	c, err := NewClient(endpoints[0], "alice", "secret", pemFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	c.EnableUDP, c.UDPStreaming, c.UDPMultiNode = true, true, true
	c.ConnectTimeout = 6 * time.Second
	if err := c.SetFallbackServers([]string{endpoints[1]}); err != nil {
		t.Fatal(err)
	}
	return c, &opened
}

func TestUDPMultiNodeHTTP2FlowShardingAndReplies(t *testing.T) {
	testUDPMultiNodeHTTP2FlowShardingAndReplies(t, false)
}
func TestManagedHTTPUDPMultiNode(t *testing.T) { testUDPMultiNodeHTTP2FlowShardingAndReplies(t, true) }
func testUDPMultiNodeHTTP2FlowShardingAndReplies(t *testing.T, managed bool) {
	c, opened := udpMultiNodeFixture(t, true)
	if managed {
		installManagedHTTPFixture(t, c, "h2-connect")
	}
	targets := make([]*net.UDPConn, 0, 2)
	picked := map[int]bool{}
	for i := 0; i < 32 && len(picked) < 2; i++ {
		target := startUDPEcho(t)
		port := uint16(target.LocalAddr().(*net.UDPAddr).Port)
		index := udpIngressIndex("127.0.0.1", port, 2)
		if !picked[index] {
			targets = append(targets, target)
			picked[index] = true
		}
	}
	if len(targets) != 2 {
		t.Fatal("fixture did not exercise both exits")
	}
	control, bind, status := udpAssociation(t, c)
	defer control.Close()
	if status != 0 {
		t.Fatalf("SOCKS UDP association failed: %d", status)
	}
	local, err := net.DialUDP("udp4", nil, bind)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	_ = local.SetDeadline(time.Now().Add(8 * time.Second))
	for _, target := range targets {
		port := target.LocalAddr().(*net.UDPAddr).Port
		for n := 0; n < 3; n++ {
			data := []byte{byte(port >> 8), byte(port), byte(n)}
			wire, err := udpproto.Encode(udpproto.Packet{Host: "127.0.0.1", Port: uint16(port), Data: data})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := local.Write(wire); err != nil {
				t.Fatal(err)
			}
		}
	}
	got := make([]string, 0, 6)
	for len(got) < 6 {
		var buf [udpproto.MaxDatagram + 1]byte
		n, err := local.Read(buf[:])
		if err != nil {
			t.Fatal(err)
		}
		p, err := udpproto.Parse(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, string(p.Data))
	}
	var expected []string
	for _, target := range targets {
		port := target.LocalAddr().(*net.UDPAddr).Port
		for n := 0; n < 3; n++ {
			expected = append(expected, string([]byte{byte(port >> 8), byte(port), byte(n)}))
		}
	}
	slices.Sort(got)
	slices.Sort(expected)
	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("UDP corrupted, duplicated or dropped: got=%v expected=%v", got, expected)
		}
	}
	if opened[0].Load() == 0 || opened[1].Load() == 0 {
		t.Fatalf("not all explicitly trusted exits opened: %d / %d", opened[0].Load(), opened[1].Load())
	}
}

func TestUDPMultiNodeRefusesUntrustedSecondStreamWithoutDowngrade(t *testing.T) {
	c, opened := udpMultiNodeFixture(t, false)
	control, bind, status := udpAssociation(t, c)
	defer control.Close()
	if status != 0 {
		t.Fatalf("local SOCKS setup failed: %d", status)
	}
	target := startUDPEcho(t)
	local, err := net.DialUDP("udp4", nil, bind)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	_ = local.SetDeadline(time.Now().Add(500 * time.Millisecond))
	wire, err := udpproto.Encode(udpproto.Packet{Host: "127.0.0.1", Port: uint16(target.LocalAddr().(*net.UDPAddr).Port), Data: []byte("must-not-fallback")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := local.Write(wire); err != nil {
		t.Fatal(err)
	}
	var buf [udpproto.MaxDatagram + 1]byte
	n, err := local.Read(buf[:])
	if n > 0 || err == nil {
		t.Fatalf("UDP payload leaked through a partial trusted cluster: %d %v", n, err)
	}
	if opened[0].Load() == 0 || opened[1].Load() == 0 {
		t.Fatal("both ingress candidates were not checked")
	}
}

func TestUDPMultiNodeSourcePortPinAndMalformedPackets(t *testing.T) {
	c, _ := udpMultiNodeFixture(t, true)
	control, bind, status := udpAssociation(t, c)
	defer control.Close()
	if status != 0 {
		t.Fatalf("SOCKS refused: %d", status)
	}
	target := startUDPEcho(t)
	valid := udpproto.Packet{Host: "127.0.0.1", Port: uint16(target.LocalAddr().(*net.UDPAddr).Port), Data: []byte("good")}
	wire, err := udpproto.Encode(valid)
	if err != nil {
		t.Fatal(err)
	}
	a, err := net.DialUDP("udp4", nil, bind)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := net.DialUDP("udp4", nil, bind)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(350 * time.Millisecond))
	_, _ = a.Write(wire)
	var buf [udpproto.MaxDatagram + 1]byte
	n, err := a.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], wire) {
		t.Fatal("unexpected primary UDP reply")
	}
	_, _ = b.Write(wire)
	if n, err := b.Read(buf[:]); err == nil || n > 0 {
		t.Fatal("other local UDP port bypassed source pin")
	}
}
