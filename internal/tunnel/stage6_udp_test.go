package tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/VetroffProxy/internal/udpproto"
)

func TestStage6UDPReplyBindsDestination(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request string
		reply   string
		port    uint16
		ok      bool
	}{
		{"ipv4-match", "198.51.100.7", "198.51.100.7", 53, true},
		{"ipv4-mismatch", "198.51.100.7", "198.51.100.8", 53, false},
		{"ipv6-match", "2001:db8::7", "2001:db8::7", 53, true},
		{"ipv6-mismatch", "2001:db8::7", "2001:db8::8", 53, false},
		{"mapped-ipv4", "198.51.100.7", "::ffff:198.51.100.7", 53, true},
		{"hostname-resolved-at-exit", "dns.example", "198.51.100.7", 53, true},
		{"hostname-not-resolved", "dns.example", "other.example", 53, false},
		{"zone-in-response", "dns.example", "fe80::1%lo", 53, false},
		{"different-port", "198.51.100.7", "198.51.100.7", 123, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := udpproto.Packet{Host: tc.request, Port: 53}
			reply := udpproto.Packet{Host: tc.reply, Port: tc.port}
			if got := udpReplyMatchesRequest(request, reply); got != tc.ok {
				t.Fatalf("reply validation got=%v want=%v", got, tc.ok)
			}
		})
	}
}

func TestStage6UDPAssociateAndStreamRejectSpoofedAndMalformed(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		name := "one-shot"
		if streaming {
			name = "stream"
		}
		t.Run(name, func(t *testing.T) {
			target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			var received atomic.Int64
			go func() {
				var buf [udpproto.MaxDatagram + 1]byte
				for {
					n, from, err := target.ReadFromUDP(buf[:])
					if err != nil {
						return
					}
					received.Add(1)
					_, _ = target.WriteToUDP(buf[:n], from)
				}
			}()
			client, _ := udpFixture(t, &Server{Username: "alice", Password: "secret", EnableUDP: true, AllowPrivate: true})
			client.EnableUDP, client.UDPStreaming = true, streaming
			control, bind, status := udpAssociation(t, client)
			defer control.Close()
			if status != 0 || bind.Port == 0 {
				t.Fatalf("UDP association refused: status=%d bind=%v", status, bind)
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
			_ = a.SetDeadline(time.Now().Add(7 * time.Second))
			_ = b.SetReadDeadline(time.Now().Add(250 * time.Millisecond))

			wire, err := udpproto.Encode(udpproto.Packet{
				Host: "127.0.0.1", Port: uint16(target.LocalAddr().(*net.UDPAddr).Port),
				Data: []byte("valid"),
			})
			if err != nil {
				t.Fatal(err)
			}
			fragment := bytes.Clone(wire)
			fragment[2] = 1 // RFC 1928 FRAG != 0 is not supported.
			invalidAddress := bytes.Clone(wire)
			invalidAddress[3] = 9
			oversize := bytes.Repeat([]byte{0}, udpproto.MaxDatagram+1)
			for _, bad := range [][]byte{fragment, invalidAddress, oversize, {0, 0, 0}} {
				if _, err := b.Write(bad); err != nil {
					t.Fatal(err)
				}
			}
			// Invalid frames from another port must never pin the association.
			if _, err := a.Write(wire); err != nil {
				t.Fatal(err)
			}
			var buf [udpproto.MaxDatagram + 1]byte
			readReply := func() {
				t.Helper()
				n, err := a.Read(buf[:])
				if err != nil {
					t.Fatal(err)
				}
				packet, err := udpproto.Parse(buf[:n])
				if err != nil || packet.Host != "127.0.0.1" || !bytes.Equal(packet.Data, []byte("valid")) {
					t.Fatalf("unexpected UDP relay response: %+v %v", packet, err)
				}
			}
			readReply()

			// A different UDP source port on the same host cannot hijack the relay.
			if _, err := b.Write(wire); err != nil {
				t.Fatal(err)
			}
			if n, err := b.Read(buf[:]); err == nil || n > 0 {
				t.Fatal("unrecognized UDP port received response")
			}
			for _, bad := range [][]byte{fragment, invalidAddress, oversize} {
				if _, err := a.Write(bad); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := a.Write(wire); err != nil {
				t.Fatal(err)
			}
			readReply()
			// Wait until the echo target has accounted for the two valid
			// payloads. No malformed or spoofed packet may reach it.
			until := time.Now().Add(time.Second)
			for received.Load() < 2 && time.Now().Before(until) {
				time.Sleep(time.Millisecond)
			}
			if got := received.Load(); got != 2 {
				t.Fatalf("target received %d packets, want exactly 2 valid", got)
			}
		})
	}
}

func TestStage6UDPStreamMalformedFramesReleaseAdmission(t *testing.T) {
	valid, err := udpproto.Encode(udpproto.Packet{Host: "127.0.0.1", Port: 53, Data: []byte("hello")})
	if err != nil {
		t.Fatal(err)
	}
	fragment := bytes.Clone(valid)
	fragment[2] = 1
	invalidAddress := bytes.Clone(valid)
	invalidAddress[3] = 255
	oversized := make([]byte, 2)
	binary.BigEndian.PutUint16(oversized, udpproto.MaxDatagram+1)
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"zero-frame", []byte{0, 0}},
		{"oversized-frame", oversized},
		{"truncated-frame", append([]byte{0, byte(len(valid))}, valid[:3]...)},
		{"fragmented-datagram", append([]byte{0, byte(len(fragment))}, fragment...)},
		{"invalid-address", append([]byte{0, byte(len(invalidAddress))}, invalidAddress...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{Username: "alice", Password: "secret", EnableUDP: true, AllowPrivate: true, MaxTunnels: 1}
			r := httptest.NewRequest(http.MethodPost, "https://test.invalid"+udpStreamPath, bytes.NewReader(tc.wire))
			r.ProtoMajor = 2
			r.Header.Set("Proxy-Authorization", basicAuth("alice", "secret"))
			w := httptest.NewRecorder()
			var aborted any
			func() {
				defer func() { aborted = recover() }()
				s.ServeHTTP(w, r)
			}()
			if aborted != http.ErrAbortHandler {
				t.Fatalf("malformed frame did not abort response: %v", aborted)
			}
			if w.Code != http.StatusOK || s.activeTunnels.Load() != 0 {
				t.Fatalf("malformed streaming association failed to release slot: status=%d tunnels=%d", w.Code, s.activeTunnels.Load())
			}
			if raw, err := io.ReadAll(w.Result().Body); err != nil || len(raw) != 0 {
				t.Fatalf("unexpected malformed stream output %q %v", raw, err)
			}
		})
	}
}

func TestStage6UDPStreamingReplyGuardBoundedAndConcurrent(t *testing.T) {
	var guard udpReplyGuard
	reply := func(host string, port uint16) []byte {
		t.Helper()
		wire, err := udpproto.Encode(udpproto.Packet{Host: host, Port: port, Data: []byte("response")})
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	if guard.matches(reply("127.0.0.1", 53)) {
		t.Fatal("unsolicited stream reply was allowed")
	}
	guard.remember(udpproto.Packet{Host: "127.0.0.1", Port: 53})
	for _, tc := range []struct {
		host string
		port uint16
		want bool
	}{
		{"127.0.0.1", 53, true},
		{"127.0.0.2", 53, false},
		{"127.0.0.1", 54, false},
	} {
		if got := guard.matches(reply(tc.host, tc.port)); got != tc.want {
			t.Fatalf("unexpected stream reply acceptance %q:%d=%v", tc.host, tc.port, got)
		}
	}
	guard.remember(udpproto.Packet{Host: "dns.example", Port: 853})
	if !guard.matches(reply("2001:db8::17", 853)) {
		t.Fatal("hostname reply resolved at remote exit rejected")
	}
	for i := 0; i < maxUDPReplyDestinations+10; i++ {
		guard.remember(udpproto.Packet{Host: "127.0.0.1", Port: uint16(10000 + i)})
	}
	if len(guard.requests) != maxUDPReplyDestinations {
		t.Fatalf("UDP stream allowlist unbounded: %d", len(guard.requests))
	}
	if guard.matches(reply("127.0.0.1", 53)) {
		t.Fatal("evicted UDP destination can still receive replies")
	}

	// Two authenticated exits must not share the same allowlist.
	var other udpReplyGuard
	other.remember(udpproto.Packet{Host: "127.0.0.2", Port: 7000})
	if guard.matches(reply("127.0.0.2", 7000)) || other.matches(reply("127.0.0.1", 10063)) {
		t.Fatal("UDP multi-node replies crossed exit allowlists")
	}
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				port := uint16(20000 + worker*100 + j)
				guard.remember(udpproto.Packet{Host: "127.0.0.1", Port: port})
				if _, err := udpproto.Parse(reply("127.0.0.1", port)); err != nil {
					t.Error(err)
				}
			}
		}(i)
	}
	workers.Wait()
	if len(guard.requests) > maxUDPReplyDestinations {
		t.Fatal("concurrent requests exceeded bounded allowlist")
	}
}
