package tunnel

import (
	"bytes"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/access"
	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

func TestAccessUDPQuotaPreservesPacketsDirectAndCascade(t *testing.T) {
	for _, cascade := range []bool{false, true} {
		mode := "direct"
		if cascade {
			mode = "cascade"
		}
		for _, quota := range []int64{9, 10} {
			name := mode + "/insufficient"
			if quota == 10 {
				name = mode + "/exact"
			}
			t.Run(name, func(t *testing.T) {
				d := accessPolicy()
				d.Users[0].QuotaBytes = quota
				ctrl, err := access.New(d, "")
				if err != nil {
					t.Fatal(err)
				}
				defer ctrl.Close()
				server := &Server{Access: ctrl, AllowPrivate: true, EnableUDP: true}
				target := udpproto.Packet{Host: "8.8.8.8", Port: 443, Data: []byte("whole")}
				if cascade {
					server.Egress, _, _ = cascadeExit(t, false)
				} else {
					relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
					if err != nil {
						t.Fatal(err)
					}
					defer relay.Close()
					relay.SetDeadline(time.Now().Add(2 * time.Second))
					done := make(chan struct{})
					go func() {
						defer close(done)
						buf := make([]byte, 100)
						n, peer, err := relay.ReadFromUDP(buf)
						if err == nil {
							_, _ = relay.WriteToUDP(buf[:n], peer)
						}
					}()
					defer func() { relay.Close(); <-done }()
					target.Host = "127.0.0.1"
					target.Port = uint16(relay.LocalAddr().(*net.UDPAddr).Port)
				}
				wire, err := udpproto.Encode(target)
				if err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest("POST", "https://example.com"+udpPath, bytes.NewReader(wire))
				req.ProtoMajor = 2
				req.Header.Set("Proxy-Authorization", basicAuth("alice", accessAlice))
				rec := httptest.NewRecorder()
				server.ServeHTTP(rec, req)
				if quota == 9 {
					if rec.Code != 502 {
						t.Fatalf("partial UDP response accepted: status=%d body=%q", rec.Code, rec.Body.Bytes())
					}
					if got := ctrl.Snapshot().Users[0].Bytes; got != 5 {
						t.Fatal("usage", got)
					}
				} else {
					packet, err := udpproto.Parse(rec.Body.Bytes())
					if rec.Code != 200 || err != nil || !bytes.Equal(packet.Data, target.Data) {
						t.Fatalf("exact quota packet: status=%d packet=%v err=%v", rec.Code, packet, err)
					}
					if got := ctrl.Snapshot().Users[0].Bytes; got != 10 {
						t.Fatal("usage", got)
					}
				}
			})
		}
	}
}
