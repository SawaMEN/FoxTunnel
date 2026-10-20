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
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

// The HTTP/2 exit intentionally sends a well-formed reply from the wrong
// destination with the requested port. A valid reply from the requested
// destination must still reach the local SOCKS UDP application.
func TestStage6UDPStreamDropsUnsolicitedRepliesOverH2(t *testing.T) {
	h := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != udpStreamPath || r.ProtoMajor != 2 {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Proxy-Authorization") == "" {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		flusher := w.(http.Flusher)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		wire, err := udpproto.ReadFrame(r.Body)
		if err != nil {
			return
		}
		requested, err := udpproto.Parse(wire)
		if err != nil {
			return
		}
		forged, err := udpproto.Encode(udpproto.Packet{
			Host: "127.0.0.2", Port: requested.Port, Data: []byte("forged"),
		})
		if err != nil {
			return
		}
		if err := udpproto.WriteFrame(w, forged); err != nil {
			return
		}
		flusher.Flush()
		if err := udpproto.WriteFrame(w, wire); err != nil {
			return
		}
		flusher.Flush()
		<-r.Context().Done()
	}))
	h.EnableHTTP2 = true
	h.TLS = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}}
	h.StartTLS()
	t.Cleanup(h.Close)
	pemFile := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(pemFile, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: h.Certificate().Raw,
	}), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(h.URL, "alice", "secret", pemFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	c.EnableUDP, c.UDPStreaming = true, true
	control, bind, code := udpAssociation(t, c)
	defer control.Close()
	if code != 0 {
		t.Fatalf("SOCKS UDP stream refused: %d", code)
	}
	local, err := net.DialUDP("udp4", nil, bind)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	wire, err := udpproto.Encode(udpproto.Packet{Host: "127.0.0.1", Port: 853, Data: []byte("real")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := local.Write(wire); err != nil {
		t.Fatal(err)
	}
	_ = local.SetReadDeadline(time.Now().Add(5 * time.Second))
	var buf [udpproto.MaxDatagram + 1]byte
	n, err := local.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], wire) {
		t.Fatalf("UDP Stream passed forged or corrupted reply: %x", buf[:n])
	}
	_ = local.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if n, err := local.Read(buf[:]); n != 0 || err == nil {
		t.Fatalf("unsolicited UDP frame was forwarded: %d %v", n, err)
	}
}
