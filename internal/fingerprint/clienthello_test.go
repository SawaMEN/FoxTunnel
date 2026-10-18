package fingerprint

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func realHello(t *testing.T) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer client.Close()
		c := tls.Client(client, &tls.Config{ServerName: "super-secret.example", NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS13})
		_ = c.Handshake()
	}()
	_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
	var record [5]byte
	if _, err := io.ReadFull(server, record[:]); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(binary.BigEndian.Uint16(record[3:])))
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
	<-done
	return append(record[:], body...)
}
func TestCaptureGoClientHello(t *testing.T) {
	b := realHello(t)
	h, err := ReadClientHello(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if h.LegacyVersion != 0x303 || !h.SNI || len(h.CipherSuites) == 0 || len(h.Extensions) == 0 || h.JA3 == "" {
		t.Fatalf("invalid TLS hello: %+v", h)
	}
	if !strings.Contains(strings.Join(h.ALPN, ","), "h2") {
		t.Fatalf("missing h2 ALPN: %v", h.ALPN)
	}
	if strings.Contains(h.JA3, "super-secret") {
		t.Fatal("leaked hostname")
	}
	// Split a handshake over two separate TLS records.
	first := b[5:]
	cut := len(first) / 2
	var fragment bytes.Buffer
	for _, part := range [][]byte{first[:cut], first[cut:]} {
		fragment.Write([]byte{22, 3, 1, byte(len(part) >> 8), byte(len(part))})
		fragment.Write(part)
	}
	got, err := ReadClientHello(&fragment)
	if err != nil {
		t.Fatal(err)
	}
	if got.JA3 != h.JA3 {
		t.Fatal("fragmentation changed parsed hello")
	}
}
func TestRejectMalformedHello(t *testing.T) {
	orig := realHello(t)
	for _, b := range [][]byte{orig[:2], append([]byte{23}, orig[1:]...), []byte{22, 3, 1, 0, 0}, []byte{22, 3, 1, 255, 255}, orig[:len(orig)-2]} {
		if _, err := ReadClientHello(bytes.NewReader(b)); err == nil {
			t.Fatal("accepted invalid ClientHello")
		}
	}
}
func TestGREASE(t *testing.T) {
	if !grease(0x0a0a) || !grease(0xfafa) || grease(0x1301) || grease(0x0a1a) {
		t.Fatal("invalid GREASE detection")
	}
	if got := nums([]uint16{0x0a0a, 4865, 4866, 0x1a1a}, true); got != "4865-4866" {
		t.Fatal(got)
	}
}
