package tunnel

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

func udpFixture(t *testing.T, server *Server) (*Client, string) {
	t.Helper()
	h := httptest.NewUnstartedServer(server)
	h.EnableHTTP2 = true
	h.TLS = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}}
	h.StartTLS()
	t.Cleanup(h.Close)
	pemFile := filepath.Join(t.TempDir(), "server.pem")
	if err := os.WriteFile(pemFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(h.URL, "alice", "secret", pemFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, h.URL
}

func startUDPEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	go func() {
		data := make([]byte, 2048)
		for {
			n, peer, err := s.ReadFromUDP(data)
			if err != nil {
				return
			}
			_, _ = s.WriteToUDP(data[:n], peer)
		}
	}()
	return s
}
func udpAssociation(t *testing.T, c *Client) (net.Conn, *net.UDPAddr, byte) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() { _ = c.Serve(listener) }()
	control, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { control.Close() })
	_ = control.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := control.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if head, err := readN(control, 2); err != nil || !bytes.Equal(head, []byte{5, 0}) {
		t.Fatalf("SOCKS greeting %v %v", head, err)
	}
	// UDP ASSOCIATE 0.0.0.0:0
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	head, err := readN(control, 4)
	if err != nil {
		t.Fatal(err)
	}
	var ip net.IP
	switch head[3] {
	case 1:
		b, e := readN(control, 4)
		if e != nil {
			t.Fatal(e)
		}
		ip = net.IP(b)
	case 4:
		b, e := readN(control, 16)
		if e != nil {
			t.Fatal(e)
		}
		ip = net.IP(b)
	default:
		t.Fatalf("invalid UDP bind response %v", head)
	}
	portData, e := readN(control, 2)
	if e != nil {
		t.Fatal(e)
	}
	return control, &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(portData))}, head[1]
}
func readN(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func TestUDPAssociateH2RoundTrip(t *testing.T) {
	target := startUDPEcho(t)
	c, _ := udpFixture(t, &Server{Username: "alice", Password: "secret", EnableUDP: true, AllowPrivate: true})
	c.EnableUDP = true
	ctrl, bind, status := udpAssociation(t, c)
	defer ctrl.Close()
	if status != 0 || bind.Port == 0 {
		t.Fatalf("UDP association refused: code=%d bind=%s", status, bind)
	}
	udp, err := net.DialUDP("udp4", nil, bind)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(4 * time.Second))
	payload := []byte("FoxTunnel UDP query / response")
	wire, err := udpproto.Encode(udpproto.Packet{Host: "127.0.0.1", Port: uint16(target.LocalAddr().(*net.UDPAddr).Port), Data: payload})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udp.Write(wire); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, udpproto.MaxDatagram+1)
	n, err := udp.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	p, err := udpproto.Parse(buf[:n])
	if err != nil || p.Host != "127.0.0.1" || !bytes.Equal(p.Data, payload) {
		t.Fatalf("UDP echo %+v err=%v", p, err)
	}
}
func TestUDPAssociationOptInAndPolicy(t *testing.T) {
	c, _ := udpFixture(t, &Server{Username: "alice", Password: "secret", EnableUDP: true, AllowPrivate: true})
	_, _, status := udpAssociation(t, c)
	if status != 7 {
		t.Fatalf("UDP must be off on client by default; code %d", status)
	}
	c.EnableUDP = true
	// The server can refuse UDP independently without changing CONNECT behavior.
	c2, _ := udpFixture(t, &Server{Username: "alice", Password: "secret", AllowPrivate: true})
	c2.EnableUDP = true
	_, bind, status := udpAssociation(t, c2)
	if status != 0 || bind.Port == 0 {
		t.Fatalf("association should bind locally before remote capability check: %d", status)
	}
}

func TestUDPServerRejectsMalformedAndPrivate(t *testing.T) {
	s := &Server{Username: "alice", Password: "secret", EnableUDP: true}
	req := httptest.NewRequest("POST", "https://example.com"+udpPath, bytes.NewReader([]byte{1, 2, 3}))
	req.ProtoMajor = 2
	req.Header.Set("Proxy-Authorization", basicAuth("alice", "secret"))
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("invalid packet returned %d", rec.Code)
	}
	wire, err := udpproto.Encode(udpproto.Packet{Host: "127.0.0.1", Port: 53, Data: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("POST", "https://example.com"+udpPath, bytes.NewReader(wire))
	req.ProtoMajor = 2
	req.Header.Set("Proxy-Authorization", basicAuth("alice", "secret"))
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 502 {
		t.Fatalf("private UDP should fail before sending: %d", rec.Code)
	}
	req = httptest.NewRequest("POST", "https://example.com"+udpPath, bytes.NewReader(wire))
	req.ProtoMajor = 2
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatalf("unauthenticated UDP must look like public site, got %d", rec.Code)
	}
	req = httptest.NewRequest("POST", "https://example.com"+udpPath, bytes.NewReader(bytes.Repeat([]byte{0}, udpproto.MaxDatagram+1)))
	req.ProtoMajor = 2
	req.Header.Set("Proxy-Authorization", basicAuth("alice", "secret"))
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 413 {
		t.Fatalf("overlimit UDP should fail, got %d", rec.Code)
	}
}
