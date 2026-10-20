package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/buildinfo"
	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

type protocolUnreadBody struct{ reads int }

func (b *protocolUnreadBody) Read([]byte) (int, error) {
	b.reads++
	return 0, errors.New("body must not be read")
}
func (b *protocolUnreadBody) Close() error { return nil }

func TestProtocolRejectsBeforeDestination(t *testing.T) {
	cases := make(map[string]http.Header)
	cases["missing"] = http.Header{}
	cases["future"] = http.Header{protocolVersionHeader: {"foxtunnel-draft-999"}}
	cases["empty"] = http.Header{protocolVersionHeader: {""}}
	cases["duplicate"] = http.Header{protocolVersionHeader: {buildinfo.ProtocolDraft, buildinfo.ProtocolDraft}}
	cases["case-duplicate"] = http.Header{protocolVersionHeader: {buildinfo.ProtocolDraft}, "x-foxtunnel-version": {buildinfo.ProtocolDraft}}
	cases["capability-without-version"] = http.Header{protocolRequireHeader: {"tcp"}}
	cases["unknown-capability"] = http.Header{protocolVersionHeader: {buildinfo.ProtocolDraft}, protocolRequireHeader: {"future"}}
	cases["disabled-udp"] = http.Header{protocolVersionHeader: {buildinfo.ProtocolDraft}, protocolRequireHeader: {"udp-v1"}}
	cases["disabled-padding"] = http.Header{protocolVersionHeader: {buildinfo.ProtocolDraft}, protocolRequireHeader: {"padding-initial-v1"}}
	cases["duplicate-capability"] = http.Header{protocolVersionHeader: {buildinfo.ProtocolDraft}, protocolRequireHeader: {"tcp,tcp"}}
	cases["empty-capability"] = http.Header{protocolVersionHeader: {buildinfo.ProtocolDraft}, protocolRequireHeader: {""}}
	for label, header := range cases {
		t.Run(label, func(t *testing.T) {
			for _, path := range []string{postPath, udpPath, udpStreamPath} {
				server := &Server{Username: "alice", Password: "secret", RequireProtocolNegotiation: true}
				body := &protocolUnreadBody{}
				request := httptest.NewRequest(http.MethodPost, "https://example.org"+path, body)
				request.ProtoMajor = 2
				request.Header = header.Clone()
				request.Header.Set(targetHeader, "must-not-resolve.invalid:443")
				request.Header.Set("Proxy-Authorization", basicAuth("alice", "secret"))
				response := httptest.NewRecorder()
				server.ServeHTTP(response, request)
				want := http.StatusBadRequest
				if label == "missing" || label == "future" || label == "empty" {
					want = http.StatusUpgradeRequired
				}
				if response.Code != want || body.reads != 0 || server.activeTunnels.Load() != 0 {
					t.Fatalf("%s: code=%d want=%d reads=%d active=%d", path, response.Code, want, body.reads, server.activeTunnels.Load())
				}
			}
		})
	}
}

func TestProtocolUnauthenticatedUsesCover(t *testing.T) {
	var covered atomic.Int32
	server := &Server{Username: "alice", Password: "secret", RequireProtocolNegotiation: true, Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		covered.Add(1)
		for key := range r.Header {
			if len(key) >= len("X-FoxTunnel-") && key[:len("X-FoxTunnel-")] == "X-FoxTunnel-" {
				t.Error("wire header reached cover")
			}
		}
		w.WriteHeader(http.StatusNotFound)
	})}
	request := httptest.NewRequest(http.MethodPost, "https://example.org"+postPath, nil)
	request.ProtoMajor = 2
	request.Header.Set(protocolVersionHeader, "foxtunnel-draft-999")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != 404 || covered.Load() != 1 || response.Header().Get(protocolVersionHeader) != "" {
		t.Fatal("unauthenticated version information exposed", response.Code, response.Header())
	}
}

func TestProtocolStrictClientRejectsLegacyAndBadConfirmation(t *testing.T) {
	cases := make(map[string]http.Header)
	cases["legacy"] = http.Header{}
	cases["future"] = http.Header{protocolVersionHeader: {"foxtunnel-draft-999"}, protocolCapabilitiesHeader: {"tcp"}}
	cases["missing-capabilities"] = http.Header{protocolVersionHeader: {buildinfo.ProtocolDraft}}
	cases["wrong-capability"] = http.Header{protocolVersionHeader: {buildinfo.ProtocolDraft}, protocolCapabilitiesHeader: {"udp-v1"}}
	cases["duplicate-version"] = http.Header{protocolVersionHeader: {buildinfo.ProtocolDraft, buildinfo.ProtocolDraft}, protocolCapabilitiesHeader: {"tcp"}}
	cases["malformed-capabilities"] = http.Header{protocolVersionHeader: {buildinfo.ProtocolDraft}, protocolCapabilitiesHeader: {"tcp,tcp"}}
	for label, header := range cases {
		t.Run(label, func(t *testing.T) {
			var calls atomic.Int32
			client, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get(protocolVersionHeader) != buildinfo.ProtocolDraft || r.Header.Get(protocolRequireHeader) != "tcp" {
					t.Error("missing strict offer")
				}
				for key, values := range header {
					w.Header()[key] = values
				}
				w.WriteHeader(http.StatusOK)
			}))
			client.RequireProtocolNegotiation = true
			if err := client.SetFallbackServers([]string{"https://must-not-dial.invalid"}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, "tcp", "example.org:443")
			if conn != nil {
				conn.Close()
			}
			if !errors.Is(err, ErrProtocolNegotiation) || calls.Load() != 1 {
				t.Fatal("negotiation failure was accepted or retried", calls.Load(), err)
			}
		})
	}
}

func TestProtocolLegacyClientPolicy(t *testing.T) {
	for _, strictServer := range []bool{false, true} {
		server := &Server{Username: "alice", Password: "secret", RequireProtocolNegotiation: strictServer, AllowPrivate: true}
		client, _ := udpFixture(t, server)
		target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err := client.DialContext(ctx, "tcp", target)
		cancel()
		if strictServer {
			if err == nil {
				conn.Close()
				t.Fatal("strict server accepted legacy request")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
		}
	}
}

func TestProtocolStrictUDP(t *testing.T) {
	server := &Server{Username: "alice", Password: "secret", RequireProtocolNegotiation: true, AllowPrivate: true, EnableUDP: true}
	client, _ := udpFixture(t, server)
	client.RequireProtocolNegotiation = true
	target := startUDPEcho(t)
	wire, err := udpproto.Encode(udpproto.Packet{Host: "127.0.0.1", Port: uint16(target.LocalAddr().(*net.UDPAddr).Port), Data: []byte("negotiated UDP")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	reply, err := client.exchangeUDP(ctx, wire)
	if err != nil || !bytes.Equal(reply, wire) {
		t.Fatal("one-shot UDP", err, reply)
	}
	stream, err := client.openUDPStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.close()
	if err = udpproto.WriteFrame(stream.writer, wire); err != nil {
		t.Fatal(err)
	}
	reply, err = udpproto.ReadFrame(stream.response)
	if err != nil || !bytes.Equal(reply, wire) {
		t.Fatal("stream UDP", err, reply)
	}
}

func FuzzProtocolTokens(f *testing.F) {
	for _, seed := range []string{"tcp", "udp-v1,udp-stream-v2", "tcp,tcp", "", "tcp, padding-initial-v1", "tcp\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		tokens, ok := protocolTokens(value)
		if ok && (len(tokens) == 0 || len(tokens) > 8 || len(value) > 256) {
			t.Fatal("unbounded capabilities accepted")
		}
	})
}
