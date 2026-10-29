package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"testing"

	"github.com/SawaMEN/VetroffProxy/internal/udpproto"
)

type udpManagedFixture struct {
	seen  [][]byte
	reply []byte
	err   error
}

func (m *udpManagedFixture) Ready(context.Context) error { return nil }
func (m *udpManagedFixture) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected managed TCP")
}
func (m *udpManagedFixture) Close() error { return nil }
func (m *udpManagedFixture) ExchangeUDP(_ context.Context, p []byte) ([]byte, error) {
	m.seen = append(m.seen, append([]byte(nil), p...))
	return m.reply, m.err
}

func TestManagedUDPUsesNativeAdapterInsteadOfGo(t *testing.T) {
	packet, err := udpproto.Encode(udpproto.Packet{Host: "127.0.0.1", Port: 53, Data: []byte("hello")})
	if err != nil {
		t.Fatal(err)
	}
	m := &udpManagedFixture{reply: packet}
	c, err := NewClient("https://127.0.0.1:8443", "user", "password", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetManagedTransport("h2-connect", func() (ManagedTransport, error) { return m, nil })
	c.EnableUDP = true
	actual, err := c.exchangeUDP(context.Background(), packet)
	if err != nil || !bytes.Equal(actual, packet) || len(m.seen) != 1 ||
		!bytes.Equal(m.seen[0], packet) {
		t.Fatalf("native UDP adapter not selected: got %x, error %v", actual, err)
	}
	m.reply = []byte{1, 2, 3}
	if _, err := c.exchangeUDP(context.Background(), packet); err == nil {
		t.Fatal("malformed Necko UDP response must not be accepted")
	}
}

func TestManagedUDPFailClosedOnUnsupportedModes(t *testing.T) {
	for _, tt := range []struct {
		mode   string
		stream bool
	}{
		{"h3-connect", false}, {"h2-connect", true},
	} {
		c, err := NewClient("https://127.0.0.1:8443", "user", "password", "")
		if err != nil {
			t.Fatal(err)
		}
		c.SetManagedTransport(tt.mode, func() (ManagedTransport, error) { return &udpManagedFixture{}, nil })
		c.EnableUDP = true
		c.UDPStreaming = tt.stream
		if err := c.Prepare(context.Background()); err == nil {
			t.Fatalf("%s streaming=%v unexpectedly permitted", tt.mode, tt.stream)
		}
		c.Close()
	}
}

type mockManagedStream struct {
	udpManagedFixture
	stream io.ReadWriteCloser
}

func (m *mockManagedStream) OpenUDPStream(context.Context) (io.ReadWriteCloser, error) {
	return m.stream, nil
}

func TestManagedUDPStreamingBridgeNoGoFallback(t *testing.T) {
	c, err := NewClient("https://127.0.0.1:8443", "u", "p", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	local, remote := net.Pipe()
	defer remote.Close()
	bridge := &mockManagedStream{stream: local}
	c.SetManagedTransport("h2-connect", func() (ManagedTransport, error) { return bridge, nil })
	// The interface is independently testable; enabling real managed UDP
	// streaming remains rejected until native Gecko implements this channel.
	stream, err := c.openManagedUDPStream(context.Background(), c.ServerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.close()
	wire, err := udpproto.Encode(udpproto.Packet{Host: "127.0.0.1", Port: 53, Data: []byte{0, 255}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		got, err := udpproto.ReadFrame(remote)
		if err != nil {
			done <- err
			return
		}
		if !bytes.Equal(wire, got) {
			done <- errors.New("wrong framed request")
			return
		}
		done <- udpproto.WriteFrame(remote, got)
	}()
	if err := udpproto.WriteFrame(stream.writer, wire); err != nil {
		t.Fatal(err)
	}
	got, err := udpproto.ReadFrame(stream.response)
	if err != nil || !bytes.Equal(got, wire) {
		t.Fatalf("managed framed streaming: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	other, _ := url.Parse("https://other.invalid")
	if _, err := c.openManagedUDPStream(context.Background(), other); err == nil {
		t.Fatal("managed UDP may not switch HTTPS exit")
	}
}

func TestManagedUDPStreamingWithoutNativeChannelFailsClosed(t *testing.T) {
	c, err := NewClient("https://127.0.0.1:8443", "u", "p", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetManagedTransport("h2-connect", func() (ManagedTransport, error) { return &udpManagedFixture{}, nil })
	if _, err := c.openManagedUDPStream(context.Background(), c.ServerURL); err == nil {
		t.Fatal("unsupported Necko streaming must fail, not use Go transport")
	}
}
