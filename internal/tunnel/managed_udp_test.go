package tunnel

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
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
