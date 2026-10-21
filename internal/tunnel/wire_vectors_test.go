package tunnel

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/SawaMEN/FoxTunnel/internal/authheader"
	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

type wireVector struct {
	Name       string
	Hex        string
	Valid      bool
	Host       string
	Port       uint16
	PayloadHex string `json:"payload_hex"`
	PacketHex  string `json:"packet_hex"`
}

type authVector struct {
	Value    string
	Valid    bool
	Username string
	Password string
}

func TestWireDraftVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/wire-draft-0.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Schema         int
		Protocol       string
		Authentication []authVector
		Datagrams      []wireVector
		Frames         []wireVector
		Padding        []wireVector
	}
	if err = json.Unmarshal(data, &vectors); err != nil || vectors.Schema != 1 || vectors.Protocol != "foxtunnel-draft-0" {
		t.Fatal("invalid vector manifest", err)
	}
	decode := func(value string) []byte {
		t.Helper()
		wire, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	for _, vector := range vectors.Authentication {
		h := make(http.Header)
		h.Set("Proxy-Authorization", vector.Value)
		name, secret, ok := authheader.Parse(h)
		if ok != vector.Valid || (ok && (name != vector.Username || secret != vector.Password)) {
			t.Fatal("authentication vector", vector.Value)
		}
	}
	for _, vector := range vectors.Datagrams {
		t.Run("datagram/"+vector.Name, func(t *testing.T) {
			packet, err := udpproto.Parse(decode(vector.Hex))
			if (err == nil) != vector.Valid {
				t.Fatal("unexpected validity", err)
			}
			if !vector.Valid {
				return
			}
			if packet.Host != vector.Host || packet.Port != vector.Port || !bytes.Equal(packet.Data, decode(vector.PayloadHex)) {
				t.Fatal("decoded fields differ", packet)
			}
			wire, err := udpproto.Encode(packet)
			if err != nil || !bytes.Equal(wire, decode(vector.Hex)) {
				t.Fatal("encoder differs from vector", err)
			}
		})
	}
	for _, vector := range vectors.Frames {
		t.Run("frame/"+vector.Name, func(t *testing.T) {
			packet, err := udpproto.ReadFrame(bytes.NewReader(decode(vector.Hex)))
			if (err == nil) != vector.Valid {
				t.Fatal("unexpected validity", err)
			}
			if vector.Valid {
				if !bytes.Equal(packet, decode(vector.PacketHex)) {
					t.Fatal("decoded frame differs")
				}
				var out bytes.Buffer
				if err = udpproto.WriteFrame(&out, packet); err != nil || !bytes.Equal(out.Bytes(), decode(vector.Hex)) {
					t.Fatal("encoded frame differs", err)
				}
			}
		})
	}
	for _, vector := range vectors.Padding {
		t.Run("padding/"+vector.Name, func(t *testing.T) {
			payload, err := io.ReadAll(newPaddingReader(bytes.NewReader(decode(vector.Hex))))
			if (err == nil) != vector.Valid || (vector.Valid && !bytes.Equal(payload, decode(vector.PayloadHex))) {
				t.Fatal("padding vector", err)
			}
		})
	}
}

func TestWireShortDomainMaximumDatagram(t *testing.T) {
	for _, host := range []string{"a", "ab", "example.org", "127.0.0.1", "::1"} {
		header, err := udpproto.Encode(udpproto.Packet{Host: host, Port: 53})
		if err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte{0x7f}, udpproto.MaxDatagram-len(header))
		wire, err := udpproto.Encode(udpproto.Packet{Host: host, Port: 53, Data: payload})
		if err != nil || len(wire) != udpproto.MaxDatagram {
			t.Fatal("maximum datagram rejected", host, err)
		}
		packet, err := udpproto.Parse(wire)
		if err != nil || !bytes.Equal(packet.Data, payload) {
			t.Fatal("maximum datagram failed round trip", host, err)
		}
		if _, err = udpproto.Encode(udpproto.Packet{Host: host, Port: 53, Data: append(payload, 0)}); err == nil {
			t.Fatal("oversize datagram accepted", host)
		}
	}
}
