package udpproto

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for _, host := range []string{"1.1.1.1", "2001:4860:4860::8888", "dns.example"} {
		src := Packet{Host: host, Port: 53, Data: []byte{1, 2, 0, 3, 4}}
		buf, err := Encode(src)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(buf)
		if err != nil || got.Host != src.Host || got.Port != src.Port || !bytes.Equal(got.Data, src.Data) {
			t.Fatalf("%q roundtrip: %+v %v", host, got, err)
		}
	}
}
func TestMalformedPackets(t *testing.T) {
	ok, err := Encode(Packet{Host: "dns.example", Port: 53, Data: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	mutations := [][]byte{{}, {0, 0, 0, 1}}
	for i := 0; i < len(ok); i++ {
		if i == len(ok)-1 {
			continue
		}
		mutations = append(mutations, ok[:i])
	}
	for _, tc := range []struct {
		at  int
		val byte
	}{{0, 1}, {1, 1}, {2, 1}, {3, 9}, {4, 0}} {
		buf := append([]byte(nil), ok...)
		buf[tc.at] = tc.val
		mutations = append(mutations, buf)
	}
	for _, b := range mutations {
		if _, err := Parse(b); err == nil {
			t.Fatalf("accepted %v", b)
		}
	}
	if _, err := Parse(make([]byte, MaxDatagram+1)); err == nil {
		t.Fatal("oversize accepted")
	}
	for _, p := range []Packet{{Host: "foo", Port: 0, Data: []byte{1}},
		{Host: "ab\r\n", Port: 1, Data: []byte{1}},
		{Host: "example", Port: 53, Data: make([]byte, MaxDatagram)}} {
		if _, err := Encode(p); err == nil {
			t.Fatalf("encoded %+v", p)
		}
	}
}

func TestEmptyDatagramRoundTrip(t *testing.T) {
	for _, host := range []string{"198.18.0.9", "fd42:2::9", "echo.example"} {
		wire, err := Encode(Packet{Host: host, Port: 5656})
		if err != nil {
			t.Fatal(err)
		}
		var stream bytes.Buffer
		if err := WriteFrame(&stream, wire); err != nil {
			t.Fatal(err)
		}
		got, err := ReadFrame(&stream)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := Parse(got)
		if err != nil || packet.Host != host || packet.Port != 5656 || len(packet.Data) != 0 {
			t.Fatalf("empty datagram: %+v %v", packet, err)
		}
	}
}
