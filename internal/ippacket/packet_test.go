package ippacket

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"
)

func IPv4(src, dst string) []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	a, b := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(p[12:16], a[:])
	copy(p[16:20], b[:])
	binary.BigEndian.PutUint16(p[24:26], 8)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	return p
}
func TestFramingAndEnvelope(t *testing.T) {
	p := IPv4("100.96.0.2", "9.9.9.9")
	var b bytes.Buffer
	s := Stream{Reader: &b, Writer: &b}
	for range 2 {
		if err := s.WritePacket(p); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		var buf [MTU]byte
		n, err := s.ReadPacket(buf[:])
		if err != nil || !bytes.Equal(p, buf[:n]) {
			t.Fatal(n, err)
		}
		src, dst, err := Addresses(buf[:n])
		if err != nil || src.String() != "100.96.0.2" || dst.String() != "9.9.9.9" {
			t.Fatal(src, dst, err)
		}
	}
	if _, err := s.ReadPacket(make([]byte, MTU)); err != io.EOF {
		t.Fatal(err)
	}
	for _, data := range [][]byte{{0, 19}, {0xff, 0xff}, {0, 28, 1, 2}} {
		s := Stream{Reader: bytes.NewReader(data)}
		if _, err := s.ReadPacket(make([]byte, MTU)); err == nil {
			t.Fatal("accepted malformed frame")
		}
	}
	for _, mutate := range []func([]byte){func(p []byte) { p[0] = 0x46 }, func(p []byte) { p[8] = 0 }, func(p []byte) { p[2] = 1 }, func(p []byte) { p[10] ^= 1 }, func(p []byte) { p[9] = 47 }} {
		bad := bytes.Clone(p)
		mutate(bad)
		if _, _, err := Addresses(bad); err == nil {
			t.Fatal("accepted malformed IPv4")
		}
	}
	v6 := make([]byte, 48)
	v6[0] = 0x60
	v6[5] = 8
	v6[6] = 17
	v6[7] = 64
	a := netip.MustParseAddr("fd62:666f:78::2").As16()
	b6 := netip.MustParseAddr("2620:fe::fe").As16()
	copy(v6[8:24], a[:])
	copy(v6[24:40], b6[:])
	if _, _, err := Addresses(v6); err != nil {
		t.Fatal(err)
	}
	v6[6] = 43
	if _, _, err := Addresses(v6); err == nil {
		t.Fatal("accepted IPv6 routing header")
	}
}
func FuzzEnvelope(f *testing.F) {
	f.Add(IPv4("100.96.0.2", "9.9.9.9"))
	f.Fuzz(func(t *testing.T, p []byte) {
		Addresses(p)
		s := Stream{Reader: bytes.NewReader(p)}
		s.ReadPacket(make([]byte, MTU))
	})
}
