// Package ippacket frames IP packets on a reliable, authenticated byte stream.
// It adds no encryption or implicit replay. It is not RFC 9298 CONNECT-UDP.
package ippacket

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sync"
)

const Version = "ip-v1"
const Authority = "ip.foxtunnel.invalid:1"
const Header = "X-FoxTunnel-Network"
const MTU = 1280

var ErrPacket = errors.New("invalid IP packet")

// A fixed MTU bounds every allocation and write. No packet length truncation.
type Stream struct {
	Reader io.Reader
	Writer io.Writer
	mu     sync.Mutex
	readMu sync.Mutex
}

func (s *Stream) ReadPacket(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	var h [2]byte
	if _, err := io.ReadFull(s.Reader, h[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n < 20 || n > MTU || n > len(p) {
		return 0, ErrPacket
	}
	_, err := io.ReadFull(s.Reader, p[:n])
	return n, err
}
func (s *Stream) WritePacket(p []byte) error {
	if len(p) < 20 || len(p) > MTU {
		return ErrPacket
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var frame [MTU + 2]byte
	binary.BigEndian.PutUint16(frame[:2], uint16(len(p)))
	copy(frame[2:], p)
	data := frame[:len(p)+2]
	for len(data) > 0 {
		n, err := s.Writer.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// Addresses validates the envelope before any packet reaches a kernel TUN.
// Routing/option headers and IPv4 options are rejected. Normal IP fragments
// retain the same pinned source/destination policy; no transport parsing occurs.
func Addresses(p []byte) (src, dst netip.Addr, err error) {
	if len(p) < 20 || len(p) > MTU {
		return src, dst, ErrPacket
	}
	switch p[0] >> 4 {
	case 4:
		if p[0] != 0x45 || int(binary.BigEndian.Uint16(p[2:4])) != len(p) || p[8] == 0 || p[6]&0x80 != 0 {
			return src, dst, ErrPacket
		}
		if p[9] != 6 && p[9] != 17 && p[9] != 1 {
			return src, dst, ErrPacket
		}
		var sum uint32
		for i := 0; i < 20; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
		}
		for sum>>16 != 0 {
			sum = (sum & 0xffff) + (sum >> 16)
		}
		if sum != 0xffff {
			return src, dst, ErrPacket
		}
		src = netip.AddrFrom4([4]byte(p[12:16]))
		dst = netip.AddrFrom4([4]byte(p[16:20]))
	case 6:
		if len(p) < 40 || int(binary.BigEndian.Uint16(p[4:6]))+40 != len(p) || p[7] == 0 {
			return src, dst, ErrPacket
		}
		next := p[6]
		if next == 44 {
			if len(p) < 48 || p[41] != 0 {
				return src, dst, ErrPacket
			}
			next = p[40]
		}
		if next != 6 && next != 17 && next != 58 {
			return src, dst, ErrPacket
		}
		src = netip.AddrFrom16([16]byte(p[8:24]))
		dst = netip.AddrFrom16([16]byte(p[24:40]))
	default:
		return src, dst, ErrPacket
	}
	if src.Is4In6() || dst.Is4In6() || !src.IsGlobalUnicast() || !dst.IsGlobalUnicast() {
		return src, dst, ErrPacket
	}
	return src, dst, nil
}
func Public(ip netip.Addr) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "fc00::/7"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return true
}
