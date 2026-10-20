// Package udpproto implements bounded SOCKS5 UDP datagrams (RFC 1928).
// It is used for one-shot HTTPS UDP relay, not for native QUIC datagrams.
package udpproto

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const MaxDatagram = 1232

var ErrPacket = errors.New("invalid or fragmented SOCKS5 UDP datagram")

// Packet preserves an original destination hostname for remote resolution.
type Packet struct {
	Host string
	Port uint16
	Data []byte
}

func Parse(b []byte) (Packet, error) {
	if len(b) < 8 || len(b) > MaxDatagram || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return Packet{}, ErrPacket
	}
	var p Packet
	offset := 4
	switch b[3] {
	case 1:
		if len(b) < offset+4+2 {
			return Packet{}, ErrPacket
		}
		a, ok := netip.AddrFromSlice(b[offset : offset+4])
		if !ok {
			return Packet{}, ErrPacket
		}
		p.Host = a.String()
		offset += 4
	case 4:
		if len(b) < offset+16+2 {
			return Packet{}, ErrPacket
		}
		a, ok := netip.AddrFromSlice(b[offset : offset+16])
		if !ok {
			return Packet{}, ErrPacket
		}
		p.Host = a.String()
		offset += 16
	case 3:
		if len(b) < offset+1 {
			return Packet{}, ErrPacket
		}
		n := int(b[offset])
		offset++
		if n == 0 || len(b) < offset+n+2 {
			return Packet{}, ErrPacket
		}
		p.Host = string(b[offset : offset+n])
		if strings.ContainsAny(p.Host, "\x00\r\n\t /\\@?#") {
			return Packet{}, ErrPacket
		}
		offset += n
	default:
		return Packet{}, ErrPacket
	}
	p.Port = binary.BigEndian.Uint16(b[offset : offset+2])
	if p.Port == 0 {
		return Packet{}, ErrPacket
	}
	p.Data = b[offset+2:]
	return p, nil
}

func Encode(p Packet) ([]byte, error) {
	if p.Port == 0 || len(p.Data) > MaxDatagram {
		return nil, ErrPacket
	}
	b := []byte{0, 0, 0}
	if a, err := netip.ParseAddr(p.Host); err == nil {
		a = a.Unmap()
		if a.Is4() {
			b = append(b, 1)
		} else {
			b = append(b, 4)
		}
		b = append(b, a.AsSlice()...)
	} else {
		if len(p.Host) == 0 || len(p.Host) > 255 || strings.ContainsAny(p.Host, "\x00\r\n\t /\\@?#") {
			return nil, ErrPacket
		}
		b = append(b, 3, byte(len(p.Host)))
		b = append(b, p.Host...)
	}
	b = binary.BigEndian.AppendUint16(b, p.Port)
	if len(b)+len(p.Data) > MaxDatagram {
		return nil, ErrPacket
	}
	return append(b, p.Data...), nil
}

func (p Packet) Target() string {
	return net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port)))
}
