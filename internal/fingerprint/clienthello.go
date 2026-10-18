// Package fingerprint extracts non-secret TLS ClientHello metadata for
// controlled interoperability research. It does not act as a TLS endpoint.
package fingerprint

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/SawaMEN/FoxTunnel/internal/i18n"
	"io"
	"strconv"
	"strings"
)

const maxHandshake = 64 << 10

// Hello deliberately excludes client random, session ID, SNI hostname and key bytes.
// JA3 is a compatibility fingerprint, NOT a cryptographic checksum or security check.
type Hello struct {
	RecordVersion       uint16   `json:"record_version"`
	LegacyVersion       uint16   `json:"legacy_version"`
	CipherSuites        []uint16 `json:"cipher_suites"`
	Extensions          []uint16 `json:"extensions"`
	SupportedGroups     []uint16 `json:"supported_groups,omitempty"`
	ECPointFormats      []int    `json:"ec_point_formats,omitempty"`
	SupportedVersions   []uint16 `json:"supported_versions,omitempty"`
	SignatureAlgorithms []uint16 `json:"signature_algorithms,omitempty"`
	KeyShareGroups      []uint16 `json:"key_share_groups,omitempty"`
	ALPN                []string `json:"alpn,omitempty"`
	SNI                 bool     `json:"sni_present"`
	JA3                 string   `json:"ja3"`
	JA3MD5              string   `json:"ja3_md5"`
}

// ReadClientHello accepts TLS handshake records split across multiple TLS
// records, limiting both record size and handshake memory use.
func ReadClientHello(r io.Reader) (Hello, error) {
	var message []byte
	var recordVersion uint16
	total := -1
	for {
		var h [5]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return Hello{}, fmt.Errorf(i18n.Text("TLS record header: %w"), err)
		}
		if h[0] != 22 {
			return Hello{}, errors.New(i18n.Text("expected TLS handshake record"))
		}
		n := int(binary.BigEndian.Uint16(h[3:]))
		if n == 0 || n > 16384+2048 {
			return Hello{}, errors.New(i18n.Text("invalid TLS record length"))
		}
		if len(message)+n > maxHandshake+4 {
			return Hello{}, errors.New(i18n.Text("ClientHello exceeds 64 KiB"))
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return Hello{}, fmt.Errorf(i18n.Text("TLS record body: %w"), err)
		}
		if len(message) == 0 {
			recordVersion = binary.BigEndian.Uint16(h[1:3])
		}
		message = append(message, body...)
		if len(message) >= 4 && total < 0 {
			if message[0] != 1 {
				return Hello{}, errors.New(i18n.Text("first handshake message is not ClientHello"))
			}
			total = int(message[1])<<16 | int(message[2])<<8 | int(message[3])
			if total > maxHandshake {
				return Hello{}, errors.New(i18n.Text("ClientHello exceeds 64 KiB"))
			}
		}
		if total >= 0 && len(message) >= total+4 {
			return ParseClientHello(recordVersion, message[:total+4])
		}
	}
}

type cursor struct{ b []byte }

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || n > len(c.b) {
		return nil, io.ErrUnexpectedEOF
	}
	p := c.b[:n]
	c.b = c.b[n:]
	return p, nil
}
func (c *cursor) u8() (byte, error) {
	b, e := c.take(1)
	if e != nil {
		return 0, e
	}
	return b[0], nil
}
func (c *cursor) u16() (uint16, error) {
	b, e := c.take(2)
	if e != nil {
		return 0, e
	}
	return binary.BigEndian.Uint16(b), nil
}
func (c *cursor) vec8() ([]byte, error) {
	n, e := c.u8()
	if e != nil {
		return nil, e
	}
	return c.take(int(n))
}
func (c *cursor) vec16() ([]byte, error) {
	n, e := c.u16()
	if e != nil {
		return nil, e
	}
	return c.take(int(n))
}
func words(b []byte) ([]uint16, error) {
	if len(b)%2 != 0 {
		return nil, errors.New(i18n.Text("odd 16-bit vector length"))
	}
	r := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		r = append(r, binary.BigEndian.Uint16(b[i:]))
	}
	return r, nil
}

// ParseClientHello parses exactly one TLS handshake message (type + 24-bit len).
func ParseClientHello(recordVersion uint16, msg []byte) (Hello, error) {
	var h Hello
	if len(msg) < 4 || msg[0] != 1 || len(msg)-4 != int(msg[1])<<16|int(msg[2])<<8|int(msg[3]) {
		return h, errors.New(i18n.Text("invalid ClientHello frame"))
	}
	h.RecordVersion = recordVersion
	c := cursor{msg[4:]}
	version, e := c.u16()
	if e != nil {
		return h, e
	}
	h.LegacyVersion = version
	if _, e = c.take(32); e != nil {
		return h, e
	}
	sid, e := c.vec8()
	if e != nil || len(sid) > 32 {
		return h, errors.New(i18n.Text("invalid session id"))
	}
	cipher, e := c.vec16()
	if e != nil || len(cipher) == 0 {
		return h, errors.New(i18n.Text("invalid cipher suites"))
	}
	h.CipherSuites, e = words(cipher)
	if e != nil {
		return h, e
	}
	compression, e := c.vec8()
	if e != nil || len(compression) == 0 {
		return h, errors.New(i18n.Text("invalid compression methods"))
	}
	if len(c.b) == 0 {
		return h, errors.New(i18n.Text("missing extensions"))
	}
	ext, e := c.vec16()
	if e != nil || len(c.b) != 0 {
		return h, errors.New(i18n.Text("invalid extension block"))
	}
	ec := cursor{ext}
	for len(ec.b) > 0 {
		typ, err := ec.u16()
		if err != nil {
			return h, err
		}
		data, err := ec.vec16()
		if err != nil {
			return h, err
		}
		h.Extensions = append(h.Extensions, typ)
		sub := cursor{data}
		switch typ {
		case 0:
			h.SNI = true // Never collect the hostname itself.
		case 10, 13:
			b, err := sub.vec16()
			if err != nil || len(sub.b) != 0 {
				return h, errors.New(i18n.Text("bad supported-groups/signature-algorithms extension"))
			}
			v, err := words(b)
			if err != nil {
				return h, err
			}
			if typ == 10 {
				h.SupportedGroups = v
			} else {
				h.SignatureAlgorithms = v
			}
		case 11:
			b, err := sub.vec8()
			if err != nil || len(sub.b) != 0 {
				return h, errors.New(i18n.Text("bad EC point formats extension"))
			}
			for _, point := range b {
				h.ECPointFormats = append(h.ECPointFormats, int(point))
			}
		case 16:
			b, err := sub.vec16()
			if err != nil || len(sub.b) != 0 {
				return h, errors.New(i18n.Text("bad ALPN extension"))
			}
			a := cursor{b}
			for len(a.b) > 0 {
				p, err := a.vec8()
				if err != nil || len(p) == 0 {
					return h, errors.New(i18n.Text("bad ALPN protocol"))
				}
				h.ALPN = append(h.ALPN, string(p))
			}
		case 43:
			b, err := sub.vec8()
			if err != nil || len(sub.b) != 0 {
				return h, errors.New(i18n.Text("bad supported versions"))
			}
			h.SupportedVersions, err = words(b)
			if err != nil {
				return h, err
			}
		case 51:
			b, err := sub.vec16()
			if err != nil || len(sub.b) != 0 {
				return h, errors.New(i18n.Text("bad key shares"))
			}
			a := cursor{b}
			for len(a.b) > 0 {
				group, err := a.u16()
				if err != nil {
					return h, err
				}
				key, err := a.vec16()
				if err != nil || len(key) == 0 {
					return h, errors.New(i18n.Text("bad key share"))
				}
				h.KeyShareGroups = append(h.KeyShareGroups, group)
			}
		}
	}
	h.JA3 = ja3(h)
	sum := md5.Sum([]byte(h.JA3))
	h.JA3MD5 = hex.EncodeToString(sum[:])
	return h, nil
}

func grease(n uint16) bool { return byte(n>>8) == byte(n) && byte(n)&0x0f == 0x0a }
func nums(v []uint16, filter bool) string {
	s := make([]string, 0, len(v))
	for _, n := range v {
		if !filter || !grease(n) {
			s = append(s, strconv.Itoa(int(n)))
		}
	}
	return strings.Join(s, "-")
}
func ja3(h Hello) string {
	points := make([]string, len(h.ECPointFormats))
	for i, n := range h.ECPointFormats {
		points[i] = strconv.Itoa(int(n))
	}
	return fmt.Sprintf("%d,%s,%s,%s,%s", h.LegacyVersion, nums(h.CipherSuites, true), nums(h.Extensions, true), nums(h.SupportedGroups, true), strings.Join(points, "-"))
}
