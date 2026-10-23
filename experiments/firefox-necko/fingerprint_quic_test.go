package firefox

// RFC 9001 section 5 / RFC 9000 section 17.2.2: decode public QUIC v1
// Initials at the loopback fixture. No TLS secrets, CIDs or key bytes are saved.
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/SawaMEN/FoxTunnel/internal/fingerprint"
	"net"
)

type fpInitial struct {
	first      int
	data       [65540]byte
	seen       [65540]bool
	hello      *fingerprint.Hello
	connection *fpConnection
	err        string
}
type fpPackets struct {
	net.PacketConn
	capture *fpCapture
	initial map[string]*fpInitial
}

func fpVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("short varint")
	}
	n := 1 << uint(b[0]>>6)
	if len(b) < n {
		return 0, 0, errors.New("short varint")
	}
	v := uint64(b[0] & 63)
	for _, x := range b[1:n] {
		v = v<<8 | uint64(x)
	}
	return v, n, nil
}
func fpExpand(secret []byte, label string, n int) []byte {
	label = "tls13 " + label
	info := []byte{byte(n >> 8), byte(n), byte(len(label))}
	info = append(info, label...)
	info = append(info, 0)
	out, e := hkdf.Expand(sha256.New, secret, string(info), n)
	if e != nil {
		panic(e)
	}
	return out
}
func fpDecryptInitial(packet []byte) (string, []byte, int, error) {
	fail := func() (string, []byte, int, error) { return "", nil, 0, errors.New("invalid QUIC Initial") }
	if len(packet) < 7 || packet[0]&0xf0 != 0xc0 || binary.BigEndian.Uint32(packet[1:5]) != 1 {
		return fail()
	}
	dcidLen := int(packet[5])
	if dcidLen > 20 || len(packet) < 7+dcidLen {
		return fail()
	}
	dcid := packet[6 : 6+dcidLen]
	offset := 6 + dcidLen
	scidLen := int(packet[offset])
	offset++
	if scidLen > 20 || len(packet) < offset+scidLen {
		return fail()
	}
	offset += scidLen
	token, n, e := fpVarint(packet[offset:])
	if e != nil || token > uint64(len(packet)-offset-n) {
		return fail()
	}
	offset += n + int(token)
	length, n, e := fpVarint(packet[offset:])
	if e != nil || length > uint64(len(packet)-offset-n) {
		return fail()
	}
	offset += n
	end := offset + int(length)
	if offset+20 > end {
		return fail()
	}
	salt, _ := hex.DecodeString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
	secret, e := hkdf.Extract(sha256.New, dcid, salt)
	if e != nil {
		return fail()
	}
	secret = fpExpand(secret, "client in", 32)
	hp, _ := aes.NewCipher(fpExpand(secret, "quic hp", 16))
	mask := make([]byte, 16)
	hp.Encrypt(mask, packet[offset+4:offset+20])
	header := append([]byte(nil), packet[:offset+4]...)
	header[0] ^= mask[0] & 15
	pnLen := int(header[0]&3) + 1
	header = header[:offset+pnLen]
	var pn uint64
	for j := 0; j < pnLen; j++ {
		header[offset+j] ^= mask[j+1]
		pn = pn<<8 | uint64(header[offset+j])
	}
	// Bounded cold/warm fixture starts at packet zero. A truncated packet number
	// outside that range fails authentication; it never counts as a measurement.
	key, _ := aes.NewCipher(fpExpand(secret, "quic key", 16))
	aead, _ := cipher.NewGCM(key)
	iv := fpExpand(secret, "quic iv", 12)
	for j := 0; j < 8; j++ {
		iv[len(iv)-1-j] ^= byte(pn >> uint(8*j))
	}
	plain, e := aead.Open(nil, iv, packet[offset+pnLen:end], header)
	return hex.EncodeToString(dcid), plain, end, e
}
func (p *fpPackets) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, e := p.PacketConn.ReadFrom(b)
	if e != nil {
		return n, addr, e
	}
	data := b[:n]
	for len(data) > 0 {
		id, plain, used, err := fpDecryptInitial(data)
		if err != nil {
			break
		}
		p.capture.Lock()
		initial := p.initial[id]
		if initial == nil {
			initial = &fpInitial{first: n}
			p.initial[id] = initial
		}
		if initial.hello == nil && initial.err == "" {
			initial.feed(plain)
		}
		if c := initial.connection; c != nil {
			c.Hello = initial.hello
			if initial.err != "" {
				c.Error = initial.err
			}
		}
		p.capture.Unlock()
		data = data[used:]
	}
	return n, addr, e
}
func (i *fpInitial) feed(plain []byte) {
	take := func() (uint64, bool) {
		v, n, e := fpVarint(plain)
		if e != nil {
			return 0, false
		}
		plain = plain[n:]
		return v, true
	}
	for len(plain) > 0 {
		typ, ok := take()
		if !ok {
			i.err = "malformed Initial frame"
			return
		}
		switch typ {
		case 0, 1:
		case 2, 3:
			_, a := take()
			_, b := take()
			ranges, c := take()
			_, d := take()
			if !a || !b || !c || !d || ranges > 256 {
				i.err = "malformed Initial ACK"
				return
			}
			for j := uint64(0); j < ranges; j++ {
				_, a = take()
				_, b = take()
				if !a || !b {
					i.err = "malformed Initial ACK"
					return
				}
			}
			if typ == 3 {
				for j := 0; j < 3; j++ {
					if _, ok := take(); !ok {
						i.err = "malformed Initial ECN"
						return
					}
				}
			}
		case 6:
			offset, a := take()
			length, b := take()
			if !a || !b || offset > uint64(len(i.data)) || length > uint64(len(i.data))-offset || length > uint64(len(plain)) {
				i.err = "Initial CRYPTO exceeds bound"
				return
			}
			for j := uint64(0); j < length; j++ {
				if i.seen[offset+j] && i.data[offset+j] != plain[j] {
					i.err = "conflicting Initial CRYPTO"
					return
				}
				i.data[offset+j] = plain[j]
				i.seen[offset+j] = true
			}
			plain = plain[length:]
		default:
			i.err = "unsupported Initial frame"
			return
		}
	}
	if !i.seen[0] || !i.seen[1] || !i.seen[2] || !i.seen[3] {
		return
	}
	length := 4 + (int(i.data[1]) << 16) + (int(i.data[2]) << 8) + int(i.data[3])
	if length > len(i.data) || length < 4 {
		i.err = "ClientHello exceeds bound"
		return
	}
	for j := 0; j < length; j++ {
		if !i.seen[j] {
			return
		}
	}
	hello, e := fingerprint.ParseClientHello(0, i.data[:length])
	if e != nil {
		i.err = "QUIC ClientHello decode failed"
		return
	}
	i.hello = &hello
}
