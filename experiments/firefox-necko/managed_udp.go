package firefox

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

// ExchangeUDP sends a single RFC1928 UDP packet to the pinned FoxTunnel v1
// endpoint using native Mozilla HTTP/2. The local loopback connection is
// authenticated independently of the remote HTTPS Basic credentials.
// No Go HTTP client, TLS fallback, destination URL or redirect is involved.
func (m *Managed) ExchangeUDP(ctx context.Context, wire []byte) ([]byte, error) {
	if _, err := udpproto.Parse(wire); err != nil {
		return nil, err
	}
	op, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	if err := m.Ready(op); err != nil {
		return nil, err
	}
	m.mu.Lock()
	listen, closed := m.listen, m.closed
	m.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	c, err := (&net.Dialer{}).DialContext(op, "tcp", listen)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if deadline, ok := op.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	stop := context.AfterFunc(op, func() { _ = c.Close() })
	defer stop()
	write := func(bytes []byte) error {
		for len(bytes) > 0 {
			n, e := c.Write(bytes)
			if e != nil {
				return e
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			bytes = bytes[n:]
		}
		return nil
	}
	var greeting [2]byte
	if err = write([]byte{5, 1, 2}); err == nil {
		_, err = io.ReadFull(c, greeting[:])
	}
	if err != nil {
		return nil, err
	}
	if greeting != [2]byte{5, 2} {
		return nil, errors.New("Necko UDP IPC greeting rejected")
	}
	auth := append([]byte{1, 9}, []byte("foxtunnel")...)
	auth = append(auth, byte(len(m.token)))
	auth = append(auth, []byte(m.token)...)
	if err = write(auth); err == nil {
		_, err = io.ReadFull(c, greeting[:])
	}
	if err != nil {
		return nil, err
	}
	if greeting != [2]byte{1, 0} {
		return nil, errors.New("Necko UDP IPC authentication rejected")
	}
	header := []byte{5, 0xf0, 0, 0, byte(len(wire) >> 8), byte(len(wire))}
	if err := write(header); err != nil {
		return nil, err
	}
	if err := write(wire); err != nil {
		return nil, err
	}
	var reply [4]byte
	if _, err = io.ReadFull(c, reply[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(reply[2:]))
	if reply[0] != 5 || size > udpproto.MaxDatagram {
		return nil, errors.New("Necko UDP IPC response invalid")
	}
	if reply[1] != 0 {
		// Fixed internal categories; no secret or remote response is exposed.
		switch reply[1] {
		case 2:
			return nil, errors.New("Necko UDP native HTTP request setup failed")
		case 3:
			return nil, errors.New("Necko UDP remote HTTP status rejected")
		case 4:
			return nil, errors.New("Necko UDP native HTTP version was not H2")
		case 5:
			return nil, errors.New("Necko UDP native HTTP network failed")
		case 6:
			return nil, errors.New("Necko UDP native HTTP response invalid")
		case 7:
			return nil, errors.New("Necko UDP native HTTP response timed out")
		default:
			return nil, errors.New("Necko UDP HTTPS relay rejected")
		}
	}
	if size == 0 { // HTTPS 204: destination supplied no response.
		if err := op.Err(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	data := make([]byte, size)
	if _, err = io.ReadFull(c, data); err != nil {
		return nil, err
	}
	if _, err = udpproto.Parse(data); err != nil {
		return nil, errors.New("Necko UDP relay returned malformed packet")
	}
	if err := op.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

