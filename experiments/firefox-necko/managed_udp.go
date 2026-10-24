package firefox

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

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
		case 8:
			return nil, errors.New("Necko UDP native channel initialization failed")
		case 9:
			return nil, errors.New("Necko UDP native channel interface initialization failed")
		case 10:
			return nil, errors.New("Necko UDP native HTTP flags initialization failed")
		case 11:
			return nil, errors.New("Necko UDP native upload stream creation failed")
		case 12:
			return nil, errors.New("Necko UDP native upload stream data setup failed")
		case 13:
			return nil, errors.New("Necko UDP native upload channel setup failed")
		case 14:
			return nil, errors.New("Necko UDP native authorization header setup failed")
		case 15:
			return nil, errors.New("Necko UDP native HTTP async-open failed")
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

// OpenUDPStream opens the experimental authenticated UDP-v2 IPC bridge.
// The setup budget expires after handshake; parent cancellation owns the flow.
// Normal client configuration remains gated pending native runtime validation.
func (m *Managed) OpenUDPStream(ctx context.Context) (io.ReadWriteCloser, error) {
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
	keep := false
	defer func() {
		if !keep {
			_ = c.Close()
		}
	}()
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
	if err := write([]byte{5, 0xf1, 0, 0}); err != nil {
		return nil, err
	}
	var reply [4]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		return nil, err
	}
	if reply != [4]byte{5, 0, 0, 0} {
		return nil, errors.New("Necko UDP stream rejected")
	}
	if !stop() {
		return nil, context.DeadlineExceeded
	}
	if err := op.Err(); err != nil {
		return nil, err
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	stream := &managedUDPConn{Conn: c}
	stream.stop = context.AfterFunc(ctx, func() { _ = c.Close() })
	keep = true
	return stream, nil
}

// Closing the flow also releases its parent context callback.
type managedUDPConn struct {
	net.Conn
	stop func() bool
}

func (c *managedUDPConn) Close() error { c.stop(); return c.Conn.Close() }
