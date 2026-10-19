// Package h2profile implements opt-in HTTP/2 receive settings.
// It does not implement Firefox Necko.
package h2profile

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

const (
	maxInitialBuffer  = 64 << 10
	settingsFrameType = 4
)

var clientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// WrapNSSConn transforms only the first client HTTP/2 SETTINGS frame when
// the measured Firefox 158 profile is enabled. HPACK, actual request headers,
// frames after SETTINGS, flow control and local limits are still handled
// by Go/x/net/http2. The wrapper is installed over the NSS plaintext API,
// not over a raw socket or inside the TLS protocol.
func WrapNSSConn(conn net.Conn, profile string) net.Conn {
	if profile != Firefox158 {
		return conn
	}
	return &settingsConn{Conn: conn}
}

type settingsConn struct {
	net.Conn
	mu     sync.Mutex
	buffer []byte
	ready  bool
	failed error
}

// Keep the verified TLS state available to Go's HTTP/2 implementation.
func (c *settingsConn) ConnectionState() tls.ConnectionState {
	if s, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return s.ConnectionState()
	}
	return tls.ConnectionState{}
}

func (c *settingsConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed != nil {
		return 0, c.failed
	}
	if c.ready {
		return c.Conn.Write(p)
	}
	if len(c.buffer)+len(p) > maxInitialBuffer {
		return c.fail(errors.New("Mozilla HTTP/2 initial write exceeds bounded buffer"))
	}
	c.buffer = append(c.buffer, p...)
	rewritten, complete, err := rewriteInitial(c.buffer)
	if err != nil {
		return c.fail(err)
	}
	if !complete {
		// The pinned Go HTTP/2 transport normally flushes preface and
		// SETTINGS together. Bound and buffer fragmented initial writes.
		return len(p), nil
	}
	if err := writeComplete(c.Conn, rewritten); err != nil {
		return c.fail(err)
	}
	c.buffer = nil
	c.ready = true
	return len(p), nil
}

func (c *settingsConn) fail(err error) (int, error) {
	c.failed = err
	c.buffer = nil
	_ = c.Conn.Close()
	return 0, err
}

func writeComplete(conn net.Conn, p []byte) error {
	for len(p) > 0 {
		n, err := conn.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// rewriteInitial accepts only the known first SETTINGS values from the Go
// HTTP/2 implementation. Unexpected initial values abort the connection.
// SETTINGS_MAX_HEADER_LIST_SIZE is removed from the advertisement, but the
// Go transport retains its independent local response header limits.
func rewriteInitial(data []byte) ([]byte, bool, error) {
	prefixLen := min(len(data), len(clientPreface))
	if !bytes.Equal(data[:prefixLen], clientPreface[:prefixLen]) {
		return nil, false, errors.New("Mozilla HTTP/2 client preface mismatch")
	}
	if len(data) < len(clientPreface)+9 {
		return nil, false, nil
	}
	pos := len(clientPreface)
	length := int(data[pos])<<16 | int(data[pos+1])<<8 | int(data[pos+2])
	if data[pos+3] != settingsFrameType || data[pos+4] != 0 ||
		binary.BigEndian.Uint32(data[pos+5:pos+9]) != 0 ||
		length > 256 || length%6 != 0 {
		return nil, false, errors.New("Mozilla HTTP/2 first SETTINGS layout changed")
	}
	end := pos + 9 + length
	if len(data) < end {
		return nil, false, nil
	}
	expected := map[uint16]uint32{1: HeaderTable, 2: 0, 4: StreamWindow, 5: 16384}
	seen := make(map[uint16]bool, 5)
	for offset := pos + 9; offset < end; offset += 6 {
		id := binary.BigEndian.Uint16(data[offset : offset+2])
		value := binary.BigEndian.Uint32(data[offset+2 : offset+6])
		if seen[id] {
			return nil, false, fmt.Errorf("duplicate initial HTTP/2 setting %d", id)
		}
		seen[id] = true
		if id == 6 {
			if value == 0 {
				return nil, false, errors.New("invalid upstream HTTP/2 header cap")
			}
			continue
		}
		want, ok := expected[id]
		if !ok || value != want {
			return nil, false, fmt.Errorf("unexpected Mozilla HTTP/2 setting %d", id)
		}
	}
	for id := range expected {
		if !seen[id] {
			return nil, false, fmt.Errorf("missing Mozilla HTTP/2 setting %d", id)
		}
	}
	// Firefox 158 reference: HEADER_TABLE_SIZE, ENABLE_PUSH,
	// INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE. The original WINDOW_UPDATE
	// and every subsequent byte pass through untouched.
	out := make([]byte, 0, len(data))
	out = append(out, clientPreface...)
	out = append(out, 0, 0, 24, settingsFrameType, 0, 0, 0, 0, 0)
	for _, id := range []uint16{1, 2, 4, 5} {
		var item [6]byte
		binary.BigEndian.PutUint16(item[:2], id)
		binary.BigEndian.PutUint32(item[2:], expected[id])
		out = append(out, item[:]...)
	}
	out = append(out, data[end:]...)
	return out, true, nil
}
