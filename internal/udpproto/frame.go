package udpproto

import (
	"encoding/binary"
	"errors"
	"io"
)

// Stream frames are length-prefixed RFC 1928 SOCKS5 UDP packets.
// The v2 streaming endpoint is distinct from the existing single-shot v1 endpoint.
// No implicit framing, fragmentation or in-band downgrade is allowed.
var ErrFrame = errors.New("invalid UDP stream frame")

func ReadFrame(r io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size == 0 || size > MaxDatagram {
		return nil, ErrFrame
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if _, err := Parse(data); err != nil {
		return nil, ErrFrame
	}
	return data, nil
}

func WriteFrame(w io.Writer, wire []byte) error {
	if _, err := Parse(wire); err != nil {
		return ErrFrame
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(wire)))
	if err := writeExact(w, header[:]); err != nil {
		return err
	}
	return writeExact(w, wire)
}

func writeExact(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
