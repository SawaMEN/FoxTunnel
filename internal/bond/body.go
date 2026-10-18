package bond

import (
	"errors"
	"io"
)

// readBounded allocates once. Content-Length is a size hint, never permission
// to exceed the limit. One extra byte detects oversized unknown-length bodies.
func readBounded(reader io.Reader, length int64, limit int) ([]byte, error) {
	if length > int64(limit) {
		return nil, errors.New("frame exceeds limit")
	}
	size := limit + 1
	if length >= 0 {
		size = int(length) + 1
	}
	data := make([]byte, size)
	n, err := io.ReadFull(reader, data)
	if n > limit {
		return nil, errors.New("frame exceeds limit")
	}
	if err != io.EOF && err != io.ErrUnexpectedEOF && err != nil {
		return nil, err
	}
	if length >= 0 && int64(n) != length {
		return nil, io.ErrUnexpectedEOF
	}
	return data[:n], nil
}
