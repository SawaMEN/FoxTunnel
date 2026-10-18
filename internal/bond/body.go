package bond

import (
	"errors"
	"io"
	"sync"
)

// readBounded allocates once. Content-Length is a size hint, never permission
// to exceed the limit. One extra byte detects oversized unknown-length bodies.
func readBounded(reader io.Reader, length int64, limit int) ([]byte, error) {
	return readBoundedInto(reader, length, limit, nil)
}

func readBoundedInto(reader io.Reader, length int64, limit int, buffer []byte) ([]byte, error) {
	if length > int64(limit) {
		return nil, errors.New("frame exceeds limit")
	}
	size := limit + 1
	if length >= 0 {
		size = int(length) + 1
	}
	data := buffer
	if cap(data) < size {
		data = make([]byte, size)
	} else {
		data = data[:size]
	}
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

// frameSet owns immutable slices for all readers created by HTTP retries.
// Closing the set joins Read and invalidates every reader, so a returned
// transport body cannot access a subsequently reused upload slot.
type frameSet struct {
	mu              sync.Mutex
	closed          bool
	header, payload []byte
}

func (f *frameSet) body() (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, io.ErrClosedPipe
	}
	return &frameBody{frames: f}, nil
}
func (f *frameSet) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	f.header = nil
	f.payload = nil
}

type frameBody struct {
	frames *frameSet
	offset int
	closed bool
}

func (b *frameBody) Read(p []byte) (int, error) {
	f := b.frames
	f.mu.Lock()
	defer f.mu.Unlock()
	if b.closed || f.closed {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}
	n := 0
	if b.offset < len(f.header) {
		n = copy(p, f.header[b.offset:])
		b.offset += n
	}
	if n < len(p) {
		m := copy(p[n:], f.payload[max(0, b.offset-len(f.header)):])
		n += m
		b.offset += m
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}
func (b *frameBody) Close() error {
	b.frames.mu.Lock()
	defer b.frames.mu.Unlock()
	b.closed = true
	return nil
}
