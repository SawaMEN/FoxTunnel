package tunnel

import (
	"io"
	"sync"
)

// A virtual tunnel normally has four simultaneous copying directions across
// the H2/H3 carrier and the local SOCKS connection. Share scratch space across
// completed transfers to avoid retaining a fresh 32 KiB allocation per pump.
// Never share a checked-out buffer between simultaneous directions.
const fastCopyBufferSize = 32 << 10

var fastCopyBuffers = sync.Pool{
	New: func() any { return new([fastCopyBufferSize]byte) },
}

// fastCopy preserves io.Copy's ReaderFrom/WriterTo fast paths and error/short
// write behavior. Pooling applies only when neither side offers a specialized
// method; otherwise checking out a buffer would be unnecessary work.
// The plaintext scratch is wiped before returning it to a global pool.
func fastCopy(dst io.Writer, src io.Reader) (int64, error) {
	if wt, ok := src.(io.WriterTo); ok {
		return wt.WriteTo(dst)
	}
	if rf, ok := dst.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	buf := fastCopyBuffers.Get().(*[fastCopyBufferSize]byte)
	defer func() {
		clear(buf[:])
		fastCopyBuffers.Put(buf)
	}()
	return io.CopyBuffer(dst, src, buf[:])
}

// readerOnly and writerOnly intentionally hide optional io.WriterTo and
// io.ReaderFrom methods. On the server's TCP -> HTTP response path, neither
// sendfile nor splice can work with a flushing HTTP ResponseWriter; avoid
// the fallback scratch allocation inside net.TCPConn.WriteTo.
// The existing fastCopy fast paths remain available on every other route.
type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }

// fastCopyHTTPResponse uses the shared, scrubbed scratch buffer for TCP ->
// streamed HTTP responses. No buffering delay is introduced: a flushingWriter
// still flushes each successfully written chunk for interactive traffic.
// Padding and authentication wrappers remain in the same order.
func fastCopyHTTPResponse(dst io.Writer, src io.Reader) (int64, error) {
	return fastCopy(writerOnly{dst}, readerOnly{src})
}
