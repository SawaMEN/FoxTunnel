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
