package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// These wrappers intentionally expose only the basic io.Reader/io.Writer
// interfaces, so fastCopy must exercise the pooled fallback.
type fastCopyReader struct{ io.Reader }
type fastCopyWriter struct{ io.Writer }
type shortFastWriter struct{}

func (shortFastWriter) Write(p []byte) (int, error) { return 0, nil }

func TestFastCopyIntegrityAndScratchWipe(t *testing.T) {
	for _, size := range []int{0, 1, 31, 1023, 32768, 32769, 1 << 20} {
		t.Run(stringSize(size), func(t *testing.T) {
			want := bytes.Repeat([]byte{0xA5}, size)
			var got bytes.Buffer
			n, err := fastCopy(fastCopyWriter{&got}, fastCopyReader{bytes.NewReader(want)})
			if err != nil || n != int64(size) || !bytes.Equal(got.Bytes(), want) {
				t.Fatalf("copy size=%d copied=%d err=%v", size, n, err)
			}
			// An acquired buffer is zeroed on release, even after a failed
			// transfer; no plaintext must remain in a future borrower's view.
			buffer := fastCopyBuffers.Get().(*[fastCopyBufferSize]byte)
			for i, b := range buffer {
				if b != 0 {
					t.Fatalf("pool contains plaintext at %d", i)
				}
			}
			fastCopyBuffers.Put(buffer)
		})
	}
}

func TestFastCopyReaderWriterSpecialization(t *testing.T) {
	type writerTo struct {
		io.Reader
		used *bool
	}
	// Use an adapter rather than io.ReaderTo embedding, ensuring the hook is
	// hit only by the actual io.WriterTo method.
	var sawWriterTo bool
	var sawReaderFrom bool
	src := &hookWriterTo{used: &sawWriterTo}
	dst := &hookReaderFrom{used: &sawReaderFrom}
	if n, err := fastCopy(dst, src); err != nil || n != 4 ||
		!sawWriterTo || sawReaderFrom {
		t.Fatalf("WriteTo fast path not preserved n=%d err=%v", n, err)
	}
	sawReaderFrom = false
	if n, err := fastCopy(dst, fastCopyReader{bytes.NewReader([]byte("hello"))}); err != nil ||
		n != 5 || !sawReaderFrom {
		t.Fatalf("ReadFrom fast path not preserved n=%d err=%v", n, err)
	}
	_ = writerTo{} // compile-time documentation of the intended case
}

type hookWriterTo struct{ used *bool }

func (h *hookWriterTo) Read([]byte) (int, error) { return 0, io.EOF }
func (h *hookWriterTo) WriteTo(w io.Writer) (int64, error) {
	*h.used = true
	n, err := w.Write([]byte("fast"))
	return int64(n), err
}

type hookReaderFrom struct{ used *bool }

func (h *hookReaderFrom) Write(p []byte) (int, error) { return len(p), nil }
func (h *hookReaderFrom) ReadFrom(r io.Reader) (int64, error) {
	*h.used = true
	return io.Copy(io.Discard, r)
}

func TestFastCopyShortWriteAndStreamError(t *testing.T) {
	_, err := fastCopy(shortFastWriter{}, fastCopyReader{bytes.NewReader([]byte("nonempty"))})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short writer returned %v", err)
	}
	const marker = "secret-data-marker"
	for _, payload := range [][]byte{[]byte(marker), bytes.Repeat([]byte("x"), fastCopyBufferSize+42)} {
		failing := &errorFastReader{data: payload}
		var target bytes.Buffer
		n, err := fastCopy(fastCopyWriter{&target}, failing)
		if !errors.Is(err, io.ErrUnexpectedEOF) || n != int64(len(payload)) {
			t.Fatalf("partial copy failed n=%d err=%v", n, err)
		}
		if !bytes.Equal(target.Bytes(), payload) {
			t.Fatal("partial-copy payload corrupted")
		}
	}
}

type errorFastReader struct {
	data []byte
}

func (r *errorFastReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestFastCopyConcurrentHalfCloseThroughNetPipe(t *testing.T) {
	// One direction must continue to receive data after the other direction
	// reaches EOF. This is why stage 3 does NOT merge the two net.Pipe pairs.
	upload, uploadPeer := net.Pipe()
	download, downloadPeer := net.Pipe()
	defer upload.Close()
	defer uploadPeer.Close()
	defer download.Close()
	defer downloadPeer.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = fastCopy(io.Discard, uploadPeer)
	}()
	go func() {
		defer wg.Done()
		_, _ = fastCopy(downloadPeer, bytes.NewReader([]byte("reply-after-upload")))
		downloadPeer.Close()
	}()
	upload.Close()
	_ = download.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := io.ReadAll(download)
	if err != nil || string(got) != "reply-after-upload" {
		t.Fatalf("half-close destroyed other direction: %q %v", got, err)
	}
	wg.Wait()
}

func FuzzFastCopy(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add(bytes.Repeat([]byte("x"), fastCopyBufferSize+1))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > 1<<20 {
			t.Skip()
		}
		var out bytes.Buffer
		n, err := fastCopy(fastCopyWriter{&out}, fastCopyReader{bytes.NewReader(p)})
		if err != nil || n != int64(len(p)) || !bytes.Equal(out.Bytes(), p) {
			t.Fatalf("fuzz mismatch, bytes=%d err=%v", n, err)
		}
	})
}

// Baseline and candidate use identical reader/writer-only wrappers. The tests
// intentionally compare allocation and throughput without hardcoded thresholds:
// shared CI hardware cannot reliably support release pass/fail speed numbers.
func BenchmarkFastCopyBaselineVsPool(b *testing.B) {
	for _, size := range []int{1 << 10, 1 << 20} {
		payload := bytes.Repeat([]byte{0xBC}, size)
		for _, candidate := range []struct {
			name string
			copy func(io.Writer, io.Reader) (int64, error)
		}{
			{"stdlib", io.Copy},
			{"pooled", fastCopy},
		} {
			b.Run(candidate.name+"/"+stringSize(size), func(b *testing.B) {
				r := bytes.NewReader(payload)
				dst := fastCopyWriter{io.Discard}
				src := fastCopyReader{r}
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					r.Reset(payload)
					n, err := candidate.copy(dst, src)
					if err != nil || n != int64(size) {
						b.Fatalf("mismatched byte count %d: %v", n, err)
					}
				}
			})
		}
	}
}
