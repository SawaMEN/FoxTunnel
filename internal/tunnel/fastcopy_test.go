package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
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
		t.Run(strconv.Itoa(size)+"B", func(t *testing.T) {
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
	// The source's io.WriterTo has priority over destination io.ReaderFrom.
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
	for _, workload := range []struct {
		name string
		size int
	}{
		{"1KiB", 1 << 10},
		{"1MiB", 1 << 20},
	} {
		payload := bytes.Repeat([]byte{0xBC}, workload.size)
		for _, candidate := range []struct {
			name string
			copy func(io.Writer, io.Reader) (int64, error)
		}{
			{"stdlib", io.Copy},
			{"pooled", fastCopy},
		} {
			b.Run(candidate.name+"/"+workload.name, func(b *testing.B) {
				r := bytes.NewReader(payload)
				dst := fastCopyWriter{io.Discard}
				src := fastCopyReader{r}
				b.SetBytes(int64(workload.size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					r.Reset(payload)
					n, err := candidate.copy(dst, src)
					if err != nil || n != int64(workload.size) {
						b.Fatalf("mismatched byte count %d: %v", n, err)
					}
				}
			})
		}
	}
}

type fastCopyHookReader struct {
	io.Reader
	writeToCalled bool
}

func (r *fastCopyHookReader) WriteTo(io.Writer) (int64, error) {
	r.writeToCalled = true
	return 0, errors.New("unusable transport WriteTo should be skipped")
}

type fastCopyHookWriter struct {
	io.Writer
	readFromCalled bool
}

func (w *fastCopyHookWriter) ReadFrom(io.Reader) (int64, error) {
	w.readFromCalled = true
	return 0, errors.New("unexpected ReadFrom hook")
}

func TestFastCopyHTTPResponseSkipsTransportHooks(t *testing.T) {
	for _, size := range []int{0, 1, 64, 32 << 10, (128 << 10) + 3} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			original := bytes.Repeat([]byte{0xCD}, size)
			src := &fastCopyHookReader{Reader: bytes.NewReader(original)}
			sink := httptest.NewRecorder()
			flushed := flushingWriter{w: sink, flusher: sink}
			dst := &fastCopyHookWriter{Writer: flushed}
			n, err := fastCopyHTTPResponse(dst, src)
			if err != nil || n != int64(size) || !bytes.Equal(sink.Body.Bytes(), original) {
				t.Fatalf("flushed copy: bytes=%d size=%d err=%v", n, size, err)
			}
			if src.writeToCalled || dst.readFromCalled {
				t.Fatal("TCP/HTTP optional fast path must not bypass pooled scratch")
			}
			if size > 0 && !sink.Flushed {
				t.Fatal("interactive HTTP response was never flushed")
			}
		})
	}
}

func TestFastCopyHTTPResponseShortWriteAndError(t *testing.T) {
	_, err := fastCopyHTTPResponse(shortFastWriter{},
		fastCopyReader{bytes.NewReader([]byte("bytes"))})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write lost: %v", err)
	}
	payload := bytes.Repeat([]byte{0xFC}, 43<<10)
	input := &errorFastReader{data: payload}
	var output bytes.Buffer
	n, err := fastCopyHTTPResponse(fastCopyWriter{&output}, input)
	if !errors.Is(err, io.ErrUnexpectedEOF) || n != int64(len(payload)) ||
		!bytes.Equal(output.Bytes(), payload) {
		t.Fatalf("partial HTTP response copied %d bytes, err=%v", n, err)
	}
}

func FuzzFastCopyHTTPResponse(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("small"))
	f.Add(bytes.Repeat([]byte("p"), fastCopyBufferSize+2))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		source := &fastCopyHookReader{Reader: bytes.NewReader(data)}
		var output bytes.Buffer
		n, err := fastCopyHTTPResponse(fastCopyWriter{&output}, source)
		if err != nil || n != int64(len(data)) || !bytes.Equal(output.Bytes(), data) || source.writeToCalled {
			t.Fatal("response copy corrupt or unexpectedly used WriteTo")
		}
	})
}

// Compares the full downstream copy with no network and a source exposing
// WriterTo, just like a TCPConn. Absolute numbers are CPU/cache sensitive and
// are not a release speed gate.
func BenchmarkFastCopyHTTPResponse(b *testing.B) {
	for _, workload := range []struct {
		name string
		size int
	}{{"64B", 64}, {"1MiB", 1 << 20}} {
		payload := bytes.Repeat([]byte{0xBE}, workload.size)
		for _, mode := range []struct {
			name string
			copy func(io.Writer, io.Reader) (int64, error)
		}{{"auto-hooks", fastCopy}, {"pooled-http", fastCopyHTTPResponse}} {
			b.Run(mode.name+"/"+workload.name, func(b *testing.B) {
				var original bytes.Reader
				var out bytes.Buffer
				// bytes.Reader implements io.WriterTo and its optimized copy
				// is *not* a TCPConn fallback. The benchmark therefore compares
				// semantics and allocation only, NOT transport speed.
				b.SetBytes(int64(workload.size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					original.Reset(payload)
					out.Reset()
					n, err := mode.copy(fastCopyWriter{&out}, &original)
					if n != int64(workload.size) || err != nil {
						b.Fatal("copy failed", n, err)
					}
				}
			})
		}
	}
}

type fastCopyDiscardResponse struct {
	bytes int64
}

func (*fastCopyDiscardResponse) Header() http.Header { return nil }
func (*fastCopyDiscardResponse) WriteHeader(int) {}
func (r *fastCopyDiscardResponse) Write(p []byte) (int, error) {
	r.bytes += int64(len(p))
	return len(p), nil
}
func (*fastCopyDiscardResponse) Flush() {}

// Runs over a real TCPConn rather than bytes.Reader, so the baseline really
// selects net.TCPConn.WriteTo and its non-splice HTTP fallback.
func BenchmarkFastCopyHTTPResponseTCP(b *testing.B) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()
	for _, workload := range []struct {
		name string
		size int
	}{{"64B", 64}, {"1MiB", 1 << 20}} {
		payload := bytes.Repeat([]byte{0xDB}, workload.size)
		for _, mode := range []struct {
			name string
			copy func(io.Writer, io.Reader) (int64, error)
		}{{"tcp-writeto", fastCopy}, {"pooled-http", fastCopyHTTPResponse}} {
			b.Run(mode.name+"/"+workload.name, func(b *testing.B) {
				b.SetBytes(int64(workload.size))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					writer, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
					if err != nil {
						b.Fatal(err)
					}
					reader, err := listener.AcceptTCP()
					if err != nil {
						writer.Close()
						b.Fatal(err)
					}
					completed := make(chan error, 1)
					go func() {
						_, copyErr := io.Copy(writer, bytes.NewReader(payload))
						if err := writer.CloseWrite(); copyErr == nil {
							copyErr = err
						}
						completed <- copyErr
					}()
					sink := new(fastCopyDiscardResponse)
					dst := flushingWriter{w: sink, flusher: sink}
					b.StartTimer()
					n, copyErr := mode.copy(dst, reader)
					b.StopTimer()
					reader.Close()
					writer.Close()
					sendErr := <-completed
					if copyErr != nil || sendErr != nil || n != int64(workload.size) ||
						sink.bytes != int64(workload.size) {
						b.Fatalf("TCP relay integrity n=%d got=%d: %v, send=%v",
							n, sink.bytes, copyErr, sendErr)
					}
				}
			})
		}
	}
}
