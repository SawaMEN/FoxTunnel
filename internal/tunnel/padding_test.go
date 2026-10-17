package tunnel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"testing"
)

func TestPaddingRoundTripAndBoundedOverhead(t *testing.T) {
	for _, size := range []int{0, 1, 64, 16384, 16385, 131072, 300000} {
		source := bytes.Repeat([]byte{0x61}, size)
		var wire bytes.Buffer
		writer := newPaddingWriter(&wire)
		if n, err := writer.Write(source); err != nil || n != size {
			t.Fatalf("size %d write %d %v", size, n, err)
		}
		encoded := bytes.Clone(wire.Bytes())
		got, err := io.ReadAll(newPaddingReader(bytes.NewReader(encoded)))
		if err != nil || !bytes.Equal(got, source) {
			t.Fatalf("size %d decode: %v", size, err)
		}
		if len(encoded) > size+initialPaddingRecords*(3+maxPaddingBytes) {
			t.Fatal("padding budget exceeded")
		}
		offset, consumed := 0, 0
		for i := 0; i < initialPaddingRecords && consumed < size; i++ {
			n := int(binary.BigEndian.Uint16(encoded[offset : offset+2]))
			pad := int(encoded[offset+2])
			offset += 3
			if n < 1 || n > maxPaddingPayload {
				t.Fatal("invalid encoder record")
			}
			if !bytes.Equal(encoded[offset+n:offset+n+pad], make([]byte, pad)) {
				t.Fatal("padding leaked pooled plaintext")
			}
			offset += n + pad
			consumed += n
		}
		if !bytes.Equal(encoded[offset:], source[consumed:]) {
			t.Fatal("raw tail differs")
		}
	}
}
func TestPaddingSmallWritesAndReads(t *testing.T) {
	var wire, source bytes.Buffer
	writer := newPaddingWriter(&wire)
	if n, err := writer.Write(nil); n != 0 || err != nil || writer.records != initialPaddingRecords {
		t.Fatal("empty write emitted record")
	}
	for i := 0; i < 12; i++ {
		p := bytes.Repeat([]byte{byte(i)}, i+1)
		source.Write(p)
		if _, err := writer.Write(p); err != nil {
			t.Fatal(err)
		}
	}
	reader := newPaddingReader(&wire)
	if n, err := reader.Read(nil); n != 0 || err != nil || reader.records != initialPaddingRecords {
		t.Fatal("empty read consumed record")
	}
	var got bytes.Buffer
	var one [1]byte
	for {
		n, err := reader.Read(one[:])
		got.Write(one[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got.Bytes(), source.Bytes()) {
		t.Fatal("small operations changed bytes")
	}
}
func TestPaddingRejectsTruncation(t *testing.T) {
	var wire bytes.Buffer
	if _, err := newPaddingWriter(&wire).Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	encoded := bytes.Clone(wire.Bytes())
	for cut := 1; cut < len(encoded); cut++ {
		r := newPaddingReader(bytes.NewReader(encoded[:cut]))
		got, err := io.ReadAll(r)
		if !errors.Is(err, io.ErrUnexpectedEOF) || len(got) != 0 {
			t.Fatalf("cut %d: %q %v", cut, got, err)
		}
		var b [1]byte
		if _, again := r.Read(b[:]); !errors.Is(again, io.ErrUnexpectedEOF) {
			t.Fatal("decoder recovered after damaged record")
		}
	}
	for _, length := range []uint16{0, maxPaddingPayload + 1, 65535} {
		encoded := binary.BigEndian.AppendUint16(nil, length)
		encoded = append(encoded, 0)
		if _, err := io.ReadAll(newPaddingReader(bytes.NewReader(encoded))); err == nil {
			t.Fatalf("accepted length %d", length)
		}
	}
}

type limitedWriter struct {
	target io.Writer
	limit  int
}

func (w limitedWriter) Write(p []byte) (int, error) { return w.target.Write(p[:min(len(p), w.limit)]) }

type failedWriter struct{ calls int }

func (w *failedWriter) Write([]byte) (int, error) { w.calls++; return 0, io.ErrClosedPipe }
func TestPaddingShortAndFailedWrites(t *testing.T) {
	var wire bytes.Buffer
	w := newPaddingWriter(limitedWriter{&wire, 1})
	if _, err := w.Write([]byte("short writer")); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(newPaddingReader(&wire))
	if err != nil || string(got) != "short writer" {
		t.Fatalf("short writes: %q %v", got, err)
	}
	failed := &failedWriter{}
	w = newPaddingWriter(failed)
	for i := 0; i < 2; i++ {
		if n, err := w.Write([]byte("secret")); n != 0 || !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("failed write %d %v", n, err)
		}
	}
	if failed.calls != 1 {
		t.Fatal("retried partially emitted stream")
	}
	w = newPaddingWriter(limitedWriter{io.Discard, 0})
	if _, err := w.Write([]byte("no progress")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
}
func TestPaddingNegotiationValues(t *testing.T) {
	for _, values := range [][]string{{paddingVersion, paddingVersion}, {"unknown"}, {""}, {paddingVersion + ", " + paddingVersion}} {
		header := http.Header{}
		for _, v := range values {
			header.Add(paddingHeader, v)
		}
		if _, err := paddingRequested(header); err == nil {
			t.Errorf("accepted ambiguous mode %q", values)
		}
	}
}
func FuzzPaddingDecoder(f *testing.F) {
	f.Add([]byte{0, 1, 0, 'a'})
	f.Add([]byte{0, 0, 0})
	f.Add([]byte{255, 255, 255})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 1<<16 {
			t.Skip()
		}
		payload, _ := io.ReadAll(newPaddingReader(bytes.NewReader(wire)))
		if len(payload) > len(wire) {
			t.Fatal("decoder expanded wire payload")
		}
	})
}

func TestPaddingReleasesBufferAfterInitialRecords(t *testing.T) {
	var wire bytes.Buffer
	w := newPaddingWriter(&wire)
	for i := 0; i < initialPaddingRecords; i++ {
		if _, err := w.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	r := newPaddingReader(&wire)
	got, err := io.ReadAll(r)
	if err != nil || len(got) != initialPaddingRecords {
		t.Fatal(err)
	}
	if r.buffer != nil || r.pending != nil {
		t.Fatal("initial buffer retained in raw phase")
	}
}

type byteCounter struct{ n int }

func (c *byteCounter) Write(p []byte) (int, error) { c.n += len(p); return len(p), nil }

// Measures the cold framing prefix, rather than hiding it in a long raw stream.
// Discards the wire output; it is an encoder CPU/overhead microbenchmark only.
func BenchmarkInitialPaddingEncoder(b *testing.B) {
	for _, tc := range []struct {
		name string
		size int
	}{{"64B", 64}, {"16KiB", 16 << 10}, {"128KiB", 128 << 10}} {
		b.Run(tc.name, func(b *testing.B) {
			payload := bytes.Repeat([]byte{0x42}, tc.size)
			counter := new(byteCounter)
			wireBytes := 0
			b.SetBytes(int64(tc.size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				counter.n = 0
				w := newPaddingWriter(counter)
				if _, err := w.Write(payload); err != nil {
					b.Fatal(err)
				}
				wireBytes += counter.n
			}
			b.StopTimer()
			b.ReportMetric(float64(wireBytes)/float64(b.N)-float64(tc.size), "extra-B/op")
		})
	}
}
