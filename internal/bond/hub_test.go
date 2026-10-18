package bond

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCoordinatorIdentityRejectsOtherExitBeforeDial(t *testing.T) {
	var dialed atomic.Bool
	h := &Hub{Dial: func(context.Context, string) (net.Conn, error) { dialed.Store(true); return nil, net.ErrClosed }}
	defer h.Close()
	data := make([]byte, headerSize)
	data[0] = opOpen
	binary.BigEndian.PutUint64(data[1:9], uint64(time.Now().Unix()))
	data = append(data, []byte("example.org:443")...)
	r := httptest.NewRequest("POST", "https://main.example"+Path, bytes.NewReader(data))
	r.Header.Set("X-FoxTunnel-Bond-Hub", strings.Repeat("ab", 32))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 409 || dialed.Load() {
		t.Fatal("wrong exit performed destination work", w.Code)
	}
}

func TestHubBoundsAndTombstones(t *testing.T) {
	var peer net.Conn
	h := &Hub{MaxSessions: 1, Dial: func(context.Context, string) (net.Conn, error) { a, b := net.Pipe(); peer = b; return a, nil }}
	defer h.Close()
	token := make([]byte, 32)
	binary.BigEndian.PutUint64(token, uint64(time.Now().Unix()))
	token[31] = 1
	call := func(op byte, seq uint64, data []byte) *httptest.ResponseRecorder {
		body := make([]byte, headerSize+len(data))
		body[0] = op
		copy(body[1:33], token)
		binary.BigEndian.PutUint64(body[33:41], seq)
		copy(body[headerSize:], data)
		req := httptest.NewRequest(http.MethodPost, "https://example.org"+Path, bytes.NewReader(body))
		if op != opOpen {
			req.Header.Set("X-FoxTunnel-Bond-Hub", hex.EncodeToString(h.identity[:]))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	if w := call(opOpen, 0, []byte("example.org:443")); w.Code != 200 {
		t.Fatal(w.Code)
	}
	defer peer.Close()
	if w := call(opWrite, window, []byte("too far")); w.Code != 429 {
		t.Fatal("unbounded upload window", w.Code)
	}
	if w := call(opRead, window, nil); w.Code != 409 {
		t.Fatal("unbounded receive window", w.Code)
	}
	if w := call(opOpen, 0, []byte("different.org:443")); w.Code != 409 {
		t.Fatal("session target changed", w.Code)
	}
	if w := call(opClose, 0, nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := call(opOpen, 0, []byte("example.org:443")); w.Code != 410 {
		t.Fatal("closed token redialed", w.Code)
	}
	binary.BigEndian.PutUint64(token, uint64(time.Now().Add(-time.Minute).Unix()))
	if w := call(opOpen, 0, []byte("example.org:443")); w.Code != 409 {
		t.Fatal("expired token accepted", w.Code)
	}
}
func TestHubRejectsMalformedFrame(t *testing.T) {
	h := new(Hub)
	for _, data := range [][]byte{nil, make([]byte, headerSize-1), make([]byte, headerSize+chunkSize+1)} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "https://example.org"+Path, bytes.NewReader(data)))
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
}
func TestHubCloseDuringDial(t *testing.T) {
	started := make(chan struct{})
	resume := make(chan struct{})
	peerDone := make(chan struct{})
	h := &Hub{Dial: func(context.Context, string) (net.Conn, error) {
		close(started)
		<-resume
		a, b := net.Pipe()
		go func() { defer b.Close(); _, _ = io.Copy(io.Discard, b); close(peerDone) }()
		return a, nil
	}}
	token := make([]byte, 32)
	binary.BigEndian.PutUint64(token, uint64(time.Now().Unix()))
	done := make(chan struct{})
	go func() { _, _ = h.get(context.Background(), token, "example.org:443"); close(done) }()
	<-started
	h.Close()
	close(resume)
	<-done
	select {
	case <-peerDone:
	case <-time.After(time.Second):
		t.Fatal("dialed socket leaked after hub close")
	}
}

func TestDifferentHubRejectedBeforeDial(t *testing.T) {
	h := &Hub{Dial: func(context.Context, string) (net.Conn, error) {
		t.Error("misrouted session dialed a destination")
		return nil, net.ErrClosed
	}}
	body := make([]byte, headerSize+len("example.org:443"))
	body[0] = opOpen
	binary.BigEndian.PutUint64(body[1:9], uint64(time.Now().Unix()))
	copy(body[headerSize:], "example.org:443")
	r := httptest.NewRequest(http.MethodPost, "https://example.org"+Path, bytes.NewReader(body))
	r.Header.Set("X-FoxTunnel-Bond-Hub", "wrong-instance")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 409 {
		t.Fatal(w.Code)
	}
}
func TestBoundedBodyReader(t *testing.T) {
	for _, tc := range []struct {
		data   string
		length int64
		limit  int
		ok     bool
	}{{"abc", 3, 3, true}, {"abc", -1, 3, true}, {"abcd", -1, 3, false}, {"abc", 4, 4, false}, {"abc", 2, 4, false}, {"abc", 3, 2, false}, {"", 0, 4, true}} {
		got, err := readBounded(bytes.NewBufferString(tc.data), tc.length, tc.limit)
		if (err == nil) != tc.ok || (tc.ok && string(got) != tc.data) {
			t.Fatalf("%+v got=%q err=%v", tc, got, err)
		}
	}
}

func TestFrameBodyChunkBoundaries(t *testing.T) {
	header := bytes.Repeat([]byte{19}, headerSize)
	payload := bytes.Repeat([]byte{37}, chunkSize)
	expected := append(append([]byte(nil), header...), payload...)
	for _, size := range []int{1, headerSize - 1, headerSize, headerSize + 1, 16 << 10, chunkSize + headerSize} {
		frames := &frameSet{header: header, payload: payload}
		reader, _ := frames.body()
		var actual bytes.Buffer
		buffer := make([]byte, size)
		for {
			n, err := reader.Read(buffer)
			actual.Write(buffer[:n])
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(actual.Bytes(), expected) {
			t.Fatalf("frame split with buffer size %d", size)
		}
	}
}

func TestFrameRewindAfterOriginalReaderClose(t *testing.T) {
	frames := &frameSet{header: []byte("header"), payload: []byte("payload")}
	original, _ := frames.body()
	prefix := make([]byte, 3)
	if _, err := io.ReadFull(original, prefix); err != nil {
		t.Fatal(err)
	}
	original.Close()
	rewound, err := frames.body()
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(rewound)
	if err != nil || string(data) != "headerpayload" {
		t.Fatal(string(data), err)
	}
	frames.close()
	if _, err := frames.body(); err != io.ErrClosedPipe {
		t.Fatal("retry reader created after terminal close", err)
	}
	if _, err := rewound.Read(make([]byte, 1)); err != io.ErrClosedPipe {
		t.Fatal("retry reader survived terminal close", err)
	}
}
