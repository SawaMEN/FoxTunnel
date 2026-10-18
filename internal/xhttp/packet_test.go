package xhttp

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

const testID = "00000000-0000-4000-8000-000000000001"

func packetRequest(s *Server, seq string, data io.Reader) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://node"+Path+testID+"/"+seq, data)
	r.ProtoMajor = 2
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func TestPacketReorderAndDuplicate(t *testing.T) {
	s := &Server{MaxSessions: 1, Authorized: func(*http.Request) bool { return true }}
	p, ok := s.claim(testID, false)
	if !ok {
		t.Fatal("download claim")
	}
	defer s.close(testID, p)
	got := make(chan string, 1)
	go func() { b := make([]byte, 3); _, _ = io.ReadFull(p.local, b); got <- string(b) }()
	entered := make(chan struct{})
	late := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		late <- packetRequest(s, "1", &enteredReader{Reader: strings.NewReader("b"), entered: entered})
	}()
	<-entered
	if w := packetRequest(s, "1", strings.NewReader("b")); w.Code != 409 {
		t.Fatal("duplicate reservation", w.Code)
	}
	if w := packetRequest(s, "0", strings.NewReader("a")); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := <-late; w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := packetRequest(s, "2", strings.NewReader("c")); w.Code != 200 {
		t.Fatal(w.Code)
	}
	select {
	case data := <-got:
		if data != "abc" {
			t.Fatal("ordering", data)
		}
	case <-time.After(time.Second):
		t.Fatal("delivery stalled")
	}
	if w := packetRequest(s, "0", strings.NewReader("a")); w.Code != 409 {
		t.Fatal("delivered sequence replayed", w.Code)
	}
}
func TestPacketLimits(t *testing.T) {
	s := &Server{MaxSessions: 1, Authorized: func(*http.Request) bool { return true }}
	p, ok := s.claim(testID, false)
	if !ok {
		t.Fatal("claim")
	}
	defer s.close(testID, p)
	if w := packetRequest(s, "8", strings.NewReader("x")); w.Code != 409 {
		t.Fatal("window bypass", w.Code)
	}
	for i := uint64(0); i < MaxPendingPackets; i++ {
		if _, status := s.admitPacket(testID, i); status != 0 {
			t.Fatal("bounded reserve", i, status)
		}
	}
	s.mu.Lock()
	n := len(p.pending)
	s.mu.Unlock()
	if n != MaxPendingPackets {
		t.Fatal("unbounded queue", n)
	}
	if _, status := s.admitPacket(testID, MaxPendingPackets); status == 0 {
		t.Fatal("queue limit bypass")
	}
}
func TestPacketOversizeAndTruncatedBody(t *testing.T) {
	for _, kind := range []string{"oversize", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			s := &Server{Authorized: func(*http.Request) bool { return true }}
			p, _ := s.claim(testID, false)
			var body io.Reader = bytes.NewReader(make([]byte, MaxPacketBytes+1))
			if kind == "truncated" {
				body = brokenBody{}
			}
			w := packetRequest(s, "0", body)
			if w.Code != 400 {
				t.Fatal("invalid body accepted", w.Code)
			}
			select {
			case <-p.done:
			default:
				t.Fatal("invalid body retained session")
			}
		})
	}
}

type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestPacketGapExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &Server{Authorized: func(*http.Request) bool { return true }}
		p, _ := s.claim(testID, false)
		q, status := s.admitPacket(testID, 1)
		if status != 0 {
			t.Fatal(status)
		}
		s.mu.Lock()
		q.pending[1].data = []byte("late")
		q.pending[1].ready = true
		q.signalLocked()
		s.mu.Unlock()
		synctest.Wait()
		time.Sleep(PairTimeout + time.Second)
		synctest.Wait()
		select {
		case <-p.done:
		default:
			t.Fatal("missing sequence did not expire")
		}
	})
}
func TestPacketAckFailureDoesNotReplay(t *testing.T) {
	var requests atomic.Int64
	accepted := make(chan struct{})
	payload := []byte("never replay accepted bytes")
	received := make(chan []byte, 1)
	s := &Server{Authorized: func(*http.Request) bool { return true }, ServeConn: func(c net.Conn, _ *http.Request) {
		b := make([]byte, len(payload))
		_, _ = io.ReadFull(c, b)
		close(accepted)
		rest, _ := io.ReadAll(c)
		received <- append(b, rest...)
	}}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, seq, _ := parsePath(r)
		if seq != nil {
			requests.Add(1)
			recorder := httptest.NewRecorder()
			s.ServeHTTP(recorder, r)
			<-accepted
			w.WriteHeader(504) // Accepted upload but lost its acknowledgement.
			return
		}
		s.ServeHTTP(w, r)
	})
	server := httptest.NewUnstartedServer(h)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	c, err := Dial(context.Background(), server.Client().Transport, server.URL, "xhttp-packet-up", "token", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-received:
		if !bytes.Equal(b, payload) {
			t.Fatal("duplicated or lost accepted upload", len(b))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("failed ACK retained carrier")
	}
	// Handler activity is over before the application socket reports EOF.
	if requests.Load() != 1 {
		t.Fatal("automatic upload replay", requests.Load())
	}
}

func TestPacketStalledBodyExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &Server{Authorized: func(*http.Request) bool { return true }}
		p, _ := s.claim(testID, false)
		reader, writer := io.Pipe()
		defer writer.Close()
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- packetRequest(s, "0", reader) }()
		synctest.Wait()
		time.Sleep(PairTimeout + time.Second)
		synctest.Wait()
		select {
		case w := <-done:
			if w.Code != 400 {
				t.Fatal(w.Code)
			}
		default:
			t.Fatal("stalled body retained request")
		}
		select {
		case <-p.done:
		default:
			t.Fatal("stalled body retained session")
		}
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestPacketLengthWithoutAutomaticReplay(t *testing.T) {
	dest, _ := url.Parse("https://node" + Path + testID + "/0")
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.ContentLength != 3 || r.GetBody != nil {
			t.Fatal("unknown size or replayable packet", r.ContentLength, r.GetBody != nil)
		}
		got, _ := io.ReadAll(r.Body)
		if string(got) != "abc" {
			t.Fatal("body changed")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	resp, err := sendRequest(context.Background(), transport, dest, "POST", packetBody{bytes.NewReader([]byte("abc"))}, "token", "", false)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

type enteredReader struct {
	io.Reader
	entered chan struct{}
	once    sync.Once
}

func (r *enteredReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	return r.Reader.Read(p)
}

func FuzzCarrierPath(f *testing.F) {
	f.Add(Path+testID+"/0", "")
	f.Add(Path+testID+"/18446744073709551615", "")
	f.Add(Path+testID+"/00", "")
	f.Add(Path+testID, "%2f")
	f.Fuzz(func(t *testing.T, path, rawPath string) {
		r := &http.Request{URL: &url.URL{Path: path, RawPath: rawPath}}
		id, seq, ok := parsePath(r)
		if !ok {
			return
		}
		canonical := Path + id
		if seq != nil {
			canonical += "/" + strconv.FormatUint(*seq, 10)
		}
		if rawPath != "" || path != canonical || id != "" && !validID(id) {
			t.Fatal("ambiguous carrier path accepted")
		}
	})
}

func TestPacketBodyDeadlineWhilePriorDeliveryBlocked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &Server{Authorized: func(*http.Request) bool { return true }}
		p, _ := s.claim(testID, false)
		delivered := make(chan *httptest.ResponseRecorder, 1)
		go func() { delivered <- packetRequest(s, "0", strings.NewReader("blocked consumer")) }()
		synctest.Wait()
		reader, writer := io.Pipe()
		defer writer.Close()
		stalled := make(chan *httptest.ResponseRecorder, 1)
		go func() { stalled <- packetRequest(s, "1", reader) }()
		synctest.Wait()
		time.Sleep(PairTimeout + time.Second)
		synctest.Wait()
		select {
		case w := <-stalled:
			if w.Code != 400 {
				t.Fatal(w.Code)
			}
		default:
			t.Fatal("body timeout was blocked by delivery")
		}
		select {
		case w := <-delivered:
			if w.Code != 410 {
				t.Fatal(w.Code)
			}
		default:
			t.Fatal("blocked ACK retained")
		}
		select {
		case <-p.done:
		default:
			t.Fatal("session retained")
		}
	})
}
