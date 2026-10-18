package webprofile

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestFragmentedMetadataAndBounds(t *testing.T) {
	r := &recorder{start: time.Now()}
	wire := wireParser{}
	// The secret body must never enter the exported metadata.
	record := append([]byte{23, 3, 3, 0, 6}, []byte("secret")...)
	for i := 0; i < maxEvents+9; i++ {
		for _, b := range record {
			wire.feed([]byte{b}, "client", r)
		}
	}
	if len(r.p.Records) != maxEvents || r.p.DroppedRecords != 9 || r.p.Records[0].Length != 6 {
		t.Fatal(r.p)
	}
	var b bytes.Buffer
	b.WriteString(http2.ClientPreface)
	f := http2.NewFramer(&b, nil)
	_ = f.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 131072}, http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536})
	_ = f.WriteWindowUpdate(0, 100)
	_ = f.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte("secret"), EndHeaders: true})
	_ = f.WriteWindowUpdate(0, 200) // After HEADERS: not an initial connection update.
	_ = f.WriteData(1, true, []byte("secret"))
	p := h2Parser{initial: true}
	for _, v := range b.Bytes() {
		p.feed([]byte{v}, r)
	}
	if len(r.p.Settings) != 2 || r.p.Settings[0] != (Setting{4, 131072}) || len(r.p.ConnectionWindow) != 1 || r.p.ConnectionWindow[0] != 100 {
		t.Fatal(r.p)
	}
	encoded, err := json.Marshal(r.p)
	if err != nil || bytes.Contains(encoded, []byte("secret")) {
		t.Fatal("payload leaked into metadata")
	}
	if len(r.p.Frames) != 5 {
		t.Fatal(r.p.Frames)
	}
	for i := 0; i < maxEvents+10; i++ {
		var h [9]byte
		h[3] = 6
		binary.BigEndian.PutUint32(h[5:], 0)
		p.feed(h[:], r)
	}
	if len(r.p.Frames) != maxEvents || r.p.DroppedFrames == 0 {
		t.Fatal("unbounded frames")
	}
}

func TestCaptureTLSH2(t *testing.T) {
	certSource := httptest.NewTLSServer(http.NotFoundHandler())
	defer certSource.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		// Verification is bypassed only for this in-process test certificate.
		tr := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		defer tr.CloseIdleConnections()
		res, e := tr.RoundTrip(mustRequest("https://" + l.Addr().String()))
		if e == nil {
			_, e = io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}
		done <- e
	}()
	p, err := Capture(l, certSource.TLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Error("missing endpoint TLS state")
		}
		_, _ = io.WriteString(w, "ok")
	}), "test", 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if p.ALPN != "h2" || len(p.Settings) == 0 || len(p.Records) == 0 || len(p.Frames) == 0 {
		t.Fatal(p)
	}
	if p.Hello.JA3 == "" {
		t.Fatal("missing ClientHello")
	}
}
func mustRequest(u string) *http.Request {
	r, e := http.NewRequest("GET", u, nil)
	if e != nil {
		panic(e)
	}
	return r
}
