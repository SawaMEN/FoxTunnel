package bond

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestAuditRejectsMalformedSuccessRecords(t *testing.T) {
	for _, tc := range []struct {
		name   string
		op     byte
		status int
		body   string
	}{
		{"upload-is-not-eof", opWrite, 201, ""},
		{"fin-is-not-eof", opFin, 201, ""},
		{"close-is-not-eof", opClose, 201, ""},
		{"eof-cannot-discard-data", opRead, 201, "lost bytes"},
		{"upload-ack-has-no-payload", opWrite, 200, "unexpected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := url.Parse("https://a.example")
			b, _ := url.Parse("https://b.example")
			calls := 0
			c := &Client{Endpoints: []*url.URL{a, b}, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				r.Body.Close()
				return &http.Response{StatusCode: tc.status, ProtoMajor: 2, ContentLength: int64(len(tc.body)), Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}
			var payload []byte
			if tc.op == opWrite {
				payload = []byte("upload")
			}
			_, err := c.request(context.Background(), make([]byte, 32), "hub", tc.op, 0, 0, payload)
			if err == nil {
				t.Fatal("malformed success record accepted")
			}
			if calls != 1 {
				t.Fatalf("protocol violation retried %d times", calls)
			}
		})
	}
}
