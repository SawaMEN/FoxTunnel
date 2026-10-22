//go:build nss && cgo && linux

package nsstls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestNSSSessionResumptionTrustAndIsolation(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(disabled), func(t *testing.T) {
			var requests atomic.Int32
			observed := make(chan bool, 4)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				observed <- r.TLS.DidResume
				_, _ = w.Write([]byte("verified"))
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			var reject atomic.Bool
			var expired atomic.Bool
			var callbacks atomic.Int32
			pinError := errors.New("pin changed")
			config := &tls.Config{RootCAs: roots, SessionTicketsDisabled: disabled, Time: func() time.Time {
				if expired.Load() {
					return server.Certificate().NotAfter.Add(time.Hour)
				}
				return time.Now()
			}, VerifyConnection: func(state tls.ConnectionState) error {
				callbacks.Add(1)
				if len(state.VerifiedChains) == 0 {
					return errors.New("missing verified chain")
				}
				if reject.Load() {
					return pinError
				}
				return nil
			}}
			transport, err := NewTransport(config)
			if err != nil {
				t.Fatal(err)
			}
			defer transport.CloseIdleConnections()
			get := func(tr Transport) error {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
				resp, err := tr.RoundTrip(req)
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				_, err = io.Copy(io.Discard, resp.Body)
				return err
			}
			if err := get(transport); err != nil {
				t.Fatal(err)
			}
			if <-observed {
				t.Fatal("cold connection resumed")
			}
			transport.CloseIdleConnections()
			if err := get(transport); err != nil {
				t.Fatal(err)
			}
			if resumed := <-observed; resumed == disabled {
				t.Fatalf("resumed=%v, disabled=%v", resumed, disabled)
			}
			if callbacks.Load() != 2 {
				t.Fatalf("verification callbacks=%d, want 2", callbacks.Load())
			}
			other, err := NewTransport(config)
			if err != nil {
				t.Fatal(err)
			}
			defer other.CloseIdleConnections()
			if err := get(other); err != nil {
				t.Fatal(err)
			}
			if <-observed {
				t.Fatal("ticket leaked to another transport")
			}
			transport.CloseIdleConnections()
			reject.Store(true)
			if err := get(transport); !errors.Is(err, pinError) {
				t.Fatalf("pin rejection: %v", err)
			}
			if requests.Load() != 3 {
				t.Fatal("HTTP data reached server after pin rejection")
			}
			// Refresh one ticket, then let the saved certificate expire without
			// expiring the ticket. X.509 verification must still reject it.
			reject.Store(false)
			if err := get(transport); err != nil {
				t.Fatal(err)
			}
			<-observed
			transport.CloseIdleConnections()
			expired.Store(true)
			if err := get(transport); err == nil {
				t.Fatal("expired certificate accepted")
			}
			if requests.Load() != 4 {
				t.Fatal("HTTP data reached server after expiry")
			}
		})
	}
}

func TestNSSSessionCacheBoundsAndSingleUse(t *testing.T) {
	s := &sessionCache{}
	cert := &x509.Certificate{Raw: []byte{1}}
	entry := session{token: []byte{1}, certificates: []*x509.Certificate{cert}, expires: time.Now().Add(time.Hour)}
	for i := range 9 {
		s.put(strconv.Itoa(i), entry)
	}
	if len(s.entries) != 8 || len(s.take("0").token) != 0 {
		t.Fatal("cache failed to evict oldest origin")
	}
	if len(s.take("1").token) != 1 || len(s.take("1").token) != 0 {
		t.Fatal("ticket is not single-use")
	}
	if len(s.take("different-origin").token) != 0 {
		t.Fatal("origin isolation failed")
	}
	entry.expires = time.Now().Add(-time.Second)
	s.put("expired", entry)
	if len(s.take("expired").token) != 0 {
		t.Fatal("expired ticket accepted")
	}
}
