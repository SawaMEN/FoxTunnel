package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SawaMEN/VetroffProxy/internal/xhttp"
)

func TestXHTTPIdleCloseRetiresPendingDial(t *testing.T) {
	for _, mode := range []string{"xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) {
			entered, resume := make(chan struct{}), make(chan struct{})
			var once sync.Once
			carrier := &xhttp.Server{Authorized: func(*http.Request) bool { return true }, ServeConn: func(c net.Conn, _ *http.Request) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}}
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				once.Do(func() { close(entered); <-resume })
				carrier.ServeHTTP(w, r)
			}))
			s.EnableHTTP2 = true
			s.StartTLS()
			defer s.Close()
			roots := x509.NewCertPool()
			roots.AddCert(s.Certificate())
			transport, err := newXHTTPTransport(mode, "go", &tls.Config{RootCAs: roots}, "", xhttp.Settings{}, "", "")
			if err != nil {
				t.Fatal(err)
			}
			tx := transport.(*xhttpTransport)
			defer tx.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				conn, err := tx.DialTLSContext(ctx, "tcp", strings.TrimPrefix(s.URL, "https://"), nil)
				if conn != nil {
					_ = conn.Close()
				}
				result <- err
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				close(resume)
				t.Fatal("carrier handshake did not start")
			}
			tx.CloseIdleConnections()
			close(resume)
			if err := <-result; !errors.Is(err, net.ErrClosed) {
				t.Fatalf("retired pending carrier returned %v, want net.ErrClosed", err)
			}
			// Retiring an earlier dial must still allow a new connection.
			conn, err := tx.DialTLSContext(ctx, "tcp", strings.TrimPrefix(s.URL, "https://"), nil)
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
		})
	}
}
