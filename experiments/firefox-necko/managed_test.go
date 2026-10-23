package firefox

import (
	"context"
	"errors"
	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestGeckoManagedIPC(t *testing.T) {
	bundle := os.Getenv("FOXTUNNEL_NECKO_BUNDLE")
	if bundle == "" {
		t.Skip("verified integration bundle required")
	}
	var requests atomic.Int32
	server := &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true}
	cfg := nativeProxy(t, "h2-connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); server.ServeHTTP(w, r) }))
	m, err := NewManaged(bundle, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = m.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	listen, tag := m.listen, m.profileTag
	m.mu.Unlock()
	if tag == "" || filepath.Base(tag) != tag {
		t.Fatal("invalid private profile tag")
	}
	for _, method := range []byte{0, 2} {
		c, e := net.DialTimeout("tcp", listen, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		c.Write([]byte{5, 1, method})
		var reply [2]byte
		if _, e = io.ReadFull(c, reply[:]); e != nil {
			c.Close()
			// Rejection may close the socket before the queued failure
			// frame reaches TCP. EOF is denial; timeout or success is not.
			if method == 0 && (errors.Is(e, io.EOF) || errors.Is(e, io.ErrUnexpectedEOF)) {
				continue
			}
			t.Fatal(e)
		}
		if method == 0 {
			if reply != [2]byte{5, 255} {
				t.Fatal("IPC accepted unauthenticated SOCKS")
			}
		} else {
			if reply != [2]byte{5, 2} {
				t.Fatal("IPC password method not selected")
			}
			c.Write([]byte{1, 1, 'x', 1, 'x'})
			_, e = io.ReadFull(c, reply[:])
			if e != nil {
				if !errors.Is(e, io.EOF) && !errors.Is(e, io.ErrUnexpectedEOF) {
					t.Fatal("IPC rejection did not finish", e)
				}
			} else if reply != [2]byte{1, 1} {
				t.Fatal("IPC accepted incorrect credentials")
			}
		}
		c.Close()
	}
	if requests.Load() != 0 {
		t.Fatal("unauthenticated IPC reached the HTTPS proxy")
	}
	c, err := m.DialContext(ctx, "tcp", nativeEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte("binary\x00\xff"))
	c.(interface{ CloseWrite() error }).CloseWrite()
	got, err := io.ReadAll(c)
	c.Close()
	if err != nil || string(got) != "binary\x00\xff" {
		t.Fatal("authenticated IPC transfer failed", err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(os.TempDir(), tag)); !os.IsNotExist(err) {
		t.Fatal("private helper profile survived Close")
	}
	if c, err = net.DialTimeout("tcp", listen, 100*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("helper listener survived Close")
	}
}
