package firefox

import (
	"context"
	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGeckoManagedIPC(t *testing.T) {
	bundle := os.Getenv("FOXTUNNEL_NECKO_BUNDLE")
	if bundle == "" {
		t.Skip("verified integration bundle required")
	}
	cfg := nativeProxy(t, "h2-connect", &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true})
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
			if _, e = io.ReadFull(c, reply[:]); e != nil || reply != [2]byte{1, 1} {
				t.Fatal("IPC accepted incorrect credentials", e)
			}
		}
		c.Close()
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
