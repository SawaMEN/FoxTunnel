package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/neqo"
	"github.com/SawaMEN/FoxTunnel/internal/nsstls"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// The browser and native clients use the same fixed, local GET workload.
// The browser bootstrap document is excluded from workload counters.
const page = `<!doctype html><meta charset="utf-8"><title>Loopback fixture</title>
<script>
async function get(path, size) {
 const r=await fetch(path,{cache:'no-store'});
 if(!r.ok) throw Error('status');
 const b=new Uint8Array(await r.arrayBuffer());
 if(b.length!==size || b.some(x=>x!==97)) throw Error('payload');
}
async function run() {
 await get('/cold',64);
 await new Promise(r=>setTimeout(r,500));
 for(let i=0;i<3;i++) await get('/sequential',64);
 await Promise.all(Array.from({length:8},()=>get('/parallel',262144)));
 await Promise.all(Array.from({length:4},async()=>{
  const c=new AbortController();
  const r=await fetch('/cancel',{signal:c.signal,cache:'no-store'});
  const reader=r.body.getReader();
  const first=await reader.read();
  if(first.done || !first.value.length) throw Error('empty stream');
  c.abort(); try { await reader.cancel(); } catch(e) {}
 }));
 for(let i=0;i<2;i++) {
  await get('/rotate',0);
  await new Promise(r=>setTimeout(r,800));
  await get('/reconnect',64);
 }
 await get('/done',0);
}
run().catch(()=>fetch('/failed',{cache:'no-store'}));
</script>`

type roundTripper interface {
	http.RoundTripper
	CloseIdleConnections()
}

func nativeWorkload(ctx context.Context, origin, cert, backend, protocol string) error {
	pem, err := os.ReadFile(cert)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("fixture CA missing")
	}
	cfg := &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13}
	if backend == "go" {
		// Positive control for server-side resumption observation. NSS and
		// Neqo own separate bounded native-token caches.
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	}
	var transport roundTripper
	if backend == "nss" {
		transport, err = nsstls.NewTransport(cfg)
	} else if backend == "nss-firefox" {
		transport, err = nsstls.NewTransportWithProfiles(cfg, "firefox-158", nsstls.Firefox158)
	} else if backend == "neqo" {
		transport, err = neqo.NewTransport(neqo.Config{TLS: cfg, HandshakeTimeout: 2 * time.Second})
	} else if backend == "go" && protocol == "h2" {
		transport = &http2.Transport{TLSClientConfig: cfg}
	} else if backend == "go" && protocol == "h3" {
		transport = &http3.Transport{TLSClientConfig: cfg}
	} else {
		return errors.New("invalid sample backend")
	}
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	get := func(callCtx context.Context, path string, size int, abort bool) error {
		url := strings.Replace(origin, "//localhost:", "//127.0.0.1:", 1) + path
		req, err := http.NewRequestWithContext(callCtx, "GET", url, nil)
		if err != nil {
			return err
		}
		req.Host = strings.TrimPrefix(origin, "https://")
		resp, err := transport.RoundTrip(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("fixture status %d", resp.StatusCode)
		}
		if abort {
			var first [1]byte
			_, err = io.ReadFull(resp.Body, first[:])
			return err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, int64(size+1)))
		if err != nil {
			return err
		}
		if len(body) != size {
			return errors.New("fixture payload length")
		}
		for _, b := range body {
			if b != 'a' {
				return errors.New("fixture payload mismatch")
			}
		}
		return nil
	}
	if err = get(ctx, "/cold", 64, false); err != nil {
		return err
	}
	if err = pause(ctx, 500*time.Millisecond); err != nil {
		return err
	}
	for range 3 {
		if err = get(ctx, "/sequential", 64, false); err != nil {
			return err
		}
	}
	parallel := func(n int, path string, size int, abort bool) error {
		var wg sync.WaitGroup
		failures := make(chan error, n)
		for range n {
			wg.Go(func() {
				callCtx, cancel := context.WithCancel(ctx)
				defer cancel()
				if err := get(callCtx, path, size, abort); err != nil {
					failures <- err
				}
			})
		}
		wg.Wait()
		close(failures)
		for err := range failures {
			return err
		}
		return nil
	}
	if err = parallel(8, "/parallel", 262144, false); err != nil {
		return err
	}
	if err = parallel(4, "/cancel", 0, true); err != nil {
		return err
	}
	for range 2 {
		if err = get(ctx, "/rotate", 0, false); err != nil {
			return err
		}
		if err = pause(ctx, 800*time.Millisecond); err != nil {
			return err
		}
		if err = get(ctx, "/reconnect", 64, false); err != nil {
			return err
		}
	}
	return get(ctx, "/done", 0, false)
}

func pause(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
