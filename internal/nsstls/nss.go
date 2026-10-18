//go:build nss && cgo && linux

// Package nsstls provides an experimental NSS TLS 1.3 client over Go-managed
// TCP sockets. It does not implement Firefox Necko or Firefox fingerprint parity.
package nsstls

/*
#cgo pkg-config: nss nspr
#include <stdlib.h>
#include "bridge.h"
*/
import "C"

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/SawaMEN/FoxTunnel/internal/h2profile"
	"github.com/SawaMEN/FoxTunnel/internal/i18n"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"runtime/cgo"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

type Transport interface {
	http.RoundTripper
	CloseIdleConnections()
}

var initOnce sync.Once
var initError error

func NewTransport(config *tls.Config) (Transport, error) {
	return NewTransportWithProfile(config, "")
}
func NewTransportWithProfile(config *tls.Config, profile string) (Transport, error) {
	if err := h2profile.Validate(profile); err != nil {
		return nil, err
	}
	if config.InsecureSkipVerify {
		return nil, i18n.Error("TLS verification cannot be disabled")
	}
	if config.VerifyPeerCertificate != nil {
		return nil, i18n.Error("unsupported NSS certificate callback (use VerifyConnection)")
	}
	initOnce.Do(func() {
		if code := C.ft_init(); code != 0 {
			initError = fmt.Errorf(i18n.Text("NSS initialization failed: %d"), code)
		}
	})
	if initError != nil {
		return nil, initError
	}
	config = config.Clone()
	h1 := &http.Transport{TLSClientConfig: config.Clone(), DisableCompression: true, IdleConnTimeout: 90 * time.Second}
	if err := h2profile.Configure(h1, profile); err != nil {
		return nil, err
	}
	transport, err := http2.ConfigureTransports(h1)
	if err != nil {
		return nil, err
	}
	// ConfigureTransports installs a no-dial pool intended for h1's ALPN
	// handoff. This adapter returns h2 directly and must own its dial pool.
	transport.ConnPool = nil
	transport.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		setup, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		raw, err := (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(setup, network, addr)
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			raw.Close()
			return nil, err
		}
		if config.ServerName != "" {
			host = config.ServerName
		}
		return wrapConfig(setup, raw, host, config)
	}
	return transport, nil
}

type conn struct {
	raw                          net.Conn
	fd                           *C.PRFileDesc
	handle                       cgo.Handle
	readMu, writeMu              sync.Mutex
	closeOnce                    sync.Once
	closed                       atomic.Bool
	errMu                        sync.Mutex
	readErr, writeErr, verifyErr error
	serverName                   string
	protocol                     string
	roots                        *x509.CertPool
	certificates                 []*x509.Certificate
	verifiedChains               [][]*x509.Certificate
	verifyConnection             func(tls.ConnectionState) error
}

func wrap(ctx context.Context, raw net.Conn, name string, roots *x509.CertPool) (*conn, error) {
	return wrapConfig(ctx, raw, name, &tls.Config{RootCAs: roots})
}
func wrapConfig(ctx context.Context, raw net.Conn, name string, config *tls.Config) (*conn, error) {
	protocol := "h2"
	if len(config.NextProtos) != 0 {
		if len(config.NextProtos) != 1 || (config.NextProtos[0] != "h2" && config.NextProtos[0] != "http/1.1") {
			raw.Close()
			return nil, i18n.Error("unsupported NSS ALPN")
		}
		protocol = config.NextProtos[0]
	}
	cprotocol := C.CString(protocol)
	defer C.free(unsafe.Pointer(cprotocol))
	c := &conn{raw: raw, serverName: name, protocol: protocol, roots: config.RootCAs, verifyConnection: config.VerifyConnection}
	c.handle = cgo.NewHandle(c)
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	local, _, _ := net.SplitHostPort(raw.LocalAddr().String())
	remote, _, _ := net.SplitHostPort(raw.RemoteAddr().String())
	clocal := C.CString(local)
	defer C.free(unsafe.Pointer(clocal))
	cremote := C.CString(remote)
	defer C.free(unsafe.Pointer(cremote))
	var code C.int
	c.fd = C.ft_new(C.uintptr_t(c.handle), cname, clocal, cremote, cprotocol, &code)
	if c.fd == nil {
		c.handle.Delete()
		raw.Close()
		return nil, fmt.Errorf(i18n.Text("NSS connection settings: %d"), code)
	}
	// Cancellation closes Go's socket, which unblocks any NSS I/O callback.
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	result := C.ft_handshake(c.fd, cprotocol, &code)
	stopped := stop()
	if result < 0 || !stopped || ctx.Err() != nil {
		c.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if c.verifyErr != nil {
			return nil, c.verifyErr
		}
		return nil, fmt.Errorf(i18n.Text("NSS handshake/ALPN failed: %d"), code)
	}
	_ = raw.SetDeadline(time.Time{})
	return c, nil
}

func (c *conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	var code C.int
	n := C.ft_read(c.fd, unsafe.Pointer(&p[0]), C.int(min(len(p), 1<<30)), &code)
	if n < 0 {
		c.errMu.Lock()
		err := c.readErr
		c.errMu.Unlock()
		if err != nil {
			return 0, err
		}
		return 0, fmt.Errorf(i18n.Text("NSS read failed: %d"), code)
	}
	if n == 0 {
		return 0, io.EOF
	}
	return int(n), nil
}
func (c *conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	var code C.int
	n := C.ft_write(c.fd, unsafe.Pointer(&p[0]), C.int(min(len(p), 1<<30)), &code)
	if n < 0 {
		c.errMu.Lock()
		err := c.writeErr
		c.errMu.Unlock()
		if err != nil {
			return 0, err
		}
		return 0, fmt.Errorf(i18n.Text("NSS write failed: %d"), code)
	}
	if int(n) < len(p) {
		return int(n), io.ErrShortWrite
	}
	return int(n), nil
}
func (c *conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		err = c.raw.Close()
		// Wait for callbacks to unwind before freeing NSS state and cgo handle.
		c.readMu.Lock()
		c.writeMu.Lock()
		C.ft_close(c.fd)
		c.handle.Delete()
		c.writeMu.Unlock()
		c.readMu.Unlock()
	})
	return err
}
func (c *conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
func (c *conn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, NegotiatedProtocol: c.protocol, ServerName: c.serverName, PeerCertificates: c.certificates, VerifiedChains: c.verifiedChains}
}

//export ft_go_read
func ft_go_read(handle C.uintptr_t, buffer unsafe.Pointer, length C.int) C.int {
	c := cgo.Handle(handle).Value().(*conn)
	n, err := c.raw.Read(unsafe.Slice((*byte)(buffer), int(length)))
	c.errMu.Lock()
	c.readErr = err
	c.errMu.Unlock()
	if n > 0 {
		return C.int(n)
	}
	if errors.Is(err, io.EOF) {
		return 0
	}
	if err != nil {
		return -1
	}
	return 0
}

//export ft_go_write
func ft_go_write(handle C.uintptr_t, buffer unsafe.Pointer, length C.int) C.int {
	c := cgo.Handle(handle).Value().(*conn)
	p := unsafe.Slice((*byte)(buffer), int(length))
	total := 0
	// NSPR's blocking send contract requires the complete buffer or an error.
	for total < len(p) {
		n, err := c.raw.Write(p[total:])
		total += n
		if err != nil || n == 0 {
			if err == nil {
				err = io.ErrShortWrite
			}
			c.errMu.Lock()
			c.writeErr = err
			c.errMu.Unlock()
			return -1
		}
	}
	return C.int(total)
}

//export ft_go_cert
func ft_go_cert(handle C.uintptr_t, buffer unsafe.Pointer, length C.int) C.int {
	c := cgo.Handle(handle).Value().(*conn)
	if length <= 0 || length > 1<<20 || len(c.certificates) >= 16 {
		return 0
	}
	cert, err := x509.ParseCertificate(C.GoBytes(buffer, length))
	if err != nil {
		c.verifyErr = err
		return 0
	}
	c.certificates = append(c.certificates, cert)
	return 1
}

//export ft_go_verify
func ft_go_verify(handle C.uintptr_t) C.int {
	c := cgo.Handle(handle).Value().(*conn)
	if len(c.certificates) == 0 {
		c.verifyErr = errors.New(i18n.Text("NSS peer provided no certificate"))
		return 0
	}
	intermediates := x509.NewCertPool()
	for _, cert := range c.certificates[1:] {
		intermediates.AddCert(cert)
	}
	c.verifiedChains, c.verifyErr = c.certificates[0].Verify(x509.VerifyOptions{DNSName: c.serverName, Roots: c.roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if c.verifyErr != nil {
		return 0
	}
	if c.verifyConnection != nil {
		c.verifyErr = c.verifyConnection(c.ConnectionState())
		if c.verifyErr != nil {
			return 0
		}
	}
	return 1
}

// Version identifies the linked NSS library for measurement provenance.
func Version() string { return C.GoString(C.ft_version()) }

// DialTLSContext verifies TLS 1.3 and exactly the requested h2 or http/1.1 ALPN.
// It is used by native WSS; it does not emulate the Firefox HTTP stack.
func DialTLSContext(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
	if config.InsecureSkipVerify || config.VerifyPeerCertificate != nil {
		return nil, i18n.Error("TLS verification cannot be disabled")
	}
	initOnce.Do(func() {
		if code := C.ft_init(); code != 0 {
			initError = fmt.Errorf(i18n.Text("NSS initialization failed: %d"), code)
		}
	})
	if initError != nil {
		return nil, initError
	}
	setup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(setup, network, addr)
	if err != nil {
		return nil, err
	}
	name := config.ServerName
	if name == "" {
		name, _, err = net.SplitHostPort(addr)
		if err != nil {
			raw.Close()
			return nil, err
		}
	}
	return wrapConfig(setup, raw, name, config)
}
