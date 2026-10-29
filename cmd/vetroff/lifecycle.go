package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/SawaMEN/VetroffProxy/internal/tunnel"
	"golang.org/x/net/netutil"
)

// serveListeners owns both listeners and treats an unexpected carrier failure
// as a server failure. Cancellation interrupts active tunnels, then allows a
// bounded period for handlers and accounting to finish before forcing close.
func serveListeners(parent context.Context, server *http.Server, handler *tunnel.Server,
	listener net.Listener, udp net.PacketConn, limit int) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer listener.Close()
	if udp != nil {
		defer udp.Close()
	}
	server.BaseContext = func(net.Listener) context.Context { return ctx }
	results := make(chan error, 2)
	count := 1
	config := server.TLSConfig.Clone()
	go func() { results <- server.ServeTLS(netutil.LimitListener(listener, limit), "", "") }()
	if udp != nil {
		count++
		go func() { results <- handler.ServeHTTP3(ctx, udp, config, limit) }()
	}
	var first error
	select {
	case <-parent.Done():
	case first = <-results:
		count--
	}
	cancel()
	deadline, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := server.Shutdown(deadline); err != nil {
		_ = server.Close()
	}
	for count > 0 {
		select {
		case <-results:
			count--
		case <-deadline.Done():
			return errors.New("server shutdown timed out")
		}
	}
	if parent.Err() != nil {
		return nil
	}
	if first == nil || errors.Is(first, http.ErrServerClosed) || errors.Is(first, net.ErrClosed) {
		return errors.New("server listener stopped unexpectedly")
	}
	return first
}

func serverTLS(get func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"}, GetCertificate: get}
}
