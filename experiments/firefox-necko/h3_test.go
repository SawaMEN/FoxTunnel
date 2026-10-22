package firefox

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/quic-go/quic-go/http3"
)

func serveTestH3(ctx context.Context, socket net.PacketConn, config *tls.Config, handler http.Handler) error {
	server := &http3.Server{TLSConfig: config.Clone(), Handler: handler}
	defer server.Close()
	stop := context.AfterFunc(ctx, func() { server.Close() })
	defer stop()
	return server.Serve(socket)
}
