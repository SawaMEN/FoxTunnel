package firefox

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func serveTestH3(ctx context.Context, socket net.PacketConn, config *tls.Config, handler http.Handler, quicConfig ...*quic.Config) error {
	server := &http3.Server{TLSConfig: config.Clone(), Handler: handler}
	if len(quicConfig) > 0 {
		server.QUICConfig = quicConfig[0]
	}
	defer server.Close()
	stop := context.AfterFunc(ctx, func() { server.Close() })
	defer stop()
	return server.Serve(socket)
}
