package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func quicConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second, MaxIdleTimeout: 90 * time.Second,
		MaxIncomingStreams: 32, MaxIncomingUniStreams: 8,
		InitialStreamReceiveWindow: 64 << 10, MaxStreamReceiveWindow: 512 << 10,
		InitialConnectionReceiveWindow: 1 << 20, MaxConnectionReceiveWindow: 8 << 20,
		Allow0RTT: false,
	}
}

func isH3Transport(mode string) bool { return mode == "h3-post" || mode == "h3-connect" }

func newH3Transport(config *tls.Config) tlsTransport {
	return postTransport{tlsTransport: newH3ConnectTransport(config), host: config.ServerName}
}

func newH3ConnectTransport(config *tls.Config) tlsTransport {
	cfg := config.Clone()
	cfg.NextProtos = []string{http3.NextProtoH3}
	recovery := &h3RecoveryTransport{newPool: func() h3Pool {
		t := &http3.Transport{TLSClientConfig: cfg.Clone(), QUICConfig: quicConfig(), DisableCompression: true, MaxResponseHeaderBytes: 32 << 10}
		// Complete verified TLS before credentials; each connection owns UDP.
		t.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, qCfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, addr, tlsCfg, qCfg)
		}
		return t
	}}
	return recovery
}

// ServeHTTP3 serves the same authorization, destination policy, discovery and
// hub as the TCP listener. The caller owns and must close packetConn.
// Cancellation releases QUIC connections and stops accepting new ones.
func (s *Server) ServeHTTP3(ctx context.Context, packetConn net.PacketConn, config *tls.Config, maxConnections int) error {
	if maxConnections < 1 {
		return errors.New("invalid HTTP/3 connection limit")
	}
	var active atomic.Int64
	transport := &quic.Transport{Conn: packetConn,
		VerifySourceAddress: func(net.Addr) bool { return active.Load() >= int64(maxConnections/2) },
		ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
			if active.Add(1) > int64(maxConnections) {
				active.Add(-1)
				return nil, errors.New("HTTP/3 server busy")
			}
			context.AfterFunc(ctx, func() { active.Add(-1) })
			return ctx, nil
		},
	}
	defer transport.Close()
	cfg := config.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.MaxVersion = tls.VersionTLS13
	cfg.NextProtos = []string{http3.NextProtoH3}
	listener, err := transport.ListenEarly(cfg, quicConfig())
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http3.Server{Handler: s, MaxHeaderBytes: 32 << 10, IdleTimeout: 90 * time.Second}
	defer server.Close()
	stop := context.AfterFunc(ctx, func() { server.Close(); listener.Close() })
	defer stop()
	err = server.ServeListener(listener)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
