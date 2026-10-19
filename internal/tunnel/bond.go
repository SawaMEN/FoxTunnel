package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/access"
	"github.com/SawaMEN/FoxTunnel/internal/bond"
	"github.com/SawaMEN/FoxTunnel/internal/i18n"
)

// EnableBond must be called after endpoint/TLS configuration, before Serve.
func (c *Client) EnableBond() error {
	if c.bondDiscovery != nil {
		return i18n.Error("invalid cluster configuration")
	}
	if c.BondPipeline != 0 && c.BondPipeline != 4 && c.BondPipeline != 8 {
		return errors.New(i18n.Text("bond pipeline must be auto, 4 or 8"))
	}
	if len(c.fallbackServers) == 0 {
		return errors.New(i18n.Text("bond requires at least two trusted nodes"))
	}
	if c.FallbackAttemptTimeout > 0 && c.FallbackAttemptTimeout < 100*time.Millisecond {
		return errors.New(i18n.Text("bond attempt timeout must be at least 100ms"))
	}
	if c.Padding {
		return errors.New(i18n.Text("bond and initial-v1 padding cannot be combined"))
	}
	c.bondClient = &bond.Client{Endpoints: append([]*url.URL{c.ServerURL}, c.fallbackServers...), Transport: c.transport, Username: c.Username, Password: c.Password, AttemptTimeout: c.FallbackAttemptTimeout, SetupTimeout: c.ConnectTimeout, Pipeline: c.BondPipeline, PersistentLanes: c.BondLanes}
	return nil
}
func (c *Client) handleBond(conn net.Conn, target string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	carrier := c.bondClient
	if c.bondDiscovery != nil {
		var err error
		carrier, err = c.discoveredBond(ctx)
		if err != nil {
			_ = socks5Reply(conn, 0x05)
			return
		}
	}
	stream, err := carrier.Open(ctx, target)
	if err != nil {
		_ = socks5Reply(conn, 0x05)
		return
	}
	defer stream.Close()
	if err := socks5Reply(conn, 0); err != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Time{})
	uploadDone := make(chan struct{})
	go func() {
		defer close(uploadDone)
		_, err := io.Copy(stream, conn)
		if err == nil {
			err = stream.CloseWrite()
		}
		if err != nil {
			cancel()
		}
	}()
	_, _ = io.Copy(conn, stream)
	cancel()
	_ = conn.Close()
	_ = stream.Close()
	<-uploadDone
}

// NewBondHub uses the same resolved-IP policy as ordinary CONNECT.
func (s *Server) NewBondHub() *bond.Hub {
	return &bond.Hub{MaxSessions: s.MaxTunnels, Owner: access.Owner, SessionContext: access.Scope, Dial: func(ctx context.Context, target string) (net.Conn, error) {
		host, port, err := splitTarget(target)
		if err != nil {
			return nil, err
		}
		return s.dialTarget(ctx, host, port)
	}}
}

// NewBondRelay forwards only to one explicit trusted hub over verified TLS/h2.
// Configure the same proxy credentials on the relay and hub. No redirects.
func NewBondRelay(raw, user, password, ca string) (http.Handler, func(), error) {
	return NewBondRelayIdentity(raw, user, password, ca, "", "")
}

func NewBondRelayIdentity(raw, user, password, ca, sni, pin string) (http.Handler, func(), error) {
	upstream, err := NewClient(raw, user, password, ca)
	if err != nil {
		return nil, nil, err
	}
	if err := upstream.SetServerIdentity(sni, pin); err != nil {
		upstream.Close()
		return nil, nil, err
	}
	endpoint := *upstream.ServerURL
	endpoint.Path = bond.Path
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := r.Clone(r.Context())
		req.URL = &endpoint
		req.Host = endpoint.Host
		req.RequestURI = ""
		streaming := r.Header.Get(bond.LaneHeader) == bond.LaneVersion
		if !streaming {
			req.Body = io.NopCloser(io.LimitReader(r.Body, 64<<10))
		}
		resp, err := upstream.transport.RoundTrip(req)
		if err != nil {
			status := http.StatusGatewayTimeout
			if terminalSetupError(err) {
				status = http.StatusBadGateway
			}
			http.Error(w, "hub unavailable", status)
			return
		}
		defer resp.Body.Close()
		if resp.Header.Get(bond.LaneHeader) == bond.LaneVersion {
			w.Header().Set(bond.LaneHeader, bond.LaneVersion)
		}
		w.WriteHeader(resp.StatusCode)
		if resp.ContentLength == 0 {
			return
		}
		if streaming {
			if err := http.NewResponseController(w).Flush(); err != nil {
				return
			}
			_, _ = copyBondLaneResponse(w, resp.Body)
		} else {
			_, _ = copyBondResponse(w, io.LimitReader(resp.Body, 64<<10))
		}
	})
	return handler, upstream.Close, nil
}

// One global bounded cache avoids allocating a copy buffer for every relay RPC.
// Buffers are exclusively owned during CopyBuffer and cleared before reuse.
var relayCopyBuffers = make(chan *[32 << 10]byte, 32)

func copyBondResponse(w io.Writer, r io.Reader) (int64, error) {
	var buffer *[32 << 10]byte
	select {
	case buffer = <-relayCopyBuffers:
	default:
		buffer = new([32 << 10]byte)
	}
	defer func() {
		clear(buffer[:])
		select {
		case relayCopyBuffers <- buffer:
		default:
		}
	}()
	return io.CopyBuffer(w, r, buffer[:])
}

// Forward one bounded reply at a time. Flushing arbitrary transport Read chunks
// would turn a split six-byte header into its own TLS/H2 write.
func copyBondLaneResponse(w http.ResponseWriter, r io.Reader) (int64, error) {
	buffer := make([]byte, (32<<10)+6)
	var total int64
	for {
		if _, err := io.ReadFull(r, buffer[:6]); err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
		n := int(binary.BigEndian.Uint32(buffer[2:6]))
		if n > 32<<10 {
			return total, errors.New("oversized bond lane reply")
		}
		if _, err := io.ReadFull(r, buffer[6:6+n]); err != nil {
			return total, err
		}
		written, err := w.Write(buffer[:6+n])
		total += int64(written)
		if err != nil {
			return total, err
		}
		if written != 6+n {
			return total, io.ErrShortWrite
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			return total, err
		}
	}
}
