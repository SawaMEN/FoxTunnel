package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/SawaMEN/FoxTunnel/internal/i18n"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/bond"
	"github.com/SawaMEN/FoxTunnel/internal/nsstls"
)

// Client exposes a local SOCKS5 CONNECT listener backed by HTTP/2 CONNECT.
// Go TLS is the default; tagged Linux builds can opt into experimental NSS.
type Client struct {
	ServerURL  *url.URL
	Username   string
	Password   string
	CACertFile string
	// ConnectTimeout bounds setup only, never the lifetime of an open stream.
	// Set before calling Serve; zero uses 15 seconds.
	ConnectTimeout time.Duration
	// Padding is an opt-in experiment; configure before Serve.
	Padding bool
	// FallbackAttemptTimeout applies only with multiple configured endpoints.
	// Zero uses five seconds; ConnectTimeout bounds all attempts together.
	FallbackAttemptTimeout time.Duration
	fallbackServers        []*url.URL
	preferredEndpoint      atomic.Uint32
	schedulerMu            sync.Mutex
	balance                string
	nextEndpoint           uint64
	activeEndpoints        [maxProxyEndpoints]int
	endpointFailures       [maxProxyEndpoints]uint8
	endpointRetryAt        [maxProxyEndpoints]time.Time
	transport              interface {
		http.RoundTripper
		CloseIdleConnections()
	}
	// BondPipeline is 0 (automatic), 4 or 8; set before EnableBond.
	BondPipeline int
	bondClient   *bond.Client
	tlsConfig    *tls.Config
}

func NewClient(rawURL, user, password, caFile string) (*Client, error) {
	u, err := parseServerURL(rawURL)
	if err != nil {
		return nil, err
	}
	if user == "" || password == "" || strings.Contains(user, ":") {
		return nil, errors.New(i18n.Text("nonempty credentials and a username without colon are required"))
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf(i18n.Text("system CA store: %w"), err)
	}
	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New(i18n.Text("CA file contains no PEM certificates"))
		}
	}
	c := &Client{ServerURL: u, Username: user, Password: password, CACertFile: caFile}
	c.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ClientSessionCache: tls.NewLRUClientSessionCache(32)}
	c.transport = newGoTransport(c.tlsConfig)

	return c, nil
}

func newGoTransport(config *tls.Config) *http.Transport {
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	return &http.Transport{
		Protocols: protocols,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialGoH2(ctx, network, addr, config)
		},
		TLSClientConfig:   config.Clone(),
		DialContext:       (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true, DisableCompression: true,
		MaxIdleConns: 64, MaxIdleConnsPerHost: 16,
		IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second,
	}
}

// SetTLSBackend selects a backend before Serve starts. It never falls back
// silently: an unavailable NSS build returns an error.
func (c *Client) SetTLSBackend(name string) error {
	switch name {
	case "go":
		c.transport.CloseIdleConnections()
		c.transport = newGoTransport(c.tlsConfig)
		return nil
	case "nss":
		transport, err := nsstls.NewTransport(c.tlsConfig)
		if err != nil {
			return err
		}
		c.transport.CloseIdleConnections()
		c.transport = transport
		return nil
	default:
		return fmt.Errorf(i18n.Text("unknown TLS backend %q (choose go or nss)"), name)
	}
}

func (c *Client) Close() { c.transport.CloseIdleConnections() }

func (c *Client) Serve(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go c.handle(conn)
	}
}

func (c *Client) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	target, err := socks5Handshake(conn)
	if err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	if c.bondClient != nil {
		c.handleBond(conn, target)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := c.openTunnel(ctx, target)
	if err != nil {
		_ = socks5Reply(conn, 0x05)
		return
	}
	defer stream.close()
	writer := stream.writer
	resp := stream.response
	var upload io.Writer = writer
	var download io.Reader = resp.Body
	if c.Padding {
		upload = newPaddingWriter(writer)
		download = newPaddingReader(resp.Body)
	}
	if err := socks5Reply(conn, 0x00); err != nil {
		return
	}

	_ = conn.SetWriteDeadline(time.Time{})

	uploadDone := make(chan struct{})
	go func() {
		defer close(uploadDone)
		_, err := io.Copy(upload, conn)
		_ = writer.CloseWithError(err)
		if err != nil {
			cancel()
		}
	}()
	_, _ = io.Copy(conn, download)
	cancel()
	_ = conn.Close()
	_ = writer.Close()
	<-uploadDone
}

func socks5Handshake(conn net.Conn) (string, error) {
	var hello [2]byte
	if _, err := io.ReadFull(conn, hello[:]); err != nil {
		return "", err
	}
	if hello[0] != 5 || hello[1] == 0 {
		return "", errors.New(i18n.Text("unsupported SOCKS greeting"))
	}
	methods := make([]byte, int(hello[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	noAuth := false
	for _, m := range methods {
		if m == 0 {
			noAuth = true
		}
	}
	if !noAuth {
		_, _ = conn.Write([]byte{5, 0xff})
		return "", errors.New(i18n.Text("SOCKS no-auth method unavailable"))
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return "", err
	}
	var h [4]byte
	if _, err := io.ReadFull(conn, h[:]); err != nil {
		return "", err
	}
	if h[0] != 5 || h[1] != 1 || h[2] != 0 {
		_ = socks5Reply(conn, 0x07)
		return "", errors.New(i18n.Text("only SOCKS CONNECT is supported"))
	}
	var host string
	switch h[3] {
	case 1:
		var addr [4]byte
		if _, err := io.ReadFull(conn, addr[:]); err != nil {
			return "", err
		}
		host = net.IP(addr[:]).String()
	case 4:
		var addr [16]byte
		if _, err := io.ReadFull(conn, addr[:]); err != nil {
			return "", err
		}
		host = net.IP(addr[:]).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return "", err
		}
		if n[0] == 0 {
			return "", errors.New(i18n.Text("empty hostname"))
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return "", err
		}
		host = string(name)
	default:
		_ = socks5Reply(conn, 0x08)
		return "", errors.New(i18n.Text("unsupported SOCKS address type"))
	}
	var p [2]byte
	if _, err := io.ReadFull(conn, p[:]); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(p[:])
	if port == 0 || strings.ContainsAny(host, "\x00\r\n") {
		return "", errors.New(i18n.Text("invalid destination"))
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func socks5Reply(w io.Writer, code byte) error {
	if conn, ok := w.(net.Conn); ok {
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	}
	_, err := w.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}
