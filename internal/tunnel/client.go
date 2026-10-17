package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Client exposes a local SOCKS5 CONNECT listener backed by HTTP/2 CONNECT.
// TLS uses the standard Go TLS implementation, not Firefox NSS.
type Client struct {
	ServerURL  *url.URL
	Username   string
	Password   string
	CACertFile string
	// ConnectTimeout bounds setup only, never the lifetime of an open stream.
	// Set before calling Serve; zero uses 15 seconds.
	ConnectTimeout time.Duration
	transport      *http.Transport
}

func NewClient(rawURL, user, password, caFile string) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("server must be an https://host[:port] URL")
	}
	if user == "" || password == "" || strings.Contains(user, ":") {
		return nil, errors.New("nonempty credentials and a username without colon are required")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("system CA store: %w", err)
	}
	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("CA file contains no PEM certificates")
		}
	}
	c := &Client{ServerURL: u, Username: user, Password: password, CACertFile: caFile}
	c.transport = &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ClientSessionCache: tls.NewLRUClientSessionCache(32)},
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return c, nil
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()

	// Host overrides the HTTP/2 :authority pseudo-header with the destination;
	// URL.Host still selects the HTTPS proxy endpoint for the TCP/TLS connection.
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, c.ServerURL.String(), reader)
	if err != nil {
		_ = socks5Reply(conn, 0x01)
		return
	}
	// An explicit setup timer also covers a server that never answers CONNECT.
	// ResponseHeaderTimeout alone need not cover a streaming request body.
	timeout := c.ConnectTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	setupTimer := time.AfterFunc(timeout, cancel)
	defer setupTimer.Stop()
	req.Host = target
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password)))
	resp, err := c.transport.RoundTrip(req)
	setupOK := setupTimer.Stop()
	if err != nil {
		_ = socks5Reply(conn, 0x05)
		return
	}
	defer resp.Body.Close()
	if !setupOK || resp.ProtoMajor != 2 || resp.StatusCode != http.StatusOK {
		_ = socks5Reply(conn, 0x05)
		return
	}
	if err := socks5Reply(conn, 0x00); err != nil {
		return
	}

	_ = conn.SetWriteDeadline(time.Time{})

	uploadDone := make(chan struct{})
	go func() {
		defer close(uploadDone)
		_, err := io.Copy(writer, conn)
		_ = writer.CloseWithError(err)
		if err != nil {
			cancel()
		}
	}()
	_, _ = io.Copy(conn, resp.Body)
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
		return "", errors.New("unsupported SOCKS greeting")
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
		return "", errors.New("SOCKS no-auth method unavailable")
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
		return "", errors.New("only SOCKS CONNECT is supported")
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
			return "", errors.New("empty hostname")
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return "", err
		}
		host = string(name)
	default:
		_ = socks5Reply(conn, 0x08)
		return "", errors.New("unsupported SOCKS address type")
	}
	var p [2]byte
	if _, err := io.ReadFull(conn, p[:]); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(p[:])
	if port == 0 || strings.ContainsAny(host, "\x00\r\n") {
		return "", errors.New("invalid destination")
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
