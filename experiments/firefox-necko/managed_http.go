package firefox

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxHTTPMetadata = 16384
const maxHTTPChunk = 32768

type httpIPCRequest struct {
	Origin  string      `json:"origin"`
	Method  string      `json:"method"`
	Path    string      `json:"path"`
	Host    string      `json:"host"`
	Headers [][2]string `json:"headers"`
	Body    bool        `json:"body"`
	Length  int64       `json:"length"`
}
type httpIPCResponse struct {
	Status  int         `json:"status"`
	Proto   int         `json:"proto"`
	Headers [][2]string `json:"headers"`
}

// privateHTTPConn authenticates a local IPC operation. No network HTTP/TLS is
// implemented here: public requests are constructed and sent by libxul.
func (m *Managed) privateHTTPConn(ctx context.Context) (net.Conn, error) {
	if err := m.Ready(ctx); err != nil {
		return nil, err
	}
	m.mu.Lock()
	address, closed := m.listen, m.closed
	m.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			c.Close()
		}
	}()
	if d, ok := ctx.Deadline(); ok {
		c.SetDeadline(d)
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if err = writeHTTPBytes(c, []byte{5, 1, 2}); err != nil {
		return nil, err
	}
	var answer [2]byte
	if _, err = io.ReadFull(c, answer[:]); err != nil {
		return nil, err
	}
	if answer != [2]byte{5, 2} {
		return nil, errors.New("native HTTP IPC requires authentication")
	}
	auth := append([]byte{1, 9}, []byte("foxtunnel")...)
	auth = append(auth, byte(len(m.token)))
	auth = append(auth, []byte(m.token)...)
	if err = writeHTTPBytes(c, auth); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(c, answer[:]); err != nil {
		return nil, err
	}
	if answer != [2]byte{1, 0} {
		return nil, errors.New("native HTTP IPC authentication rejected")
	}
	if !stop() || ctx.Err() != nil {
		return nil, context.DeadlineExceeded
	}
	keep = true
	return c, nil
}
func writeHTTPBytes(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func writeHTTPChunk(w io.Writer, b []byte) error {
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(b)))
	if err := writeHTTPBytes(w, head[:]); err != nil {
		return err
	}
	return writeHTTPBytes(w, b)
}

// RoundTrip sends one bounded-metadata HTTP operation through an owned Gecko
// helper. Its owner must restrict request origins with a trusted origin pool.
// The IPC upload and download are independently framed so EOF and native errors
// cannot be confused, and a response may precede the first upload byte.
func (m *Managed) RoundTrip(req *http.Request) (result *http.Response, resultErr error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("native HTTP request missing URL")
	}
	var writeOnce sync.Once
	trace := httptrace.ContextClientTrace(req.Context())
	notifyWrite := func(err error) {
		writeOnce.Do(func() {
			if trace != nil && trace.WroteRequest != nil {
				trace.WroteRequest(httptrace.WroteRequestInfo{Err: err})
			}
		})
	}
	defer func() {
		if resultErr != nil {
			notifyWrite(resultErr)
		}
	}()
	owned := false
	defer func() {
		if !owned && req.Body != nil {
			req.Body.Close()
		}
	}()
	if req.URL.Scheme != "https" || req.URL.User != nil || req.URL.Fragment != "" || (req.Method != "GET" && req.Method != "POST" && req.Method != "HEAD" && req.Method != "CONNECT") {
		return nil, errors.New("unsupported native HTTP request")
	}
	meta := httpIPCRequest{Origin: "https://" + req.URL.Host, Headers: make([][2]string, 0), Method: req.Method, Path: req.URL.RequestURI(), Host: req.Host, Body: req.Body != nil && req.Body != http.NoBody}
	if meta.Body {
		meta.Length = -1
		if req.ContentLength > 0 && req.ContentLength <= 1<<20 {
			meta.Length = req.ContentLength
		}
	}
	for name, values := range req.Header {
		for _, v := range values {
			meta.Headers = append(meta.Headers, [2]string{name, v})
		}
	}
	encoded, err := json.Marshal(meta)
	if err != nil || len(encoded) > maxHTTPMetadata {
		return nil, errors.New("native HTTP metadata limit")
	}
	setup, cancel := context.WithTimeout(req.Context(), m.timeout)
	defer cancel()
	c, err := m.privateHTTPConn(setup)
	if err != nil {
		return nil, err
	}
	var once sync.Once
	var stop, stopOwned func() bool
	closeFlow := func() {
		once.Do(func() {
			if stop != nil {
				stop()
			}
			if stopOwned != nil {
				stopOwned()
			}
			c.Close()
			if req.Body != nil {
				req.Body.Close()
			}
		})
	}
	abortFlow := func() {
		c.Close()
		if req.Body != nil {
			req.Body.Close()
		}
	}
	stop = context.AfterFunc(req.Context(), abortFlow)
	if m.lifetime != nil {
		stopOwned = context.AfterFunc(m.lifetime, abortFlow)
	}
	success := false
	defer func() {
		if !success {
			closeFlow()
		}
	}()
	timer := time.AfterFunc(time.Until(deadlineOf(setup)), func() { c.Close() })
	defer timer.Stop()
	command := []byte{5, 0xf2, 0, 0, byte(len(encoded) >> 8), byte(len(encoded))}
	command = append(command, encoded...)
	if err = writeHTTPBytes(c, command); err != nil {
		return nil, err
	}
	if meta.Body {
		go func() {
			defer req.Body.Close()
			buf := make([]byte, maxHTTPChunk)
			for {
				n, e := req.Body.Read(buf)
				if n > 0 {
					if writeErr := writeHTTPChunk(c, buf[:n]); writeErr != nil {
						notifyWrite(writeErr)
						c.Close()
						return
					}
				}
				if e != nil {
					if e == io.EOF {
						writeErr := writeHTTPChunk(c, nil)
						notifyWrite(writeErr)
						if writeErr != nil {
							c.Close()
						}
					} else {
						notifyWrite(e)
						c.Close()
					}
					return
				}
			}
		}()
	} else {
		notifyWrite(nil)
	}
	var header [4]byte
	if _, err = io.ReadFull(c, header[:]); err != nil {
		return nil, err
	}
	if header[0] == 5 && header[1] == 2 && header[2] == 0 && header[3] == 0 {
		return nil, nativeHTTPNetworkError{}
	}
	n := int(binary.BigEndian.Uint16(header[2:]))
	if header[0] != 5 || header[1] != 0 || n < 2 || n > maxHTTPMetadata {
		return nil, errors.New("native HTTP setup rejected")
	}
	payload := make([]byte, n)
	if _, err = io.ReadFull(c, payload); err != nil {
		return nil, err
	}
	var reply httpIPCResponse
	if json.Unmarshal(payload, &reply) != nil || reply.Status < 100 || reply.Status > 599 || (reply.Proto != 2 && reply.Proto != 3) || len(reply.Headers) > 128 {
		return nil, errors.New("invalid native HTTP response metadata")
	}
	h := make(http.Header)
	for _, entry := range reply.Headers {
		if strings.ContainsAny(entry[0]+entry[1], "\r\n\x00") {
			return nil, errors.New("invalid native HTTP response header")
		}
		h.Add(entry[0], entry[1])
	}
	if !timer.Stop() || setup.Err() != nil {
		return nil, context.DeadlineExceeded
	}
	if err = c.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	length := int64(-1)
	if v := h.Get("Content-Length"); v != "" {
		if parsed, e := strconv.ParseInt(v, 10, 64); e == nil && parsed >= 0 {
			length = parsed
		}
	}
	owned = true
	success = true
	return &http.Response{StatusCode: reply.Status, Status: strconv.Itoa(reply.Status) + " " + http.StatusText(reply.Status), Proto: "HTTP/" + strconv.Itoa(reply.Proto) + ".0", ProtoMajor: reply.Proto, Header: h, Body: &httpIPCBody{conn: c, close: closeFlow}, ContentLength: length, Request: req}, nil
}
func deadlineOf(ctx context.Context) time.Time { d, _ := ctx.Deadline(); return d }

type httpIPCBody struct {
	conn      net.Conn
	remaining uint32
	done      bool
	close     func()
}

func (b *httpIPCBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.done {
		return 0, io.EOF
	}
	if b.remaining == 0 {
		var header [4]byte
		if _, err := io.ReadFull(b.conn, header[:]); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		b.remaining = binary.BigEndian.Uint32(header[:])
		if b.remaining == 0 {
			b.done = true
			return 0, io.EOF
		}
		if b.remaining == 0xffffffff {
			// Gecko terminated an established response. Preserve the same
			// interruption category as a truncated IPC body so sequence-based
			// carriers can recover without treating it as an application EOF.
			return 0, io.ErrUnexpectedEOF
		}
		if b.remaining > maxHTTPChunk {
			return 0, errors.New("oversized native HTTP body frame")
		}
	}
	n, err := b.conn.Read(p[:min(len(p), int(b.remaining))])
	b.remaining -= uint32(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
func (b *httpIPCBody) Close() error { b.close(); return nil }

// Only explicit native network categories permit pre-request failover. TLS,
// authentication, protocol and malformed metadata failures remain terminal.
type nativeHTTPNetworkError struct{}

func (nativeHTTPNetworkError) Error() string   { return "native HTTP network unavailable" }
func (nativeHTTPNetworkError) Timeout() bool   { return false }
func (nativeHTTPNetworkError) Temporary() bool { return true }
