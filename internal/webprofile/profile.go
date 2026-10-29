// Package webprofile records bounded, non-secret metadata at a controlled TLS
// endpoint. TLS records are not TCP packets; HTTP/2 fields require decryption
// at the endpoint and are not directly visible to an on-path observer.
package webprofile

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/SawaMEN/VetroffProxy/internal/fingerprint"
	"golang.org/x/net/http2"
)

const maxEvents = 512

type Record struct {
	Direction    string `json:"direction"`
	Type         uint8  `json:"type"`
	Length       int    `json:"length"`
	Microseconds int64  `json:"microseconds"`
}
type Setting struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}
type Frame struct {
	Type   uint8  `json:"type"`
	Flags  uint8  `json:"flags"`
	Length int    `json:"length"`
	Stream uint32 `json:"stream"`
}
type Profile struct {
	Schema           int               `json:"schema"`
	Source           string            `json:"source"`
	Hello            fingerprint.Hello `json:"hello"`
	ALPN             string            `json:"negotiated_alpn"`
	SessionResumed   bool              `json:"session_resumed"`
	Records          []Record          `json:"tls_records"`
	DroppedRecords   int               `json:"dropped_records"`
	Frames           []Frame           `json:"client_h2_frames"`
	DroppedFrames    int               `json:"dropped_frames"`
	Settings         []Setting         `json:"initial_h2_settings"`
	ConnectionWindow []uint32          `json:"initial_connection_window_updates"`
}

type recorder struct {
	mu    sync.Mutex
	start time.Time
	p     Profile
}

// wireParser never retains a record body, even for a fragmented header.
type wireParser struct {
	header          [5]byte
	used, remaining int
}

func (p *wireParser) feed(b []byte, direction string, r *recorder) {
	for len(b) > 0 {
		if p.remaining > 0 {
			n := min(len(b), p.remaining)
			b = b[n:]
			p.remaining -= n
			continue
		}
		n := copy(p.header[p.used:], b)
		p.used += n
		b = b[n:]
		if p.used != 5 {
			continue
		}
		p.used = 0
		p.remaining = int(binary.BigEndian.Uint16(p.header[3:]))
		r.mu.Lock()
		if len(r.p.Records) < maxEvents {
			r.p.Records = append(r.p.Records, Record{direction, p.header[0], p.remaining, time.Since(r.start).Microseconds()})
		} else {
			r.p.DroppedRecords++
		}
		r.mu.Unlock()
	}
}

type wireConn struct {
	net.Conn
	r       *recorder
	in, out wireParser
}

func (c *wireConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	c.in.feed(b[:n], "client", c.r)
	return n, e
}
func (c *wireConn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	c.out.feed(b[:n], "server", c.r)
	return n, e
}

type replayConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

// h2Parser retains only a frame header and at most 256 bytes of SETTINGS or
// WINDOW_UPDATE. It never stores HPACK, request headers or DATA payloads.
type h2Parser struct {
	preface               int
	header                [9]byte
	used, remaining       int
	frame                 Frame
	payload               [256]byte
	payloadUsed           int
	initial, settingsSeen bool
}

func (p *h2Parser) feed(b []byte, r *recorder) {
	for len(b) > 0 {
		if p.preface < len(http2.ClientPreface) {
			n := min(len(b), len(http2.ClientPreface)-p.preface)
			p.preface += n
			b = b[n:]
			continue
		}
		if p.remaining > 0 {
			n := min(len(b), p.remaining)
			if (p.frame.Type == 4 || p.frame.Type == 8) && p.frame.Length <= len(p.payload) {
				p.payloadUsed += copy(p.payload[p.payloadUsed:], b[:n])
			}
			p.remaining -= n
			b = b[n:]
			if p.remaining == 0 {
				p.finish(r)
			}
			continue
		}
		n := copy(p.header[p.used:], b)
		p.used += n
		b = b[n:]
		if p.used != 9 {
			continue
		}
		p.used = 0
		h := p.header
		p.frame = Frame{h[3], h[4], int(h[0])<<16 | int(h[1])<<8 | int(h[2]), binary.BigEndian.Uint32(h[5:]) & 0x7fffffff}
		p.remaining = p.frame.Length
		p.payloadUsed = 0
		r.mu.Lock()
		if len(r.p.Frames) < maxEvents {
			r.p.Frames = append(r.p.Frames, p.frame)
		} else {
			r.p.DroppedFrames++
		}
		r.mu.Unlock()
		if p.frame.Type == 1 {
			p.initial = false
		}
		if p.remaining == 0 {
			p.finish(r)
		}
	}
}
func (p *h2Parser) finish(r *recorder) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := p.frame
	if f.Type == 4 && f.Flags&1 == 0 && f.Stream == 0 && !p.settingsSeen {
		p.settingsSeen = true
		if f.Length > len(p.payload) || f.Length%6 != 0 {
			return
		}
		for i := 0; i < p.payloadUsed; i += 6 {
			r.p.Settings = append(r.p.Settings, Setting{binary.BigEndian.Uint16(p.payload[i:]), binary.BigEndian.Uint32(p.payload[i+2:])})
		}
	}
	if p.initial && f.Type == 8 && f.Stream == 0 && p.payloadUsed == 4 && len(r.p.ConnectionWindow) < maxEvents {
		r.p.ConnectionWindow = append(r.p.ConnectionWindow, binary.BigEndian.Uint32(p.payload[:4])&0x7fffffff)
	}
}

type plainConn struct {
	net.Conn
	r     *recorder
	p     h2Parser
	state tls.ConnectionState
}

func (c *plainConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	c.p.feed(b[:n], c.r)
	return n, e
}
func (c *plainConn) ConnectionState() tls.ConnectionState { return c.state }

// Capture owns one accepted connection. The caller bounds Accept with a
// listener deadline. duration bounds the post-handshake observation (max 30s).
// handler must be a controlled fixture; never point a browser's normal profile
// containing accounts at a research endpoint.
func Capture(l net.Listener, config *tls.Config, handler http.Handler, source string, duration time.Duration) (Profile, error) {
	if duration <= 0 || duration > 30*time.Second {
		return Profile{}, errors.New("capture duration must be within (0,30s]")
	}
	raw, err := l.Accept()
	if err != nil {
		return Profile{}, err
	}
	defer raw.Close()
	r := &recorder{start: time.Now(), p: Profile{Schema: 1, Source: source}}
	wire := &wireConn{Conn: raw, r: r}
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	var prefix bytes.Buffer
	hello, err := fingerprint.ReadClientHello(io.TeeReader(wire, &prefix))
	if err != nil {
		return Profile{}, err
	}
	cfg := config.Clone()
	cfg.NextProtos = []string{"h2"}
	cfg.MinVersion = tls.VersionTLS13
	secure := tls.Server(&replayConn{Conn: wire, reader: io.MultiReader(&prefix, wire)}, cfg)
	if err = secure.Handshake(); err != nil {
		return Profile{}, err
	}
	state := secure.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		return Profile{}, errors.New("client did not negotiate h2")
	}
	r.mu.Lock()
	r.p.Hello = hello
	r.p.ALPN = state.NegotiatedProtocol
	r.p.SessionResumed = state.DidResume
	r.mu.Unlock()
	_ = raw.SetDeadline(time.Now().Add(duration))
	// Close also unblocks a handler waiting on an application stream.
	timer := time.AfterFunc(duration, func() { _ = raw.Close() })
	defer timer.Stop()
	plain := &plainConn{Conn: secure, r: r, state: state, p: h2Parser{initial: true}}
	server := http2.Server{}
	server.ServeConn(plain, &http2.ServeConnOpts{Handler: handler})
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.p.Frames) == 0 {
		return Profile{}, errors.New("no HTTP/2 frames captured")
	}
	p := r.p
	p.Records = append([]Record(nil), p.Records...)
	p.Frames = append([]Frame(nil), p.Frames...)
	p.Settings = append([]Setting(nil), p.Settings...)
	p.ConnectionWindow = append([]uint32(nil), p.ConnectionWindow...)
	return p, nil
}
