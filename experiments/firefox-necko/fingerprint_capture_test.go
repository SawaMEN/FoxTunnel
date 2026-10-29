package firefox

// Test-only endpoint-assisted measurements. No application headers, payloads,
// client randoms, ticket bytes or connection IDs are serialized.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/SawaMEN/VetroffProxy/internal/fingerprint"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	h3log "github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type fpHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type fpBlock struct {
	Stream uint32     `json:"stream"`
	Length int        `json:"length"`
	SHA256 string     `json:"sha256"`
	Fields []fpHeader `json:"fields"`
}
type fpFrame struct {
	Type   uint8  `json:"type"`
	Flags  uint8  `json:"flags"`
	Stream uint32 `json:"stream"`
	Length int    `json:"length"`
}
type fpSetting struct {
	ID    uint64 `json:"id"`
	Value uint64 `json:"value"`
}
type fpConnection struct {
	Subject         string             `json:"subject"`
	Protocol        string             `json:"protocol"`
	Hello           *fingerprint.Hello `json:"hello,omitempty"`
	ALPN            string             `json:"alpn"`
	Resumed         bool               `json:"resumed"`
	InitialDatagram int                `json:"initial_datagram_size,omitempty"`
	Settings        []fpSetting        `json:"settings"`
	Parameters      []fpSetting        `json:"quic_effective_parameters,omitempty"`
	Frames          []fpFrame          `json:"h2_frames,omitempty"`
	Blocks          []fpBlock          `json:"hpack_blocks,omitempty"`
	H3Headers       [][]fpHeader       `json:"h3_headers,omitempty"`
	Fins            []uint64           `json:"client_fin_streams"`
	Resets          []uint64           `json:"client_reset_codes"`
	Requests        int                `json:"requests"`
	Completed       int                `json:"completed"`
	Truncated       bool               `json:"truncated"`
	Error           string             `json:"error,omitempty"`
	close           func()
}
type fpKey struct{}
type fpCapture struct {
	sync.Mutex
	subject     string
	connections []*fpConnection
}

func (c *fpCapture) add(protocol string) *fpConnection {
	c.Lock()
	defer c.Unlock()
	p := &fpConnection{Subject: c.subject, Protocol: protocol}
	c.connections = append(c.connections, p)
	return p
}
func fpSafeField(name, value string) fpHeader {
	switch name {
	case ":method", "alpn", "user-agent":
		return fpHeader{name, value}
	case ":authority":
		return fpHeader{name, "<fixture>"}
	default:
		return fpHeader{name, fmt.Sprintf("<%d bytes>", len(value))}
	}
}
func (c *fpCapture) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.Context().Value(fpKey{}).(*fpConnection)
		c.Lock()
		p.Requests++
		round := p.Requests
		c.Unlock()
		next.ServeHTTP(w, r)
		c.Lock()
		p.Completed++
		closeFn := p.close
		c.Unlock()
		if round == 2 {
			time.AfterFunc(200*time.Millisecond, closeFn)
		}
	})
}

type fpReplay struct {
	net.Conn
	reader io.Reader
}

func (c *fpReplay) Read(b []byte) (int, error) { return c.reader.Read(b) }

type fpTap struct {
	net.Conn
	owner          *fpCapture
	p              *fpConnection
	preface        int
	pending, block []byte
	blockStream    uint32
	decoder        *hpack.Decoder
}

func (c *fpTap) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	if n > 0 {
		c.feed(b[:n])
	}
	return n, e
}
func (c *fpTap) feed(b []byte) {
	c.owner.Lock()
	defer c.owner.Unlock()
	if c.p.Truncated || c.p.Error != "" {
		return
	}
	if c.preface < len(http2.ClientPreface) {
		n := min(len(b), len(http2.ClientPreface)-c.preface)
		c.preface += n
		b = b[n:]
	}
	c.pending = append(c.pending, b...)
	for len(c.pending) >= 9 {
		h := c.pending
		length := int(h[0])<<16 | int(h[1])<<8 | int(h[2])
		if length > 1<<20 {
			c.p.Truncated = true
			return
		}
		if len(h) < 9+length {
			return
		}
		typ, flags, stream := h[3], h[4], binary.BigEndian.Uint32(h[5:9])&0x7fffffff
		data := h[9 : 9+length]
		if len(c.p.Frames) >= 2048 {
			c.p.Truncated = true
			return
		}
		c.p.Frames = append(c.p.Frames, fpFrame{typ, flags, stream, length})
		switch typ {
		case 4:
			if flags&1 == 0 && len(c.p.Settings) == 0 {
				for j := 0; j+6 <= len(data); j += 6 {
					c.p.Settings = append(c.p.Settings, fpSetting{uint64(binary.BigEndian.Uint16(data[j:])), uint64(binary.BigEndian.Uint32(data[j+2:]))})
				}
			}
		case 0:
			if flags&1 != 0 {
				c.p.Fins = append(c.p.Fins, uint64(stream))
			}
		case 3:
			if len(data) == 4 {
				c.p.Resets = append(c.p.Resets, uint64(binary.BigEndian.Uint32(data)))
			}
		case 1, 9:
			if typ == 1 {
				c.blockStream = stream
				if flags&8 != 0 {
					if len(data) == 0 || int(data[0])+1 > len(data) {
						c.p.Truncated = true
						return
					}
					padding := int(data[0])
					data = data[1 : len(data)-padding]
				}
				if flags&32 != 0 {
					if len(data) < 5 {
						c.p.Truncated = true
						return
					}
					data = data[5:]
				}
			}
			c.block = append(c.block, data...)
			if len(c.block) > 64<<10 {
				c.p.Truncated = true
				return
			}
			if flags&4 != 0 {
				fields, e := c.decoder.DecodeFull(c.block)
				if e != nil {
					c.p.Error = "HPACK decode failed"
					return
				}
				sum := sha256.Sum256(c.block)
				block := fpBlock{Stream: c.blockStream, Length: len(c.block), SHA256: hex.EncodeToString(sum[:])}
				for _, f := range fields {
					block.Fields = append(block.Fields, fpSafeField(f.Name, f.Value))
				}
				c.p.Blocks = append(c.p.Blocks, block)
				c.block = nil
			}
		}
		c.pending = c.pending[9+length:]
	}
}
func (c *fpCapture) serveH2(ctx context.Context, l net.Listener, config *tls.Config, handler http.Handler) {
	for {
		raw, e := l.Accept()
		if e != nil {
			return
		}
		go func() {
			defer raw.Close()
			p := c.add("h2")
			raw.SetDeadline(time.Now().Add(40 * time.Second))
			var prefix bytes.Buffer
			hello, e := fingerprint.ReadClientHello(io.TeeReader(raw, &prefix))
			if e != nil {
				c.Lock()
				p.Error = "ClientHello read failed"
				c.Unlock()
				return
			}
			secure := tls.Server(&fpReplay{raw, io.MultiReader(&prefix, raw)}, config)
			if e := secure.HandshakeContext(ctx); e != nil {
				c.Lock()
				p.Error = "TLS handshake failed"
				c.Unlock()
				return
			}
			state := secure.ConnectionState()
			c.Lock()
			p.Hello = &hello
			p.Resumed = state.DidResume
			p.ALPN = state.NegotiatedProtocol
			p.close = func() { raw.Close() }
			c.Unlock()
			tap := &fpTap{Conn: secure, owner: c, p: p, decoder: hpack.NewDecoder(65536, nil)}
			(&http2.Server{}).ServeConn(tap, &http2.ServeConnOpts{Context: context.WithValue(ctx, fpKey{}, p), Handler: handler})
		}()
	}
}

type fpH3Trace struct {
	owner *fpCapture
	p     *fpConnection
}

func (t *fpH3Trace) SupportsSchemas(string) bool      { return true }
func (t *fpH3Trace) AddProducer() qlogwriter.Recorder { return t }
func (t *fpH3Trace) Close() error                     { return nil }
func (t *fpH3Trace) RecordEvent(event qlogwriter.Event) {
	c, p := t.owner, t.p
	c.Lock()
	defer c.Unlock()
	switch e := event.(type) {
	case qlog.ParametersSet:
		if e.Initiator == qlog.InitiatorRemote && !e.Restore {
			p.Parameters = []fpSetting{{1, uint64(e.MaxIdleTimeout.Milliseconds())}, {3, uint64(e.MaxUDPPayloadSize)}, {4, uint64(e.InitialMaxData)}, {5, uint64(e.InitialMaxStreamDataBidiLocal)}, {6, uint64(e.InitialMaxStreamDataBidiRemote)}, {7, uint64(e.InitialMaxStreamDataUni)}, {8, uint64(e.InitialMaxStreamsBidi)}, {9, uint64(e.InitialMaxStreamsUni)}, {10, uint64(e.AckDelayExponent)}, {11, uint64(e.MaxAckDelay.Milliseconds())}, {14, e.ActiveConnectionIDLimit}}
		}
	case h3log.FrameParsed:
		switch f := e.Frame.Frame.(type) {
		case h3log.SettingsFrame:
			if p.Settings != nil {
				return
			}
			p.Settings = []fpSetting{}
			if f.MaxFieldSectionSize >= 0 {
				p.Settings = append(p.Settings, fpSetting{6, uint64(f.MaxFieldSectionSize)})
			}
			if f.Datagram != nil {
				v := uint64(0)
				if *f.Datagram {
					v = 1
				}
				p.Settings = append(p.Settings, fpSetting{0x33, v})
			}
			if f.ExtendedConnect != nil {
				v := uint64(0)
				if *f.ExtendedConnect {
					v = 1
				}
				p.Settings = append(p.Settings, fpSetting{8, v})
			}
			for id, v := range f.Other {
				p.Settings = append(p.Settings, fpSetting{id, v})
			}
			sort.Slice(p.Settings, func(i, j int) bool { return p.Settings[i].ID < p.Settings[j].ID })
		case h3log.HeadersFrame:
			if len(p.H3Headers) >= 64 {
				p.Truncated = true
				return
			}
			var fields []fpHeader
			for _, f := range f.HeaderFields {
				fields = append(fields, fpSafeField(f.Name, f.Value))
			}
			p.H3Headers = append(p.H3Headers, fields)
		}
	case qlog.PacketReceived:
		for _, frame := range e.Frames {
			switch f := frame.Frame.(type) {
			case *qlog.StreamFrame:
				if f.Fin && uint64(f.StreamID)%4 == 0 {
					if len(p.Fins) < 128 {
						p.Fins = append(p.Fins, uint64(f.StreamID))
					} else {
						p.Truncated = true
					}
				}
			case *qlog.ResetStreamFrame:
				if len(p.Resets) < 128 {
					p.Resets = append(p.Resets, uint64(f.ErrorCode))
				} else {
					p.Truncated = true
				}
			}
		}
	}
}
func (c *fpCapture) h3Server(config *tls.Config, handler http.Handler, packets *fpPackets) *http3.Server {
	var traces sync.Map
	return &http3.Server{TLSConfig: config, Handler: handler,
		QUICConfig: &quic.Config{Versions: []quic.Version{quic.Version1}, Tracer: func(ctx context.Context, _ bool, id quic.ConnectionID) qlogwriter.Trace {
			p := c.add("h3")
			c.Lock()
			if initial := packets.initial[id.String()]; initial != nil {
				p.InitialDatagram = initial.first
				p.Hello = initial.hello
				initial.connection = p
			} else {
				p.Error = "missing Initial capture"
			}
			c.Unlock()
			traces.Store(ctx.Done(), p)
			return &fpH3Trace{c, p}
		}}, ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			v, ok := traces.LoadAndDelete(ctx.Done())
			if !ok {
				panic("missing trace context")
			}
			p := v.(*fpConnection)
			c.Lock()
			p.Resumed = conn.ConnectionState().TLS.DidResume
			p.ALPN = conn.ConnectionState().TLS.NegotiatedProtocol
			p.close = func() { conn.CloseWithError(0, "controlled reconnect") }
			c.Unlock()
			return context.WithValue(ctx, fpKey{}, p)
		}}
}
