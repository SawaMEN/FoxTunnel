package tunnel

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/access"
	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

// UDP stream v2 is intentionally separate from the one-datagram POST v1.
// An association multiplexes destinations over one authenticated request;
// each destination has one connected UDP socket until idle, evicted or closed.
const (
	udpStreamPath     = "/.well-known/foxtunnel-udp-stream-v2"
	udpStreamLifetime = 10 * time.Minute
	udpFlowIdle       = 30 * time.Second
	udpStreamFlows    = 16
	udpStreamQueued   = 32
)

type udpStreamFlow struct {
	conn net.Conn
	ip   string
	port uint16
	last time.Time // Owned only by the stream request reader.
	dead atomic.Bool
}

func (s *Server) serveUDPStream(w http.ResponseWriter, r *http.Request) {
	if !s.acquireTunnel() {
		http.Error(w, "server busy", http.StatusServiceUnavailable)
		return
	}
	defer s.activeTunnels.Add(-1)
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unavailable", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), udpStreamLifetime)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = r.Body.Close() })
	defer stop()

	out := make(chan []byte, udpStreamQueued)
	writerDone := make(chan struct{})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// The request handler remains alive for the whole duplex exchange.
	// Only this goroutine writes/flushes response data.
	go func() {
		defer close(writerDone)
		for {
			select {
			case <-ctx.Done():
				return
			case pkt, ok := <-out:
				if !ok {
					return
				}
				if err := udpproto.WriteFrame(w, pkt); err != nil {
					cancel()
					return
				}
				flusher.Flush()
			}
		}
	}()

	flows := make(map[string]*udpStreamFlow)
	var readers sync.WaitGroup
	defer func() {
		cancel()
		for _, f := range flows {
			_ = f.conn.Close()
		}
		readers.Wait()
		close(out)
		<-writerDone
	}()

	for {
		raw, err := udpproto.ReadFrame(r.Body)
		if err != nil {
			return
		} // malformed frames terminate this association
		packet, err := udpproto.Parse(raw)
		if err != nil {
			return
		}
		key := net.JoinHostPort(packet.Host, strconv.Itoa(int(packet.Port)))
		now := time.Now()
		f := flows[key]
		if f != nil && (f.dead.Load() || now.Sub(f.last) >= udpFlowIdle) {
			_ = f.conn.Close()
			delete(flows, key)
			f = nil
		}
		if f == nil {
			ip, err := s.resolveUDP(ctx, packet.Host) // Filter + pin DNS before dial.
			if err != nil {
				continue
			}
			// Evict the least recently used destination before admitting one more.
			if len(flows) >= udpStreamFlows {
				var oldestKey string
				var oldest time.Time
				for k, candidate := range flows {
					if oldestKey == "" || candidate.last.Before(oldest) {
						oldestKey, oldest = k, candidate.last
					}
				}
				_ = flows[oldestKey].conn.Close()
				delete(flows, oldestKey)
			}
			dest := net.JoinHostPort(ip.String(), strconv.Itoa(int(packet.Port)))
			conn, err := access.Dial(ctx, func(ctx context.Context) (net.Conn, error) {
				return (&net.Dialer{Timeout: s.timeout()}).DialContext(ctx, "udp", dest)
			})
			if err != nil {
				continue
			}
			f = &udpStreamFlow{conn: conn, ip: ip.String(), port: packet.Port, last: now}
			flows[key] = f
			readers.Add(1)
			go func(flow *udpStreamFlow) {
				defer readers.Done()
				defer flow.dead.Store(true)
				defer flow.conn.Close()
				buf := make([]byte, udpproto.MaxDatagram+1)
				for {
					n, err := flow.conn.Read(buf)
					if err != nil {
						return
					}
					raw, err := udpproto.Encode(udpproto.Packet{
						Host: flow.ip, Port: flow.port, Data: buf[:n],
					})
					if err != nil {
						continue
					}
					select {
					case out <- raw:
					case <-ctx.Done():
						return
					default: // bounded queue; drop instead of blocking a UDP reader
					}
				}
			}(f)
		}
		f.last = now
		_ = f.conn.SetReadDeadline(now.Add(udpFlowIdle))
		if _, err := f.conn.Write(packet.Data); err != nil {
			_ = f.conn.Close()
			delete(flows, key)
		}
	}
}
