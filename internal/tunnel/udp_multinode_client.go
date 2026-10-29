package tunnel

import (
	"context"
	"hash/fnv"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SawaMEN/VetroffProxy/internal/udpproto"
)

// udpIngressIndex consistently assigns an entire destination flow to a
// trusted exit. Do not switch exits for an established UDP flow: the remote
// peer may bind state to the observed external source IP/port. This hash
// distributes distinct destinations, not individual game packets.
func udpIngressIndex(host string, port uint16, nodes int) int {
	if nodes <= 1 {
		return 0
	}
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(strings.ToLower(host)))
	_, _ = hash.Write([]byte{0, byte(port >> 8), byte(port)})
	return int(hash.Sum64() % uint64(nodes))
}

// handleUDPMultiNodeStream keeps one authenticated, persistent HTTP/2 or
// HTTP/3 stream per explicitly trusted exit. Each exit has its own bounded
// upload queue, eliminating head-of-line blocking BETWEEN destinations that
// hash to different exits. A single flow stays on one exit and retains its
// own datagram order. Fail closed if any stream is lost (no NAT rebinding).
func (c *Client) handleUDPMultiNodeStream(parent context.Context, control net.Conn, socket *net.UDPConn, peer *net.TCPAddr) {
	if !c.EnableUDP || !c.UDPStreaming || !c.UDPMultiNode ||
		len(c.fallbackServers) < 1 || len(c.fallbackServers) >= maxProxyEndpoints ||
		c.bondClient != nil || c.bondDiscovery != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = socket.Close(); _ = control.Close() })
	defer stop()
	go func() {
		_, _ = io.Copy(io.Discard, control)
		cancel()
	}()

	peerIP, ok := netip.AddrFromSlice(peer.IP)
	if !ok {
		return
	}
	peerIP = peerIP.Unmap()
	endpoints := make([]*url.URL, 0, 1+len(c.fallbackServers))
	endpoints = append(endpoints, c.ServerURL)
	endpoints = append(endpoints, c.fallbackServers...)
	streams := make([]*udpStream, 0, len(endpoints))
	defer func() {
		cancel()
		_ = socket.Close()
		for _, stream := range streams {
			stream.close()
		}
	}()
	// All exits must negotiate authenticated v2 before dispatch. In
	// particular, a failed exit cannot transparently redirect or receive
	// datagrams from an already pinned destination.
	setupBudget := c.ConnectTimeout
	if setupBudget <= 0 {
		setupBudget = 15 * time.Second
	}
	setupTimer := time.AfterFunc(setupBudget, cancel)
	defer setupTimer.Stop()
	for _, endpoint := range endpoints {
		stream, err := c.openUDPStreamTo(ctx, endpoint)
		if err != nil {
			return
		}
		streams = append(streams, stream)
	}
	if !setupTimer.Stop() || ctx.Err() != nil {
		return
	}

	var source atomic.Pointer[net.UDPAddr]
	guards := make([]udpReplyGuard, len(streams))
	queues := make([]chan []byte, len(streams))
	var workers sync.WaitGroup
	for i, stream := range streams {
		queues[i] = make(chan []byte, 16)
		workers.Add(2)
		go func(s *udpStream, queue <-chan []byte) {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case packet := <-queue:
					if ctx.Err() != nil {
						return
					}
					if err := udpproto.WriteFrame(s.writer, packet); err != nil {
						cancel()
						return
					}
				}
			}
		}(stream, queues[i])
		go func(s *udpStream, guard *udpReplyGuard) {
			defer workers.Done()
			for {
				wire, err := udpproto.ReadFrame(s.response)
				if err != nil {
					cancel()
					return
				}
				if !guard.matches(wire) {
					continue
				}
				dst := source.Load()
				if dst == nil || ctx.Err() != nil {
					continue
				}
				_ = socket.SetWriteDeadline(time.Now().Add(2 * time.Second))
				if _, err := socket.WriteToUDP(wire, dst); err != nil {
					cancel()
					return
				}
			}
		}(stream, &guards[i])
	}
	defer func() {
		cancel()
		_ = socket.Close()
		for _, stream := range streams {
			stream.close()
		}
		workers.Wait()
	}()

	buf := make([]byte, udpproto.MaxDatagram+1)
	for {
		n, src, err := socket.ReadFromUDP(buf)
		if err != nil {
			return
		}
		ip, valid := netip.AddrFromSlice(src.IP)
		if !valid || ip.Unmap() != peerIP || n > udpproto.MaxDatagram {
			continue
		}
		packet, err := udpproto.Parse(buf[:n])
		if err != nil {
			continue
		}
		pinned := source.Load()
		if pinned == nil {
			dst := *src
			source.CompareAndSwap(nil, &dst)
			pinned = source.Load()
		}
		if pinned.Port != src.Port || !pinned.IP.Equal(src.IP) {
			continue
		}
		// Each SOCKS UDP destination always hashes to the same server,
		// independent of queue pressure. No per-packet exit switching.
		index := udpIngressIndex(packet.Host, packet.Port, len(queues))
		owned := append([]byte(nil), buf[:n]...)
		// Each exit may reply only for destinations sent on its stream.
		// A different trusted exit cannot forge a response for this flow.
		guards[index].remember(packet)
		select {
		case <-ctx.Done():
			return
		case queues[index] <- owned:
		default:
			// Bound UDP latency rather than blocking all other flows behind
			// a slow exit. Overflow is a drop, never a silent reroute.
		}
	}
}
