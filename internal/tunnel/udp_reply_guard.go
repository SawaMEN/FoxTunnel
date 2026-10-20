package tunnel

import (
	"net/netip"
	"sync"

	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
)

// UDP streaming may have multiple destinations, but must not forward an
// unsolicited reply from the remote exit to a local application. A bounded
// allowlist records destinations actually requested by this association.
// Hostname requests must be resolved by the authenticated remote exit; the
// local client never performs DNS to validate a reply.
const maxUDPReplyDestinations = 64

type udpReplyGuard struct {
	mu       sync.RWMutex
	requests []udpproto.Packet // Only Host/Port fields are stored, never Data.
}

func (g *udpReplyGuard) remember(request udpproto.Packet) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, existing := range g.requests {
		if existing.Host == request.Host && existing.Port == request.Port {
			return
		}
	}
	if len(g.requests) == maxUDPReplyDestinations {
		copy(g.requests, g.requests[1:])
		g.requests = g.requests[:maxUDPReplyDestinations-1]
	}
	g.requests = append(g.requests, udpproto.Packet{Host: request.Host, Port: request.Port})
}

func (g *udpReplyGuard) matches(wire []byte) bool {
	reply, err := udpproto.Parse(wire)
	if err != nil {
		return false
	}
	// Numeric reply origin is mandatory, including for requests that used
	// an upstream-resolved hostname.
	if ip, err := netip.ParseAddr(reply.Host); err != nil || ip.Zone() != "" {
		return false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, request := range g.requests {
		if udpReplyMatchesRequest(request, reply) {
			return true
		}
	}
	return false
}
