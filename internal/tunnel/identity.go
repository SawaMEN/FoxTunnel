package tunnel

import (
	"crypto/tls"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/i18n"
	"github.com/SawaMEN/FoxTunnel/internal/nodeperf"
	"github.com/SawaMEN/FoxTunnel/internal/nsstls"
	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
	"github.com/SawaMEN/FoxTunnel/internal/xhttp"
)

type tlsTransport interface {
	http.RoundTripper
	CloseIdleConnections()
}
type identityEntry struct {
	transport tlsTransport
	touched   time.Time
}
type identityPool struct {
	mu               sync.Mutex
	base             tlsTransport
	monitor          *nodeperf.Monitor
	config           *tls.Config
	backend          string
	mode             string
	quic             quicSettings
	h2ReceiveProfile string
	tlsClientProfile string
	xhttpSettings    xhttp.Settings
	auth             string
	primary          string
	policy           tlsidentity.Policy
	// Optional explicit trust policy for each configured origin.
	// Set before Serve, immutable for the lifetime of the transport.
	nodePolicies map[string]tlsidentity.Policy
	entries      map[string]identityEntry
}

func makeTLStransport(backend string, config *tls.Config, receiveProfile, clientProfile string) (tlsTransport, error) {
	if backend == "nss" {
		return nsstls.NewTransportWithProfiles(config, receiveProfile, clientProfile)
	}
	goTransport, err := newGoTransportWithProfile(config, receiveProfile)
	if err != nil {
		// Preserve nil interface semantics on an invalid H2 profile:
		// returning a typed nil *http.Transport as tlsTransport is non-nil.
		return nil, err
	}
	return goTransport, nil
}

// SetServerIdentity applies only to the primary origin. Other origins keep
// their own hostname, and discovery supplies independent per-node policies.
// Configure before enabling bond/discovery and before serving.
func (c *Client) SetServerIdentity(sni, pin string) error {
	policy, err := tlsidentity.Normalize(sni, pin)
	if err != nil || c.bondClient != nil || c.bondDiscovery != nil {
		return i18n.Error("invalid TLS identity settings")
	}
	if pool, ok := c.transport.(*identityPool); ok && len(pool.nodePolicies) != 0 {
		return i18n.Error("cannot override TLS identity after per-node SPKI pins have been configured")
	}
	old := c.identity
	c.identity = policy
	backend := c.backend
	if backend == "" {
		backend = "go"
	}
	if err := c.SetTLSBackend(backend); err != nil {
		c.identity = old
		return err
	}
	return nil
}

func (p *identityPool) forPolicy(origin string, policy tlsidentity.Policy) (tlsTransport, error) {
	if policy == (tlsidentity.Policy{}) {
		return p.base, nil
	}
	key := origin + "|" + policy.SNI + "|" + policy.PinSHA256
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.entries[key]; ok {
		e.touched = time.Now()
		p.entries[key] = e
		return e.transport, nil
	}
	config := p.config.Clone()
	// Session tickets must not cross origins or pin/SNI rotations, even when
	// operators share ticket keys between servers using different certificates.
	config.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	policy.Apply(config)
	transport, err := makeNativeTransport(p.mode, p.backend, config, p.auth, p.xhttpSettings, p.h2ReceiveProfile, p.tlsClientProfile, p.quic)
	if err != nil {
		return nil, err
	}
	// Bound idle transport variants during topology/key rotation. Closing idle
	// connections does not interrupt streams using an older topology snapshot.
	if len(p.entries) >= 32 {
		oldKey := ""
		var oldest time.Time
		for k, e := range p.entries {
			if oldKey == "" || e.touched.Before(oldest) {
				oldKey = k
				oldest = e.touched
			}
		}
		p.entries[oldKey].transport.CloseIdleConnections()
		delete(p.entries, oldKey)
	}
	p.entries[key] = identityEntry{transport: transport, touched: time.Now()}
	return transport, nil
}
func (p *identityPool) RoundTrip(r *http.Request) (*http.Response, error) {
	origin := r.URL.Scheme + "://" + r.URL.Host
	policy, pinned := p.nodePolicies[origin]
	if len(p.nodePolicies) != 0 && !pinned {
		if r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, errors.New("HTTPS origin lacks a configured SPKI policy")
	}
	if policy == (tlsidentity.Policy{}) && origin == p.primary {
		policy = p.policy
	}
	return p.roundTrip(r, policy)
}
func (p *identityPool) roundTrip(r *http.Request, policy tlsidentity.Policy) (*http.Response, error) {
	transport, err := p.forPolicy(r.URL.Scheme+"://"+r.URL.Host, policy)
	if err != nil {
		if p.monitor != nil {
			p.monitor.Observe(r.URL.Scheme+"://"+r.URL.Host, 0, 0, err)
		}
		// RoundTripper owns closing request bodies, even when selecting the
		// identity-specific transport fails before any network I/O.
		if r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, err
	}
	if policy.SNI != "" && r.Method != http.MethodConnect {
		r = r.Clone(r.Context())
		r.Host = policy.SNI
	}
	if p.monitor != nil {
		return monitoredRoundTrip(p.monitor, transport, r)
	}
	return transport.RoundTrip(r)
}
func (p *identityPool) CloseIdleConnections() {
	p.base.CloseIdleConnections()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.entries {
		e.transport.CloseIdleConnections()
	}
}

type identityView struct {
	pool     *identityPool
	policies map[string]tlsidentity.Policy
}

func (v identityView) RoundTrip(r *http.Request) (*http.Response, error) {
	policy := v.policies[r.URL.Scheme+"://"+r.URL.Host]
	if policy == (tlsidentity.Policy{}) {
		return v.pool.RoundTrip(r)
	}
	return v.pool.roundTrip(r, policy)
}

// NetworkChanged refreshes cached reachability across primary and pinned
// identity-specific transports without changing TLS trust, SNI or SPKI policy.
// New per-policy transports created after this snapshot have no stale cache.
func (p *identityPool) NetworkChanged() {
	p.mu.Lock()
	transports := make([]tlsTransport, 0, len(p.entries)+1)
	transports = append(transports, p.base)
	for _, entry := range p.entries {
		transports = append(transports, entry.transport)
	}
	p.mu.Unlock()
	for _, transport := range transports {
		if notifier, ok := transport.(interface{ NetworkChanged() }); ok {
			notifier.NetworkChanged()
		} else {
			transport.CloseIdleConnections()
		}
	}
}
