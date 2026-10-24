package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/bond"
	"github.com/SawaMEN/FoxTunnel/internal/cluster"
	"github.com/SawaMEN/FoxTunnel/internal/i18n"
	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
)

// ConfigureCluster must run before serving, on the common exit only. The file
// is reread for each authenticated discovery request; replace it atomically.
func (s *Server) ConfigureCluster(path string) error {
	hub, ok := s.Bond.(*bond.Hub)
	if !ok {
		return i18n.Error("cluster configuration requires --bond-hub")
	}
	load := func() (cluster.Config, error) {
		f, err := os.Open(path)
		if err != nil {
			return cluster.Config{}, cluster.ErrInvalid
		}
		defer f.Close()
		return cluster.DecodeConfig(f)
	}
	if _, err := load(); err != nil {
		return i18n.Error("invalid cluster configuration")
	}
	s.Cluster = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config, err := load()
		if err != nil {
			http.Error(w, "cluster unavailable", 503)
			return
		}
		id, err := hub.Identity()
		if err != nil {
			http.Error(w, "cluster unavailable", 503)
			return
		}
		nodes := make([]cluster.Node, 0, len(config.Nodes))
		for _, n := range config.Nodes {
			if !n.Disabled {
				nodes = append(nodes, n)
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cluster.Manifest{Version: 1, HubID: id, ValidFor: 120, Nodes: nodes})
	})
	return nil
}

// Coordinator and cluster URLs are already validated HTTPS origins.
// Canonicalize optional :443 and hostname case for direct/relay recognition.
func bondOriginKey(u *url.URL) string { return cluster.OriginKey(u) }

func sameBondOrigin(a, b *url.URL) bool {
	return a.Scheme == "https" && b.Scheme == "https" && bondOriginKey(a) == bondOriginKey(b)
}

func bondRouteMode(value string) string {
	if value == "smart" {
		return "smart"
	}
	return ""
}

type bondDiscovery struct {
	mu                 sync.Mutex
	current            *bond.Client
	manifest           cluster.Manifest
	refreshAt, expires time.Time
	refreshing         chan struct{}
	lastErr            error
}

// EnableBondDiscovery delegates endpoint selection to the one verified HTTPS
// coordinator. Its listed origins receive the same credentials after TLS/h2.
// Call after TLS/timeouts, before Serve. A failed initial fetch fails closed.
func (c *Client) EnableBondDiscovery(ctx context.Context) error {
	if c.RequireProtocolNegotiation {
		return errors.New("strict protocol policy is not supported with bond/discovery")
	}
	if c.managed != nil && !c.fullManagedHTTP() {
		return errors.New("Necko does not support bond or discovery")
	}
	if pool, ok := c.transport.(*identityPool); ok && len(pool.nodePolicies) != 0 {
		return i18n.Error("cannot combine dynamic discovery and static per-node SPKI pins")
	}
	if err := validateBondTraffic(c.BondTraffic, c.BondAdaptive); err != nil {
		return err
	}
	if (c.BondRoute != "" && c.BondRoute != "legacy" && c.BondRoute != "smart") || c.balance == "adaptive" || c.bondDiscovery != nil || c.bondClient != nil || len(c.fallbackServers) != 0 || c.Padding || (c.BondPipeline != 0 && c.BondPipeline != 4 && c.BondPipeline != 8) || (c.FallbackAttemptTimeout > 0 && c.FallbackAttemptTimeout < 100*time.Millisecond) {
		return i18n.Error("invalid cluster configuration")
	}
	c.bondDiscovery = &bondDiscovery{}
	if _, err := c.discoveredBond(ctx); err != nil {
		c.bondDiscovery = nil
		return err
	}
	return nil
}

func (c *Client) fetchCluster(ctx context.Context) (cluster.Manifest, bool, error) {
	timeout := c.ConnectTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	u := *c.ServerURL
	u.Path = cluster.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return cluster.Manifest{}, false, i18n.Error("cluster discovery failed")
	}
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password)))
	resp, err := c.transport.RoundTrip(req) // No redirect following.
	if err != nil {
		var network net.Error
		transient := !terminalSetupError(err) && (errors.As(err, &network) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF))
		return cluster.Manifest{}, transient, i18n.Error("cluster discovery failed")
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 && resp.ProtoMajor != 3 {
		return cluster.Manifest{}, false, i18n.Error("cluster discovery failed")
	}
	if resp.StatusCode != http.StatusOK {
		retry := resp.StatusCode == 408 || resp.StatusCode == 429 || resp.StatusCode == 503 || resp.StatusCode == 504
		return cluster.Manifest{}, retry, i18n.Error("cluster discovery failed")
	}
	m, err := cluster.DecodeManifest(resp.Body)
	if err != nil {
		return cluster.Manifest{}, false, i18n.Error("invalid cluster configuration")
	}
	return m, false, nil
}

// Refresh on new-stream demand, at most once every 30 seconds. Concurrent
// callers share one refresh. A transient outage can use the unexpired snapshot;
// malformed/authentication/TLS responses cannot. Existing streams keep theirs.
func (c *Client) discoveredBond(ctx context.Context) (*bond.Client, error) {
	d := c.bondDiscovery
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		d.mu.Lock()
		now := time.Now()
		if now.Before(d.refreshAt) && (d.current == nil || now.Before(d.expires)) {
			current, err := d.current, d.lastErr
			d.mu.Unlock()
			return current, err
		}
		if wait := d.refreshing; wait != nil {
			if d.current != nil && now.Before(d.expires) {
				current := d.current
				d.mu.Unlock()
				return current, nil
			}
			d.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		d.refreshing = make(chan struct{})
		d.mu.Unlock()
		m, transient, err := c.fetchCluster(ctx)
		if err == nil && c.BondRoute == "smart" {
			// Restrict smart routing to an explicit direct hub plus one or more
			// authenticated single-relay paths. Never chain arbitrary relays.
			direct, relay := false, false
			for _, n := range m.Nodes {
				u, _ := cluster.Origin(n.URL)
				if sameBondOrigin(u, c.ServerURL) {
					direct = true
				} else {
					relay = true
				}
			}
			if !direct || !relay {
				err = i18n.Error("smart bond routes require the coordinator hub and at least one relay in the manifest")
				transient = false
			}
		}
		d.mu.Lock()
		if ctx.Err() != nil {
			close(d.refreshing)
			d.refreshing = nil
			d.mu.Unlock()
			return nil, ctx.Err()
		}
		now = time.Now()
		if err == nil {
			if d.current == nil || !reflect.DeepEqual(d.manifest, m) {
				endpoints := make([]*url.URL, 0, len(m.Nodes))
				weights := make([]int, 0, len(m.Nodes))
				policies := make(map[string]tlsidentity.Policy)
				for _, n := range m.Nodes {
					u, _ := cluster.Origin(n.URL)
					endpoints = append(endpoints, u)
					weights = append(weights, n.Weight)
					policies[u.Scheme+"://"+u.Host] = tlsidentity.Policy{SNI: n.SNI, PinSHA256: n.PinSHA256}
				}
				var transport http.RoundTripper = c.transport
				if pool, ok := c.transport.(*identityPool); ok {
					transport = identityView{pool: pool, policies: policies}
				} else {
					for _, policy := range policies {
						if policy != (tlsidentity.Policy{}) {
							close(d.refreshing)
							d.refreshing = nil
							d.mu.Unlock()
							return nil, i18n.Error("invalid TLS identity settings")
						}
					}
				}
				if c.fullManagedHTTP() {
					var trustErr error
					transport, trustErr = managedDiscoveryView(transport, endpoints)
					if trustErr != nil {
						close(d.refreshing)
						d.refreshing = nil
						d.mu.Unlock()
						return nil, trustErr
					}
				}
				d.current = &bond.Client{Endpoints: endpoints, Weights: weights, ExpectedHub: m.HubID,
					RouteMode: bondRouteMode(c.BondRoute), DirectOrigin: bondOriginKey(c.ServerURL),
					Transport: transport, Username: c.Username, Password: c.Password,
					AttemptTimeout: c.FallbackAttemptTimeout, SetupTimeout: c.ConnectTimeout,
					Pipeline: c.BondPipeline, PersistentLanes: c.BondLanes, Adaptive: c.BondAdaptive, AutoTune: c.BondAutoTune, TrafficMode: c.BondTraffic}
				d.manifest = m
			}
			d.expires = now.Add(time.Duration(m.ValidFor) * time.Second)
			d.refreshAt = now.Add(min(30*time.Second, time.Duration(m.ValidFor)*time.Second/2))
			d.lastErr = nil
		} else {
			d.refreshAt = now.Add(5 * time.Second)
			if !transient || !now.Before(d.expires) {
				d.current = nil
			}
			d.lastErr = err
			if d.current != nil {
				d.lastErr = nil
			}
		}
		close(d.refreshing)
		d.refreshing = nil
		current, resultErr := d.current, d.lastErr
		d.mu.Unlock()
		return current, resultErr
	}
}
