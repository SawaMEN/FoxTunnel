package tunnel

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/SawaMEN/FoxTunnel/internal/cluster"
	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
	"github.com/SawaMEN/FoxTunnel/internal/xhttp"
)

// SetManagedHTTPTransport installs an owned native HTTP stack. XHTTP's inner
// application envelope stays in Go; the outer HTTP, TLS and sockets use Gecko.
func (c *Client) SetManagedHTTPTransport(mode string, factory func() (ManagedTransport, error)) {
	c.SetManagedTransport(mode, factory)
	c.managed.http = true
	c.backend = "auto"
	c.configureManagedHTTP()
}

// SetManagedHTTPTransportWithIdentity delivers the immutable, validated node
// policies to the native factory. Prepare invokes it under the managed lock.
func (c *Client) SetManagedHTTPTransportWithIdentity(mode string, factory func(map[string]tlsidentity.Policy) (ManagedTransport, error)) {
	var owner *managedTransport
	c.SetManagedHTTPTransport(mode, func() (ManagedTransport, error) {
		policies := make(map[string]tlsidentity.Policy, len(owner.nodePolicies))
		for origin, policy := range owner.nodePolicies {
			policies[origin] = policy
		}
		return factory(policies)
	})
	owner = c.managed
	owner.acceptsNodePolicies = true
}

func (c *Client) configureManagedHTTP() {
	var transport tlsTransport = managedHTTPTransport{client: c}
	if xhttp.IsMode(c.nativeTransport) {
		transport = newXHTTPWithOuter(c.nativeTransport, c.tlsConfig, basicAuth(c.Username, c.Password), c.xhttpSettings, transport)
	} else if c.nativeTransport == "h2-post" || c.nativeTransport == "h3-post" {
		transport = postTransport{tlsTransport: transport}
	}
	c.transport.CloseIdleConnections()
	c.transport = transport
}

type managedHTTPTransport struct{ client *Client }

func (t managedHTTPTransport) CloseIdleConnections() {}
func (t managedHTTPTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c := t.client
	reject := func(err error) (*http.Response, error) {
		if r != nil && r.Body != nil {
			r.Body.Close()
		}
		return nil, err
	}
	if r == nil || r.URL == nil || r.URL.Scheme != "https" || r.URL.User != nil {
		return reject(errors.New("native HTTP requires a trusted HTTPS origin"))
	}
	origin, err := cluster.Origin("https://" + r.URL.Host)
	if err != nil {
		return reject(err)
	}
	allowed := sameBondOrigin(origin, c.ServerURL)
	for _, u := range c.fallbackServers {
		allowed = allowed || sameBondOrigin(origin, u)
	}
	if trusted, ok := r.Context().Value(managedOriginsKey{}).(map[string]bool); ok {
		allowed = allowed || trusted[cluster.OriginKey(origin)]
	}
	if !allowed {
		return reject(errors.New("native HTTP origin is not configured or authenticated by discovery"))
	}
	if err := c.Prepare(r.Context()); err != nil {
		return reject(err)
	}
	c.managed.Lock()
	tr, closed := c.managed.transport, c.managed.closed
	c.managed.Unlock()
	if closed {
		return reject(errors.New("native HTTP transport is closed"))
	}
	httpTransport, ok := tr.(http.RoundTripper)
	if !ok {
		return reject(errors.New("native engine has no HTTP IPC adapter"))
	}
	route := "h2"
	if isH3Transport(c.nativeTransport) {
		route = "h3"
	}
	c.status.Route(route, "explicit")
	return monitoredRoundTrip(c.nodeMetrics, managedHTTPAdapter{httpTransport}, r)
}

// Each authenticated topology keeps its own origin snapshot. Refreshing the
// coordinator cannot revoke an already established bond's retry paths.
type managedOriginsKey struct{}
type managedOriginView struct {
	base    http.RoundTripper
	origins map[string]bool
}

func (v managedOriginView) RoundTrip(r *http.Request) (*http.Response, error) {
	return v.base.RoundTrip(r.Clone(context.WithValue(r.Context(), managedOriginsKey{}, v.origins)))
}
func managedDiscoveryView(base http.RoundTripper, endpoints []*url.URL) (http.RoundTripper, error) {
	if len(endpoints) > maxProxyEndpoints {
		return nil, errors.New("native discovery origin limit")
	}
	origins := make(map[string]bool, len(endpoints))
	for _, u := range endpoints {
		origins[cluster.OriginKey(u)] = true
	}
	return managedOriginView{base: base, origins: origins}, nil
}
func (c *Client) fullManagedHTTP() bool { return c.managed != nil && c.managed.http }

type managedHTTPAdapter struct{ http.RoundTripper }

func (managedHTTPAdapter) CloseIdleConnections() {}
