package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net/url"
	"os"
	"runtime"

	"github.com/SawaMEN/FoxTunnel/internal/cluster"
	"github.com/SawaMEN/FoxTunnel/internal/safejson"
	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
)

const maxNodePinsFile = 16 << 10

type nodePinsDocument struct {
	Version int            `json:"v"`
	Nodes   []nodePinEntry `json:"nodes"`
}

type nodePinEntry struct {
	URL       string `json:"url"`
	SNI       string `json:"sni,omitempty"`
	PinSHA256 string `json:"pin_sha256"`
}

// SetNodePinsFile enables CA/hostname validation PLUS independent SPKI pins
// for every explicitly trusted HTTPS ingress. The private local file is
// authenticated by file permissions, and all configured origins must match.
// Call after TLS/profile and fallback configuration, before EnableBond/Serve.
// Discovery supplies a separate, dynamic TLS policy: do not combine them.
func (c *Client) SetNodePinsFile(path string) error {
	if c.managed != nil {
		c.managed.Lock()
		defer c.managed.Unlock()
		if !c.managed.http || !c.managed.acceptsNodePolicies || c.managed.transport != nil || c.managed.closed {
			return errors.New("configure native node pins before starting the helper")
		}
	}
	if path == "" || c.bondClient != nil || c.bondDiscovery != nil ||
		c.identity != (tlsidentity.Policy{}) {
		return errors.New("configure per-node SPKI pins before bonding, without discovery or a separate primary identity override")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() ||
		(runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) ||
		info.Size() > maxNodePinsFile {
		return errors.New("node pins file must be a private regular file (chmod 600, no symlinks, <=16KiB)")
	}
	f, err := os.Open(path)
	if err != nil {
		return errors.New("cannot open node pins file")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return errors.New("node pins file changed during opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxNodePinsFile+1))
	if err != nil || len(data) > maxNodePinsFile {
		return errors.New("invalid node pins file size")
	}
	var doc nodePinsDocument
	if safejson.Decode(bytes.NewReader(data), maxNodePinsFile, &doc) != nil ||
		doc.Version != 1 || len(doc.Nodes) != len(c.fallbackServers)+1 {
		return errors.New("invalid node pins document")
	}
	configured := make(map[string]string, len(c.fallbackServers)+1)
	for _, endpoint := range append([]*url.URL{c.ServerURL}, c.fallbackServers...) {
		origin := endpoint.Scheme + "://" + endpoint.Host
		configured[cluster.OriginKey(endpoint)] = origin
	}
	policies := make(map[string]tlsidentity.Policy, len(configured))
	for _, entry := range doc.Nodes {
		node, err := cluster.Origin(entry.URL)
		if err != nil || entry.PinSHA256 == "" {
			return errors.New("invalid node pins identity")
		}
		policy, err := tlsidentity.Normalize(entry.SNI, entry.PinSHA256)
		if err != nil {
			return errors.New("invalid node SPKI pin or SNI")
		}
		key := cluster.OriginKey(node)
		origin, ok := configured[key]
		if !ok || policies[origin] != (tlsidentity.Policy{}) {
			return errors.New("node pins file includes a duplicate or unconfigured HTTPS origin")
		}
		policies[origin] = policy
	}
	if len(policies) != len(configured) {
		return errors.New("missing SPKI pin for a trusted ingress")
	}
	if c.managed != nil {
		if len(c.managed.nodePolicies) != 0 {
			return errors.New("node pins were already configured")
		}
		c.managed.nodePolicies = policies
		return nil
	}
	pool, ok := c.transport.(*identityPool)
	if !ok {
		return errors.New("node TLS identity pool unavailable")
	}
	// Locked together with the transport setup; no requests exist until Serve.
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if len(pool.nodePolicies) != 0 {
		return errors.New("node pins were already configured")
	}
	pool.nodePolicies = policies
	return nil
}
