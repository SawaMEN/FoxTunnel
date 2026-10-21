package tunnel

import (
	"errors"
	"net/http"
	"strings"

	"github.com/SawaMEN/FoxTunnel/internal/buildinfo"
)

const protocolVersionHeader = "X-FoxTunnel-Version"
const protocolRequireHeader = "X-FoxTunnel-Require"
const protocolCapabilitiesHeader = "X-FoxTunnel-Capabilities"

// ErrProtocolNegotiation is terminal: never retry without version/capabilities.
var ErrProtocolNegotiation = errors.New("FoxTunnel protocol negotiation failed")

// protocolValue checks actual keys as SDK hosts may use noncanonical maps.
func protocolValue(h http.Header, name string) (string, bool, bool) {
	value, found := "", false
	for key, values := range h {
		if !strings.EqualFold(key, name) {
			continue
		}
		if found || len(values) != 1 {
			return "", true, false
		}
		value, found = values[0], true
	}
	return value, found, true
}

func protocolTokens(value string) ([]string, bool) {
	if len(value) == 0 || len(value) > 256 {
		return nil, false
	}
	tokens := strings.Split(value, ",")
	if len(tokens) > 8 {
		return nil, false
	}
	seen := make(map[string]bool)
	for i, token := range tokens {
		token = strings.Trim(token, " \t")
		if token == "" || len(token) > 32 || seen[token] {
			return nil, false
		}
		for _, b := range []byte(token) {
			if (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '-' {
				return nil, false
			}
		}
		tokens[i], seen[token] = token, true
	}
	return tokens, true
}

// Negotiation belongs to each inner TCP/UDP request, never the WSS/XHTTP
// envelope or cluster/bond RPCs. Authentication and managed access run first.
func protocolRequest(r *http.Request) bool {
	if r.ProtoMajor != 2 && r.ProtoMajor != 3 {
		return false
	}
	return r.Method == http.MethodConnect || (r.Method == http.MethodPost &&
		(r.URL.Path == postPath || r.URL.Path == udpPath || r.URL.Path == udpStreamPath))
}

func (s *Server) acceptProtocol(w http.ResponseWriter, r *http.Request) bool {
	version, present, valid := protocolValue(r.Header, protocolVersionHeader)
	required, hasRequired, validRequired := protocolValue(r.Header, protocolRequireHeader)
	if !valid || !validRequired || (hasRequired && !present) {
		http.Error(w, "invalid protocol negotiation", http.StatusBadRequest)
		return false
	}
	if !present {
		if s.RequireProtocolNegotiation {
			http.Error(w, "protocol negotiation required", http.StatusUpgradeRequired)
			return false
		}
		return true // Explicit legacy deployment policy; no negotiated guarantee.
	}
	if version != buildinfo.ProtocolDraft {
		http.Error(w, "unsupported protocol version", http.StatusUpgradeRequired)
		return false
	}
	var tokens []string
	if hasRequired {
		var ok bool
		tokens, ok = protocolTokens(required)
		if !ok {
			http.Error(w, "invalid protocol capabilities", http.StatusBadRequest)
			return false
		}
	}
	available := make(map[string]bool)
	capabilities := make([]string, 0, 4)
	if !s.BondRelayOnly {
		available["tcp"] = true
		capabilities = append(capabilities, "tcp")
		if s.EnableUDP {
			available["udp-v1"], available["udp-stream-v2"] = true, true
			capabilities = append(capabilities, "udp-v1", "udp-stream-v2")
		}
		if s.Padding {
			available["padding-initial-v1"] = true
			capabilities = append(capabilities, "padding-initial-v1")
		}
	}
	for _, token := range tokens {
		if !available[token] {
			http.Error(w, "unsupported protocol capability", http.StatusBadRequest)
			return false
		}
	}
	w.Header().Set(protocolVersionHeader, buildinfo.ProtocolDraft)
	if len(capabilities) > 0 {
		w.Header().Set(protocolCapabilitiesHeader, strings.Join(capabilities, ","))
	}
	return true
}

func (c *Client) requestProtocol(r *http.Request, capability string) {
	if !c.RequireProtocolNegotiation {
		return
	}
	r.Header.Set(protocolVersionHeader, buildinfo.ProtocolDraft)
	if capability == "tcp" && c.Padding {
		capability += ",padding-initial-v1"
	}
	r.Header.Set(protocolRequireHeader, capability)
}

func (c *Client) verifyProtocol(r *http.Response, capability string) error {
	if !c.RequireProtocolNegotiation {
		return nil
	}
	version, present, valid := protocolValue(r.Header, protocolVersionHeader)
	if !valid || !present || version != buildinfo.ProtocolDraft {
		return ErrProtocolNegotiation
	}
	value, present, valid := protocolValue(r.Header, protocolCapabilitiesHeader)
	if !valid || !present {
		return ErrProtocolNegotiation
	}
	tokens, valid := protocolTokens(value)
	if !valid {
		return ErrProtocolNegotiation
	}
	confirmed := make(map[string]bool)
	for _, token := range tokens {
		confirmed[token] = true
	}
	if !confirmed[capability] || (capability == "tcp" && c.Padding && !confirmed["padding-initial-v1"]) {
		return ErrProtocolNegotiation
	}
	return nil
}
