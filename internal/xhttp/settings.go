package xhttp

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
)

// Settings are shared by a cluster. Host affects only the outer HTTP carrier,
// never its network endpoint or TLS SNI/certificate policy. Configure before use.
type Settings struct {
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
}

var ErrSettings = errors.New("invalid XHTTP path or Host")

func IsMode(mode string) bool {
	return mode == "xhttp-stream-one" || mode == "xhttp-stream-up" || mode == "xhttp-packet-up"
}

func Normalize(path, host string) (Settings, error) {
	if path == "" {
		path = Path
	}
	if len(path) > 256 || !strings.HasPrefix(path, "/") || path == "/" {
		return Settings{}, ErrSettings
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	if len(path) > 256 {
		return Settings{}, ErrSettings
	}
	for _, part := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/"), "/") {
		if part == "" || part == "." || part == ".." {
			return Settings{}, ErrSettings
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~') {
				return Settings{}, ErrSettings
			}
		}
	}
	if host == "" {
		return Settings{Path: path}, nil
	}
	if len(host) > 259 || strings.ContainsAny(host, "\x00\r\n\t \\%") || strings.HasSuffix(host, ":") {
		return Settings{}, ErrSettings
	}
	host = strings.ToLower(host)
	u, err := url.Parse("https://" + host)
	if err != nil || u.Host != host || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Hostname() == "" {
		return Settings{}, ErrSettings
	}
	name := u.Hostname()
	if ip := net.ParseIP(name); ip == nil {
		if strings.HasPrefix(host, "[") {
			return Settings{}, ErrSettings
		}
		if _, err := tlsidentity.Normalize(name, ""); err != nil {
			return Settings{}, ErrSettings
		}
	} else if strings.Contains(name, ":") && !strings.HasPrefix(host, "[") {
		return Settings{}, ErrSettings
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return Settings{}, ErrSettings
		}
	}
	return Settings{Path: path, Host: host}, nil
}

// Match applies the configured HTTP route before any carrier allocation.
func (s Settings) Match(rHost string, path string) bool {
	return (s.Host == "" || strings.EqualFold(rHost, s.Host)) && strings.HasPrefix(path, s.Path)
}
