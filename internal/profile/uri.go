// Package profile defines the versioned vetroff:// connection-link format.
// It never imports local file paths or disables TLS certificate verification.
package profile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/SawaMEN/FoxTunnel/internal/i18n"
	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
)

const Scheme = "vetroff"
const MaxLinkBytes = 16 << 10

type Config struct {
	Version        int      `json:"v"`
	Servers        []string `json:"servers"`
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	TLSBackend     string   `json:"tls,omitempty"`
	SNI            string   `json:"sni,omitempty"`
	PinSHA256      string   `json:"pin_sha256,omitempty"`
	Encryption     string   `json:"encryption,omitempty"`
	Balance        string   `json:"balance,omitempty"`
	Bond           bool     `json:"bond,omitempty"`
	Discover       bool     `json:"discover,omitempty"`
	Pipeline       string   `json:"pipeline,omitempty"`
	Padding        bool     `json:"padding,omitempty"`
	ConnectTimeout string   `json:"connect_timeout,omitempty"`
	AttemptTimeout string   `json:"attempt_timeout,omitempty"`
}

func invalid() error { return errors.New(i18n.Text("invalid vetroff connection link")) }

// normalize validates a complete profile without opening files or sockets.
func (c *Config) normalize() error {
	if c.Version != 1 || len(c.Servers) < 1 || len(c.Servers) > 8 {
		return invalid()
	}
	if c.Username == "" || c.Password == "" || strings.Contains(c.Username, ":") || len(c.Username) > 256 || len(c.Password) > 1024 || !utf8.ValidString(c.Username) || !utf8.ValidString(c.Password) {
		return invalid()
	}
	seen := make(map[string]bool)
	for _, raw := range c.Servers {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(u.Host, "\x00\r\n\t ") {
			return invalid()
		}
		port := u.Port()
		if port == "" {
			port = "443"
		} else {
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 {
				return invalid()
			}
			port = strconv.Itoa(n)
		}
		key := net.JoinHostPort(strings.ToLower(u.Hostname()), port)
		if seen[key] {
			return invalid()
		}
		seen[key] = true
	}
	if c.TLSBackend == "" {
		c.TLSBackend = "go"
	}
	policy, err := tlsidentity.Normalize(c.SNI, c.PinSHA256)
	if err != nil {
		return invalid()
	}
	c.SNI, c.PinSHA256 = policy.SNI, policy.PinSHA256
	if c.Encryption == "" {
		c.Encryption = "tls13"
	}
	if c.Encryption != "tls13" {
		return invalid()
	}
	if c.TLSBackend != "go" && c.TLSBackend != "nss" {
		return invalid()
	}
	if c.Balance == "" {
		c.Balance = "failover"
	}
	if c.Balance != "failover" && c.Balance != "round-robin" && c.Balance != "least-active" {
		return invalid()
	}
	if c.Pipeline == "" {
		c.Pipeline = "auto"
	}
	if c.Pipeline != "auto" && c.Pipeline != "4" && c.Pipeline != "8" {
		return invalid()
	}
	if c.Discover && (!c.Bond || len(c.Servers) != 1) {
		return invalid()
	}
	if c.Bond && ((!c.Discover && len(c.Servers) < 2) || c.Padding) {
		return invalid()
	}
	if c.ConnectTimeout == "" {
		c.ConnectTimeout = "15s"
	}
	if c.AttemptTimeout == "" {
		c.AttemptTimeout = "5s"
	}
	connect, err := time.ParseDuration(c.ConnectTimeout)
	if err != nil || connect <= 0 || connect > 2*time.Minute {
		return invalid()
	}
	attempt, err := time.ParseDuration(c.AttemptTimeout)
	if err != nil || attempt <= 0 || attempt > 30*time.Second || (c.Bond && attempt < 100*time.Millisecond) {
		return invalid()
	}
	return nil
}
func Encode(config Config) (string, error) {
	if err := config.normalize(); err != nil {
		return "", err
	}
	data, err := json.Marshal(config)
	if err != nil {
		return "", invalid()
	}
	link := Scheme + "://" + base64.RawURLEncoding.EncodeToString(data)
	if len(link) > MaxLinkBytes {
		return "", invalid()
	}
	return link, nil
}

// Decode rejects unknown and duplicate fields. Errors never include the input
// URI, decoded JSON, credentials or parser diagnostics containing those values.
func Decode(link string) (Config, error) {
	var config Config
	if len(link) > MaxLinkBytes || !strings.HasPrefix(link, Scheme+"://") || strings.ContainsAny(link, " \r\n\t") {
		return config, invalid()
	}
	u, err := url.Parse(link)
	if err != nil || u.Scheme != Scheme || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return config, invalid()
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(u.Host)
	if err != nil || !utf8.Valid(data) {
		return config, invalid()
	}
	if !uniqueFields(data) {
		return config, invalid()
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, invalid()
	}
	if err := config.normalize(); err != nil {
		return Config{}, invalid()
	}
	return config, nil
}
func uniqueFields(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool)
	allowed := map[string]bool{"v": true, "servers": true, "username": true, "password": true, "tls": true, "sni": true, "pin_sha256": true, "encryption": true, "balance": true, "bond": true, "discover": true, "pipeline": true, "padding": true, "connect_timeout": true, "attempt_timeout": true}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		key, ok := token.(string)
		if !ok || seen[key] || !allowed[key] {
			return false
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return false
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return false
	}
	var extra any
	return decoder.Decode(&extra) == io.EOF
}
func Read(reader io.Reader) (Config, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxLinkBytes+1))
	if err != nil || len(data) > MaxLinkBytes {
		return Config{}, invalid()
	}
	return Decode(strings.TrimSpace(string(data)))
}
