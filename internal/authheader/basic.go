// Package authheader validates the single Basic proxy authorization value.
//
// Authentication is always inside a verified TLS transport. This parser does
// not offer replay prevention; credential rotation/revocation belongs to access.
package authheader

import (
	"encoding/base64"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxHeaderBytes allows the managed access policy maximum (256-byte username,
// 1024-byte password) with base64 expansion, while bounding memory on SDK hosts.
const MaxHeaderBytes = 2048

// ValidCredentials is shared by configuration and the wire parser. Usernames
// support UTF-8 profiles but exclude whitespace, controls and the separator.
// Passwords retain their original bytes; colons are valid inside a password.
func ValidCredentials(name, secret string) bool {
	if len(name) < 1 || len(name) > 256 || len(secret) < 1 || len(secret) > 1024 || !utf8.ValidString(name) {
		return false
	}
	for _, c := range name {
		if c == ':' || unicode.IsControl(c) || unicode.IsSpace(c) {
			return false
		}
	}
	return true
}

// Parse fails closed on duplicate headers, noncanonical encoding, oversize
// values, empty credentials and invalid usernames. No credentials are logged.
func Parse(header http.Header) (username, password string, ok bool) {
	if header == nil {
		return "", "", false
	}
	var value string
	foundHeader := false
	for key, values := range header {
		if !strings.EqualFold(key, "Proxy-Authorization") {
			continue
		}
		if foundHeader || len(values) != 1 {
			return "", "", false
		}
		value = values[0]
		foundHeader = true
	}
	if !foundHeader {
		return "", "", false
	}
	if len(value) < len("Basic ")+4 || len(value) > MaxHeaderBytes ||
		!strings.EqualFold(value[:len("Basic ")], "Basic ") {
		return "", "", false
	}
	token := value[len("Basic "):]
	if len(token)%4 != 0 || strings.ContainsAny(token, " \r\n\t") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(token)
	if err != nil {
		return "", "", false
	}
	name, secret, found := strings.Cut(string(decoded), ":")
	if !found || !ValidCredentials(name, secret) {
		return "", "", false
	}
	return name, secret, true
}
