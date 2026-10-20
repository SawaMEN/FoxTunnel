// Package authheader validates the single Basic proxy authorization value.
//
// Authentication is always inside a verified TLS transport. This parser does
// not offer replay prevention; credential rotation/revocation belongs to access.
package authheader

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// MaxHeaderBytes allows the managed access policy maximum (256-byte username,
// 1024-byte password) with base64 expansion, while bounding memory on SDK hosts.
const MaxHeaderBytes = 2048

// Parse fails closed on duplicate headers, noncanonical encoding, oversize
// values, empty credentials and control characters. No credentials are logged.
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
	if !found || len(name) < 1 || len(name) > 256 || len(secret) < 1 || len(secret) > 1024 {
		return "", "", false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < '!' || name[i] > '~' || name[i] == ':' {
			return "", "", false
		}
	}
	return name, secret, true
}
