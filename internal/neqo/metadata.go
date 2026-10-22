package neqo

import (
	"encoding/binary"
	"errors"
	"golang.org/x/net/http/httpguts"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const maxHeaders = 64 << 10

func putFields(fields ...string) []byte {
	var out []byte
	for _, v := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(v)))
		out = append(out, v...)
	}
	return out
}
func takeFields(p []byte) ([][]byte, error) {
	var fields [][]byte
	for len(p) > 0 {
		if len(p) < 4 {
			return nil, errProtocol
		}
		n := int(binary.BigEndian.Uint32(p))
		p = p[4:]
		if n > len(p) {
			return nil, errProtocol
		}
		fields = append(fields, p[:n])
		p = p[n:]
		if len(fields) > 256 {
			return nil, errProtocol
		}
	}
	return fields, nil
}
func requestMetadata(r *http.Request) ([]byte, error) {
	if r == nil || r.URL == nil || r.URL.Scheme != "https" || !httpguts.ValidHeaderFieldValue(r.Host) {
		return nil, errors.New("invalid Neqo request")
	}
	method := r.Method
	if method == "" {
		method = "GET"
	}
	if !httpguts.ValidHeaderFieldName(method) {
		return nil, errors.New("invalid method")
	}
	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}
	path := r.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	fields := []string{method, "https", authority, path}
	if method == http.MethodConnect {
		if r.Host == "" {
			return nil, errors.New("CONNECT requires an explicit authority")
		}
		host, port, err := net.SplitHostPort(authority)
		n, parseErr := strconv.Atoi(port)
		if err != nil || parseErr != nil || host == "" || n < 1 || n > 65535 || strings.ContainsAny(host, " /\\@?#\t\r\n") {
			return nil, errors.New("invalid CONNECT authority")
		}
		// RFC 9114 classic CONNECT has authority only, no scheme or path.
		fields[1], fields[3] = "", ""
	}
	count := 0
	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if lower == "content-length" {
			continue
		} // Request.ContentLength is authoritative.
		if !httpguts.ValidHeaderFieldName(lower) || lower == "connection" || lower == "upgrade" || lower == "transfer-encoding" || lower == "keep-alive" || lower == "proxy-connection" || lower == "host" {
			return nil, errors.New("unsupported Neqo header")
		}
		for _, v := range values {
			if !httpguts.ValidHeaderFieldValue(v) {
				return nil, errors.New("invalid Neqo header")
			}
			count++
			if count > 128 {
				return nil, errors.New("too many Neqo headers")
			}
			fields = append(fields, lower, v)
		}
	}
	if r.ContentLength > 0 {
		if count == 128 {
			return nil, errors.New("too many Neqo headers")
		}
		fields = append(fields, "content-length", strconv.FormatInt(r.ContentLength, 10))
	}
	metadata := putFields(fields...)
	if len(metadata) > maxHeaders {
		return nil, errors.New("Neqo request headers too large")
	}
	return metadata, nil
}
