// Package safejson decodes bounded configuration objects without duplicate keys.
package safejson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

var ErrInvalid = errors.New("invalid configuration document")

func Decode(r io.Reader, maxBytes int64, out any) error {
	data, err := document(r, maxBytes, true)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrInvalid
	}
	return nil
}

// DecodeObject retains case-sensitive keys, such as filenames in a manifest,
// while rejecting duplicates at every level. Callers validate the object schema.
func DecodeObject(r io.Reader, maxBytes int64) (map[string]json.RawMessage, error) {
	data, err := document(r, maxBytes, false)
	if err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil || object == nil {
		return nil, ErrInvalid
	}
	return object, nil
}

func document(r io.Reader, maxBytes int64, lowercase bool) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil || int64(len(data)) > maxBytes || !utf8.Valid(data) {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if !uniqueValue(d, 0, lowercase) {
		return nil, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	return data, nil
}

// Reject duplicate keys and case aliases, including in nested node objects.
func uniqueValue(d *json.Decoder, depth int, lowercase bool) bool {
	if depth > 8 {
		return false
	}
	t, err := d.Token()
	if err != nil {
		return false
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return true
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for d.More() {
			t, err := d.Token()
			key, ok := t.(string)
			if err != nil || !ok || (lowercase && key != strings.ToLower(key)) || seen[key] {
				return false
			}
			seen[key] = true
			if !uniqueValue(d, depth+1, lowercase) {
				return false
			}
		}
	case '[':
		for d.More() {
			if !uniqueValue(d, depth+1, lowercase) {
				return false
			}
		}
	default:
		return false
	}
	end, err := d.Token()
	return err == nil && ((delim == '{' && end == json.Delim('}')) || (delim == '[' && end == json.Delim(']')))
}
