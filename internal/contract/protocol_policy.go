package contract

import (
	"encoding/json"
	"errors"
)

// ProtocolPolicy selects per-request TCP/UDP version/capability confirmation.
// Its zero value preserves old configuration files and means legacy.
type ProtocolPolicy string

const (
	ProtocolLegacy ProtocolPolicy = "legacy"
	ProtocolStrict ProtocolPolicy = "strict"
)

var ErrProtocolPolicy = errors.New("protocol policy must be legacy or strict")

// ParseProtocolPolicy accepts only explicit CLI/JSON policy names, never an
// empty value, unknown spelling or a peer-controlled error message.
func ParseProtocolPolicy(value string) (ProtocolPolicy, error) {
	if value != string(ProtocolLegacy) && value != string(ProtocolStrict) {
		return "", ErrProtocolPolicy
	}
	return ProtocolPolicy(value), nil
}

func (p ProtocolPolicy) Validate() error {
	if p == "" {
		return nil
	}
	_, err := ParseProtocolPolicy(string(p))
	return err
}

func (p ProtocolPolicy) Effective() ProtocolPolicy {
	if p == "" {
		return ProtocolLegacy
	}
	return p
}

// Omission is backward compatible; explicit null/empty/non-string values are
// errors. Treating null as a string zero value could silently disable strict.
func (p *ProtocolPolicy) UnmarshalJSON(data []byte) error {
	var value *string
	if json.Unmarshal(data, &value) != nil || value == nil {
		return ErrProtocolPolicy
	}
	parsed, err := ParseProtocolPolicy(*value)
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}
