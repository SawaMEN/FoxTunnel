//go:build neqo && nss && cgo && linux && amd64

package tunnel

import "testing"

func TestIPNeqoTransport(t *testing.T) { testIPTransports(t, "nss", true) }
