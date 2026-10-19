//go:build nss && cgo

package tunnel

import "testing"

func TestAccessRevocationIsolationNSS(t *testing.T) {
	testAccessRevocationIsolationAllTransports(t, "nss")
}
