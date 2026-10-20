//go:build nss && cgo && linux

package tunnel

import "testing"

func TestSecurityStage5ManagedUDPIsolationNSS(t *testing.T) {
	testSecurityStage5ManagedUDPIsolation(t, "nss")
}
