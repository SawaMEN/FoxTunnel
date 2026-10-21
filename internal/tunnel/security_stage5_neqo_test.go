//go:build neqo && nss && cgo && linux && amd64

package tunnel

import "testing"

func TestSecurityStage5ManagedUDPIsolationNeqo(t *testing.T) {
	testSecurityStage5ManagedUDPIsolation(t, "neqo")
}
