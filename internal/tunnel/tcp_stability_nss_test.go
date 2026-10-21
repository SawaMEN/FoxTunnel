//go:build linux && cgo && nss

package tunnel

import "testing"

func TestStage3TCPResetIsNotEOFWithNSS(t *testing.T) {
	testStage3TCPResetIsNotEOF(t, "nss")
}
