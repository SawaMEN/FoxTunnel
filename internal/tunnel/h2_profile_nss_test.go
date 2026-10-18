//go:build nss && cgo && linux

package tunnel

import (
	"github.com/SawaMEN/FoxTunnel/internal/h2profile"
	"testing"
)

func TestNSSHTTP2ReceiveProfile(t *testing.T) { testHTTP2ReceiveProfile(t, "nss") }
func TestNSSHTTP2ReceiveProfileCreditRenewal(t *testing.T) {
	testHTTP2ReceiveProfileCreditRenewal(t, "nss")
}

func TestNSSHTTP2ReceiveProfileTLSRejection(t *testing.T) {
	testNativeVerificationBeforeCredentials(t, "nss", h2profile.Firefox158)
}
func TestNSSHTTP2ReceiveProfileCancellation(t *testing.T) {
	testHTTP2ReceiveProfileCancellation(t, "nss")
}
