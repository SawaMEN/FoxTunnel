//go:build nss && cgo && linux

package foxtunnel_test

import (
	ft "github.com/SawaMEN/FoxTunnel"
	"github.com/SawaMEN/FoxTunnel/internal/nsstls"
	"testing"
)

func TestPublicNSSDialHalfClose(t *testing.T) { testPublicDialHalfCloseAndSetupContext(t, "nss") }

func TestPublicNSSClosePendingDial(t *testing.T) { testPublicCloseCancelsPendingDial(t, "nss") }

func TestPublicNSSMozillaProfile(t *testing.T) {
	if nsstls.Version() != "3.130" {
		t.Skip("requires pinned NSS runtime")
	}
	testPublicDialHalfCloseAndSetupContext(t, "nss", ft.TLSClientFirefox158)
}
