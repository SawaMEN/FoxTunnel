//go:build nss && cgo && linux

package foxtunnel_test

import "testing"

func TestPublicNSSDialHalfClose(t *testing.T) { testPublicDialHalfCloseAndSetupContext(t, "nss") }

func TestPublicNSSClosePendingDial(t *testing.T) { testPublicCloseCancelsPendingDial(t, "nss") }
