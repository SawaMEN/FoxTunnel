//go:build linux && cgo && nss

package tunnel

import "testing"

func TestStableNativeBondModesNSS(t *testing.T) { testStableNativeBondModes(t, "nss") }
