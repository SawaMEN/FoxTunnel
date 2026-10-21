//go:build nss && cgo && linux

package tunnel

import "testing"

func TestStage4NSSDatagramBoundaries(t *testing.T) { testStage4UDPDatagramBoundaries(t, "nss") }
