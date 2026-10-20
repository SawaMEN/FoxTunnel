//go:build neqo && nss && cgo && linux && amd64

package tunnel

import "testing"

func TestStage4NeqoDatagramBoundaries(t *testing.T) { testStage4UDPDatagramBoundaries(t, "neqo") }
