//go:build nss && cgo && linux

package tunnel

import "testing"

func TestIPNSSTransports(t *testing.T) { testIPTransports(t, "nss", false) }
