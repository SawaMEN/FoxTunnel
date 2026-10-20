//go:build nss && cgo && linux

package tunnel

import "testing"

// NSS is used for TCP TLS; Go still implements the HTTP/2 frame pipeline.
// Go pprof cannot sample CPU execution within libnss C itself.
func BenchmarkStage3NSSH2(b *testing.B) {
	benchmarkNativeOptions(b, "nss", false, "h2-connect")
}
