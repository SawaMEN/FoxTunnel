//go:build neqo && nss && cgo && linux && amd64

package tunnel

import "testing"

// The same payloads, SOCKS adapter, echo target and independent quic-go server
// as Go-H3. Only the client HTTP/3 engine changes.
func BenchmarkStage6NeqoH3(b *testing.B) {
	benchmarkNativeOptions(b, "neqo", false, "h3-post")
}
