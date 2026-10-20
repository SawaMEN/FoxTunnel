package tunnel

import "testing"

// Each variant invokes the existing full SOCKS -> authenticated HTTPS ->
// destination echo benchmark. "64B" is latency-sensitive; "1MiB" is bulk.
// Staging and TLS handshakes occur outside each sub-benchmark's timed loop.
// These are loopback profiles only, never a claim about VDS or DPI throughput.
func BenchmarkStage3GoH2(b *testing.B) {
	benchmarkNativeOptions(b, "go", false, "h2-connect")
}

func BenchmarkStage3GoH3(b *testing.B) {
	benchmarkNativeOptions(b, "go", false, "h3-post")
}
