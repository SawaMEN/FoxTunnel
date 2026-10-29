package tunnel

import (
	"os"
	"testing"
)

func TestStableNativeBondModes(t *testing.T) { testStableNativeBondModes(t, "go") }
func testStableNativeBondModes(t *testing.T, backend string) {
	for _, mode := range []string{"h2-connect", "h2-post", "h3-post", "wss", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		if backend == "nss" && mode == "h3-post" {
			continue
		}
		trafficModes := []string{"auto"}
		if os.Getenv("VETROFF_STABLE_MATRIX") == "full" {
			trafficModes = []string{"auto", "latency", "throughput"}
		}
		for _, traffic := range trafficModes {
			for _, lanes := range []bool{false, true} {
				carrier := "rpc"
				if lanes {
					carrier = "lanes"
				}
				t.Run(mode+"/"+traffic+"/"+carrier, func(t *testing.T) {
					t.Parallel() // Independent TLS/relay fixtures; avoid serial timeout accumulation.
					testBondedSOCKSNativeLanes(t, backend, 0, true, mode, lanes, traffic)
				})
			}
		}
	}
}
