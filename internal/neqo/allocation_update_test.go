//go:build neqo && cgo && linux && amd64

package neqo

import (
	"runtime"
	"testing"
)

func TestUpdateEmptyEventHasNoGoAllocation(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	e, err := newEngine(putFields("localhost", "127.0.0.1:40000", "127.0.0.1:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	buffer := make([]byte, maxMetadata)
	// No packets are sent or received; the new engine has no peer events.
	check := func() {
		kind, stream, arg, n, err := e.event(buffer)
		if err != nil || kind != 0 || stream != 0 || arg != 0 || n != 0 {
			t.Fatal("unexpected empty event", kind, stream, arg, n, err)
		}
	}
	// The ABI only writes kind on an empty queue. Previously zero-initialized
	// locals ensured the other outputs were zero; reused storage must too.
	e.eventStream, e.eventArg = 123, 456
	check()
	if allocations := testing.AllocsPerRun(1000, check); allocations != 0 {
		t.Fatalf("empty event allocated %.2f Go objects per call", allocations)
	}
}
