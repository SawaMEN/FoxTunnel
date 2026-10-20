//go:build nss && cgo && linux

package nsstls

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestStage3NSSFaultStateIsolation(t *testing.T) {
	readFault := errors.New("read fault")
	writeFault := errors.New("write fault")
	c := new(conn)

	c.readFault.Store(&ioFailure{err: readFault})
	c.writeFault.Store(&ioFailure{err: writeFault})
	if got := c.readFault.Load(); got == nil || !errors.Is(got.err, readFault) {
		t.Fatal("read error was not preserved")
	}
	if got := c.writeFault.Load(); got == nil || !errors.Is(got.err, writeFault) {
		t.Fatal("write error was not preserved")
	}
	c.readFault.Store(nil) // successful next read must clear stale state
	if c.readFault.Load() != nil {
		t.Fatal("stale read failure would mask an NSS decrypt error")
	}
	if got := c.writeFault.Load(); got == nil || !errors.Is(got.err, writeFault) {
		t.Fatal("read success unexpectedly overwrote write failure")
	}
	c.writeFault.Store(nil)
	if c.writeFault.Load() != nil {
		t.Fatal("stale write failure")
	}
}

// The read/write callbacks may overlap on the same NSS connection. Verify
// that fault slots are independent and free of races under rapid replacement.
func TestStage3NSSFaultStateConcurrent(t *testing.T) {
	c := new(conn)
	var wg sync.WaitGroup
	for direction := 0; direction < 4; direction++ {
		wg.Add(1)
		go func(d int) {
			defer wg.Done()
			for i := 0; i < 3000; i++ {
				if d%2 == 0 {
					c.readFault.Store(&ioFailure{err: errors.New("read")})
					c.readFault.Store(nil)
					_ = c.writeFault.Load()
				} else {
					c.writeFault.Store(&ioFailure{err: errors.New("write")})
					c.writeFault.Store(nil)
					_ = c.readFault.Load()
				}
			}
		}(direction)
	}
	wg.Wait()
}

// Isolates just the error-bookkeeping cost at the Go/C callback boundary.
// Real NSS encrypt/decrypt costs and cgo entry latency are not captured here.
// Both modes store nil for successful I/O; the error path is uncommon.
func BenchmarkStage3NSSFaultState(b *testing.B) {
	type mutexState struct {
		mu  sync.Mutex
		err error
	}
	var legacy mutexState
	var fast atomic.Pointer[ioFailure]
	failure := errors.New("expected I/O failure")
	for _, testcase := range []struct {
		name string
		set  func()
	}{
		{"mutex-success", func() {
			legacy.mu.Lock()
			legacy.err = nil
			legacy.mu.Unlock()
		}},
		{"atomic-success", func() { fast.Store(nil) }},
		{"mutex-error", func() {
			legacy.mu.Lock()
			legacy.err = failure
			legacy.mu.Unlock()
		}},
		{"atomic-error", func() { fast.Store(&ioFailure{err: failure}) }},
	} {
		b.Run(testcase.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				testcase.set()
			}
		})
	}
}
