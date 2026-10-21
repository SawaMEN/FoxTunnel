//go:build neqo && cgo && linux && amd64

package neqo

/*
#cgo LDFLAGS: -L${SRCDIR}/../../rust/neqo-bridge/target/release -lfoxtunnel_neqo -lssl3 -lsmime3 -lnss3 -lnssutil3 -lplds4 -lplc4 -lnspr4 -ldl -lm -lpthread
#include "bridge.h"
#include "build_stamp.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

const Available = true

var errBridge = errors.New("Neqo bridge rejected operation")

// Only the owning actor accesses an engine, on one locked OS thread. Reuse
// scalar out-parameters: fresh locals escape through cgo on every poll/read.
// The bridge borrows them synchronously and never retains these Go pointers.
// Keep this object free of pointers to other Go objects.
type engine struct {
	p                     unsafe.Pointer
	value                 C.uint64_t
	eventStream, eventArg C.uint64_t
	eventKind, finValue   C.uint32_t
}

func ptr(p []byte) *C.uint8_t {
	if len(p) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&p[0]))
}
func checkABI() error {
	if C.ftn_abi() != 1 || C.ftn_init() != 0 {
		return errors.New("Neqo ABI or pinned NSS 3.130 runtime mismatch")
	}
	return nil
}
func newEngine(settings []byte) (*engine, error) {
	if C.ftn_abi() != 1 || C.ftn_init() != 0 {
		return nil, errors.New("Neqo ABI or pinned NSS 3.130 runtime mismatch")
	}
	p := C.ftn_new(ptr(settings), C.size_t(len(settings)))
	if p == nil {
		return nil, errBridge
	}
	return &engine{p}, nil
}
func (e *engine) shutdown() { C.ftn_shutdown(e.p) }
func (e *engine) close()    { C.ftn_free(e.p); e.p = nil }
func (e *engine) input(p []byte) error {
	if C.ftn_input(e.p, ptr(p), C.size_t(len(p))) < 0 {
		return errProtocol
	}
	return nil
}
func (e *engine) output(p []byte) (int, uint64, error) {
	e.value = 0
	n := int(C.ftn_output(e.p, ptr(p), C.size_t(len(p)), &e.value))
	if n < 0 {
		return 0, 0, errProtocol
	}
	return n, uint64(e.value), nil
}
func (e *engine) event(buf []byte) (uint32, uint64, uint64, int, error) {
	e.eventKind, e.eventStream, e.eventArg = 0, 0, 0
	n := int(C.ftn_event(e.p, &e.eventKind, &e.eventStream, &e.eventArg, ptr(buf), C.size_t(len(buf))))
	if n < 0 {
		return 0, 0, 0, 0, errProtocol
	}
	return uint32(e.eventKind), uint64(e.eventStream), uint64(e.eventArg), n, nil
}
func (e *engine) authenticate() error {
	if C.ftn_auth(e.p) < 0 {
		return errProtocol
	}
	return nil
}
func (e *engine) fetch(metadata []byte) (uint64, error) {
	e.value = 0
	if C.ftn_fetch(e.p, ptr(metadata), C.size_t(len(metadata)), &e.value) < 0 {
		return 0, errProtocol
	}
	return uint64(e.value), nil
}
func (e *engine) send(id uint64, p []byte) (int, error) {
	n := int(C.ftn_send(e.p, C.uint64_t(id), ptr(p), C.size_t(len(p))))
	if n < 0 {
		return 0, errProtocol
	}
	return n, nil
}
func (e *engine) fin(id uint64) error {
	if C.ftn_fin(e.p, C.uint64_t(id)) < 0 {
		return errProtocol
	}
	return nil
}
func (e *engine) read(id uint64, p []byte) (int, bool, error) {
	e.finValue = 0
	n := int(C.ftn_read(e.p, C.uint64_t(id), ptr(p), C.size_t(len(p)), &e.finValue))
	if n < 0 {
		return 0, false, errProtocol
	}
	return n, e.finValue != 0, nil
}
func (e *engine) reset(id uint64) { C.ftn_reset(e.p, C.uint64_t(id)) }
