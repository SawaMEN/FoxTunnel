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

type engine struct{ p unsafe.Pointer }

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
	var wait C.uint64_t
	n := int(C.ftn_output(e.p, ptr(p), C.size_t(len(p)), &wait))
	if n < 0 {
		return 0, 0, errProtocol
	}
	return n, uint64(wait), nil
}
func (e *engine) event(buf []byte) (uint32, uint64, uint64, int, error) {
	var kind C.uint32_t
	var stream, arg C.uint64_t
	n := int(C.ftn_event(e.p, &kind, &stream, &arg, ptr(buf), C.size_t(len(buf))))
	if n < 0 {
		return 0, 0, 0, 0, errProtocol
	}
	return uint32(kind), uint64(stream), uint64(arg), n, nil
}
func (e *engine) authenticate() error {
	if C.ftn_auth(e.p) < 0 {
		return errProtocol
	}
	return nil
}
func (e *engine) fetch(metadata []byte) (uint64, error) {
	var id C.uint64_t
	if C.ftn_fetch(e.p, ptr(metadata), C.size_t(len(metadata)), &id) < 0 {
		return 0, errProtocol
	}
	return uint64(id), nil
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
	var fin C.uint32_t
	n := int(C.ftn_read(e.p, C.uint64_t(id), ptr(p), C.size_t(len(p)), &fin))
	if n < 0 {
		return 0, false, errProtocol
	}
	return n, fin != 0, nil
}
func (e *engine) reset(id uint64) { C.ftn_reset(e.p, C.uint64_t(id)) }
