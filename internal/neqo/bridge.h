#ifndef FT_NEQO_BRIDGE_H
#define FT_NEQO_BRIDGE_H
#include <stddef.h>
#include <stdint.h>
/* ABI 1: all calls and destruction on one OS thread. No Go pointers retained.
 * Engine is opaque. Negative results are terminal except -2 (buffer too small).
 * Byte buffers are borrowed for a single synchronous call. */
uint32_t ftn_abi(void);
int32_t ftn_init(void);
void *ftn_new(const uint8_t *settings, size_t len);
void ftn_free(void *engine);
int32_t ftn_shutdown(void *engine);
int32_t ftn_input(void *engine, const uint8_t *packet, size_t len);
int32_t ftn_output(void *engine, uint8_t *packet, size_t capacity, uint64_t *wait_ns);
int32_t ftn_event(void *engine, uint32_t *kind, uint64_t *stream, uint64_t *arg, uint8_t *data, size_t capacity);
int32_t ftn_auth(void *engine);
int32_t ftn_fetch(void *engine, const uint8_t *request, size_t len, uint64_t *stream);
int32_t ftn_send(void *engine, uint64_t stream, const uint8_t *data, size_t len);
int32_t ftn_fin(void *engine, uint64_t stream);
int32_t ftn_read(void *engine, uint64_t stream, uint8_t *data, size_t capacity, uint32_t *fin);
int32_t ftn_reset(void *engine, uint64_t stream);
#endif
