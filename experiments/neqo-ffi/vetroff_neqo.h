/* Experimental Mozilla Neqo QUIC UDP state machine, ABI version 2.
 * NOT an authenticated HTTP/3 transport: all certificate authentication is
 * rejected, and no request or proxy credential API is provided.
 * Handles are single-thread-owned; never call concurrently or after free. */
#ifndef VETROFF_NEQO_H
#define VETROFF_NEQO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FT_NEQO_INVALID (-1)
#define FT_NEQO_TOO_SMALL (-2)
#define FT_NEQO_STOPPED (-3)
#define FT_NEQO_IDLE 0
#define FT_NEQO_DATAGRAM 1
#define FT_NEQO_TIMER 2

struct NeqoProbe;
uint32_t ft_neqo_abi_version(void);

/* All three arguments are readable, NUL-terminated strings.
 * local_addr and remote_addr are numeric IP:port or [IPv6]:port.
 * The caller must bind a socket to local_addr and connect it to remote_addr. */
struct NeqoProbe *ft_neqo_new(const char *host,
                              const char *local_addr,
                              const char *remote_addr);

/* Poll output repeatedly until FT_NEQO_TIMER or FT_NEQO_IDLE.
 * DATAGRAM: UDP payload stored in out, length in out_len.
 * TOO_SMALL: packet retained; required length stored in out_len.
 * TIMER: call again after timeout_ms milliseconds, or sooner on new input.
 * out_len and timeout_ms must be distinct writable pointers. */
int32_t ft_neqo_next(struct NeqoProbe *client, uint8_t *out,
                     size_t capacity, size_t *out_len, uint32_t *timeout_ms);

/* Feed datagram received from connected UDP peer, verifying source_addr
 * matches the numeric remote_addr supplied to ft_neqo_new. Returns
 * FT_NEQO_DATAGRAM if accepted, otherwise a negative error code.
 * A valid-looking datagram is NOT authenticated by this call. */
int32_t ft_neqo_feed(struct NeqoProbe *client, const char *source_addr,
                     const uint8_t *bytes, size_t length);

/* 1 = certificate authentication was explicitly rejected, 0 = not yet
 * rejected. No authenticated state is possible in this ABI. */
int32_t ft_neqo_auth_rejected(struct NeqoProbe *client);

/* Idempotent stop. The caller must subsequently free the handle. */
int32_t ft_neqo_stop(struct NeqoProbe *client);

/* Compatibility wrapper: generates datagrams but ignores timer notifications.
 * Prefer ft_neqo_next in new clients. */
int32_t ft_neqo_initial(struct NeqoProbe *client, uint8_t *out,
                        size_t capacity, size_t *out_len);

void ft_neqo_free(struct NeqoProbe *client);

#ifdef __cplusplus
}
#endif
#endif
