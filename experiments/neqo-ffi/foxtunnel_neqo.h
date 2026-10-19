/* First-stage FoxTunnel <-> Mozilla Neqo C ABI. Experimental, not for deployment.
 * The opaque handle and all operations are single-thread-owned. No network
 * receive or TLS certificate authentication exists in this ABI revision. */
#ifndef FOXTUNNEL_NEQO_H
#define FOXTUNNEL_NEQO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct NeqoProbe;
uint32_t ft_neqo_abi_version(void);
/* All arguments must be readable, NUL-terminated C strings.
 * local_addr and remote_addr use IP:port or [IPv6]:port. */
struct NeqoProbe *ft_neqo_new(const char *host,
                              const char *local_addr,
                              const char *remote_addr);
/* Returns 1 for packet written, 0 if none, -1 for invalid arguments, -2
 * for insufficient capacity (out_len is required size, packet retained).
 * The output is a raw UDP payload, not an authenticated tunnel. */
int32_t ft_neqo_initial(struct NeqoProbe *client, uint8_t *out,
                        size_t capacity, size_t *out_len);
void ft_neqo_free(struct NeqoProbe *client);
#ifdef __cplusplus
}
#endif
#endif
