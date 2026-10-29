#include "vetroff_neqo.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    assert(ft_neqo_abi_version() == 2);
    assert(ft_neqo_new("bad..example", "127.0.0.1:12345", "127.0.0.1:443") == NULL);
    assert(ft_neqo_new("example.org", "127.0.0.1:12345", "localhost:443") == NULL);
    struct NeqoProbe *client =
        ft_neqo_new("example.org", "127.0.0.1:12345", "127.0.0.1:443");
    assert(client != NULL);

    size_t length = 0;
    uint32_t timeout_ms = 0;
    assert(ft_neqo_next(client, NULL, 0, &length, &timeout_ms) == FT_NEQO_TOO_SMALL);
    assert(length >= 1200 && length <= 65527);
    uint8_t *buf = malloc(length);
    assert(buf != NULL);
    size_t written = 0;
    assert(ft_neqo_next(client, buf, length, &written, &timeout_ms) == FT_NEQO_DATAGRAM);
    assert(written == length && (buf[0] & 0xc0) == 0xc0);
    assert(buf[1] == 0 && buf[2] == 0 && buf[3] == 0 && buf[4] == 1);
    assert(ft_neqo_auth_rejected(client) == 0);

    /* The caller must verify recvfrom's peer; an unexpected source is refused. */
    static const uint8_t malformed[] = {0x01, 0x02, 0x03};
    assert(ft_neqo_feed(client, "127.0.0.2:443", malformed, sizeof malformed) == FT_NEQO_INVALID);
    assert(ft_neqo_feed(client, "127.0.0.1:443", NULL, 0) == FT_NEQO_INVALID);
    assert(ft_neqo_feed(client, "127.0.0.1:443", malformed, sizeof malformed) == FT_NEQO_DATAGRAM);
    assert(ft_neqo_auth_rejected(client) == 0);
    uint8_t output[65527];
    int32_t ret = ft_neqo_next(client, output, sizeof output, &written, &timeout_ms);
    assert(ret == FT_NEQO_IDLE || ret == FT_NEQO_DATAGRAM || ret == FT_NEQO_TIMER);

    assert(ft_neqo_stop(client) == 0);
    assert(ft_neqo_stop(client) == 0);
    assert(ft_neqo_next(client, output, sizeof output, &written, &timeout_ms) == FT_NEQO_STOPPED);
    assert(ft_neqo_feed(client, "127.0.0.1:443", malformed, sizeof malformed) == FT_NEQO_STOPPED);
    free(buf);
    ft_neqo_free(client);
    puts("Neqo Rust/C ABI: QUIC Initial, UDP feed, callback and stop verified");
    return 0;
}
