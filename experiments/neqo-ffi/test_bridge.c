#include "foxtunnel_neqo.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    assert(ft_neqo_abi_version() == 1);
    assert(ft_neqo_new("bad..example", "127.0.0.1:12345", "127.0.0.1:443") == NULL);
    struct NeqoProbe *client =
        ft_neqo_new("example.org", "127.0.0.1:12345", "127.0.0.1:443");
    assert(client != NULL);
    size_t length = 0;
    assert(ft_neqo_initial(client, NULL, 0, &length) == -2);
    assert(length >= 1200 && length <= 65535);
    uint8_t *buf = malloc(length);
    assert(buf != NULL);
    size_t written = 0;
    assert(ft_neqo_initial(client, buf, length, &written) == 1);
    assert(written == length && (buf[0] & 0xc0) == 0xc0);
    assert(buf[1] == 0 && buf[2] == 0 && buf[3] == 0 && buf[4] == 1);
    free(buf);
    ft_neqo_free(client);
    puts("Neqo Rust -> C ABI: QUIC v1 Initial generated");
    return 0;
}
