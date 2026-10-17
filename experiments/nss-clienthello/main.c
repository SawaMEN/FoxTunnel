/*
 * Standalone NSS ClientHello experiment. Connects ONLY to IPv4 loopback, emits
 * a TLS handshake and expects the separate capture tool to close immediately.
 * This is not a proxy and does not bypass certificate authentication.
 * A real transport requires secure NSS trust-store management, verified full
 * handshakes, HTTP/2 and lifecycle integration.
 */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include <nss.h>
#include <prerror.h>
#include <prio.h>
#include <prnetdb.h>
#include <ssl.h>
#include <sslproto.h>

static int fail(const char *step) {
    fprintf(stderr, "%s failed (NSPR error %d)\n", step, PR_GetError());
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: nss-clienthello <loopback-port> <tls-sni-hostname>\n");
        return 2;
    }
    char *end = NULL;
    errno = 0;
    long port = strtol(argv[1], &end, 10);
    if (errno || *end != '\0' || port < 1 || port > 65535 || argv[2][0] == '\0') {
        fprintf(stderr, "invalid port or SNI hostname\n");
        return 2;
    }
    if (NSS_NoDB_Init(NULL) != SECSuccess) return fail("NSS_NoDB_Init");
    int result = 1;
    PRFileDesc *fd = PR_NewTCPSocket();
    if (!fd) { fail("PR_NewTCPSocket"); goto cleanup; }

    PRNetAddr address;
    if (PR_InitializeNetAddr(PR_IpAddrLoopback, (PRUint16)port, &address) != PR_SUCCESS ||
        PR_Connect(fd, &address, PR_SecondsToInterval(5)) != PR_SUCCESS) {
        fail("loopback connect"); goto close_socket;
    }

    /* The imported descriptor is owned by the TLS layer upon success. */
    PRFileDesc *secure = SSL_ImportFD(NULL, fd);
    if (!secure) { fail("SSL_ImportFD"); goto close_socket; }
    fd = secure;
    if (SSL_OptionSet(fd, SSL_SECURITY, PR_TRUE) != SECSuccess ||
        SSL_OptionSet(fd, SSL_HANDSHAKE_AS_CLIENT, PR_TRUE) != SECSuccess ||
        SSL_SetURL(fd, argv[2]) != SECSuccess) {
        fail("TLS client settings"); goto close_socket;
    }
    SSLVersionRange range;
    if (SSL_VersionRangeGetSupported(ssl_variant_stream, &range) != SECSuccess) {
        fail("SSL_VersionRangeGetSupported"); goto close_socket;
    }
    if (range.max < SSL_LIBRARY_VERSION_TLS_1_3) {
        fprintf(stderr, "NSS TLS 1.3 support is required\n"); goto close_socket;
    }
    range.min = SSL_LIBRARY_VERSION_TLS_1_3;
    range.max = SSL_LIBRARY_VERSION_TLS_1_3;
    if (SSL_VersionRangeSet(fd, &range) != SECSuccess) {
        fail("SSL_VersionRangeSet"); goto close_socket;
    }
    const unsigned char alpn[] = { 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    if (SSL_SetNextProtoNego(fd, alpn, sizeof(alpn)) != SECSuccess) {
        fail("SSL_SetNextProtoNego"); goto close_socket;
    }
    /* Imported connected descriptors need an explicit client handshake reset. */
    if (SSL_ResetHandshake(fd, PR_FALSE) != SECSuccess) {
        fail("SSL_ResetHandshake"); goto close_socket;
    }
    /* The capture probe closes before a server certificate or handshake reply
     * exists. A handshake error is expected; successful ClientHello parsing is
     * checked by the CI capture process, not by this program. */
    if (SSL_ForceHandshakeWithTimeout(fd, PR_SecondsToInterval(5)) != SECSuccess) {
        PRErrorCode err = PR_GetError();
        const char *name = PR_ErrorToName(err);
        fprintf(stderr, "expected incomplete handshake: %s (%d)\n", name ? name : "unknown", err);
    }
    fprintf(stderr, "NSS %s: ClientHello attempted on loopback; full TLS handshake is intentionally unavailable\n", NSS_GetVersion());
    result = 0;
close_socket:
    PR_Close(fd);
cleanup:
    if (NSS_Shutdown() != SECSuccess) return fail("NSS_Shutdown");
    return result;
}
