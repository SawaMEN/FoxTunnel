/* Minimal Linux-only UDP driver for the experimental Neqo ABI.
 * No HTTP requests are generated; success means certificate auth was
 * REJECTED, never that the peer was authenticated. */
#define _POSIX_C_SOURCE 200809L
#include "foxtunnel_neqo.h"
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int64_t clock_millis(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <remote-ipv4> <port> <sni>\n", argv[0]);
        return 64;
    }
    char *end = NULL;
    unsigned long port = strtoul(argv[2], &end, 10);
    if (argv[2][0] == '\0' || *end || port == 0 || port > 65535) return 64;
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    if (inet_pton(AF_INET, argv[1], &peer.sin_addr) != 1) return 64;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 1;
    if (connect(fd, (struct sockaddr *)&peer, sizeof peer) != 0) {
        perror("connect UDP");
        close(fd);
        return 1;
    }
    struct sockaddr_in local;
    socklen_t len = sizeof local;
    if (getsockname(fd, (struct sockaddr *)&local, &len) != 0) {
        perror("getsockname");
        close(fd);
        return 1;
    }
    char local_ip[INET_ADDRSTRLEN], local_addr[64], remote_addr[64];
    if (!inet_ntop(AF_INET, &local.sin_addr, local_ip, sizeof local_ip)) {
        close(fd);
        return 1;
    }
    snprintf(local_addr, sizeof local_addr, "%s:%u", local_ip, ntohs(local.sin_port));
    snprintf(remote_addr, sizeof remote_addr, "%s:%lu", argv[1], port);
    struct NeqoProbe *client = ft_neqo_new(argv[3], local_addr, remote_addr);
    if (!client) {
        fprintf(stderr, "Neqo refused peer parameters or NSS initialization\n");
        close(fd);
        return 1;
    }
    uint8_t payload[65527];
    int result = 1;
    const int64_t started = clock_millis();
    for (int loops = 0; loops < 5000; ++loops) {
        if (ft_neqo_auth_rejected(client) == 1) {
            puts("PASS: Neqo reached TLS certificate verification and rejected the untrusted peer");
            result = 0;
            break;
        }
        int64_t remain = started + 8000 - clock_millis();
        if (remain <= 0) {
            fprintf(stderr, "timeout: peer did not reach certificate verification\n");
            break;
        }
        size_t n = 0;
        uint32_t ms = 0;
        int32_t next = ft_neqo_next(client, payload, sizeof payload, &n, &ms);
        if (next == FT_NEQO_DATAGRAM) {
            if (send(fd, payload, n, 0) != (ssize_t)n) {
                perror("send UDP");
                break;
            }
            continue;
        }
        if (next < 0) {
            fprintf(stderr, "Neqo output failed: %d\n", next);
            break;
        }
        int wait_ms = (int)remain;
        if (next == FT_NEQO_TIMER && ms < (uint32_t)wait_ms) wait_ms = (int)ms;
        struct pollfd watch = {.fd = fd, .events = POLLIN};
        int ready = poll(&watch, 1, wait_ms);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        if (ready == 0) continue;  /* Timer expired; advance Neqo. */
        if (!(watch.revents & POLLIN)) {
            fprintf(stderr, "UDP error/hangup during handshake\n");
            break;
        }
        ssize_t received = recv(fd, payload, sizeof payload, 0);
        if (received <= 0) {
            perror("recv UDP");
            break;
        }
        if (ft_neqo_feed(client, remote_addr, payload, (size_t)received) != FT_NEQO_DATAGRAM) {
            fprintf(stderr, "Neqo refused received datagram\n");
            break;
        }
    }
    (void)ft_neqo_stop(client);
    ft_neqo_free(client);
    close(fd);
    return result;
}
