/* Start measurements after exec into this small launcher, so Python's peak
 * memory is not an inherited floor in the benchmark child's ru_maxrss. */
#define _GNU_SOURCE
#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    pid_t child;
    struct timespec started, ended;
    if (clock_gettime(CLOCK_MONOTONIC, &started)) return 2;
    if (posix_spawn(&child, argv[1], NULL, NULL, argv + 1, environ)) return 2;
    int status;
    struct rusage usage;
    while (wait4(child, &status, 0, &usage) < 0) {
        if (errno != EINTR) return 2;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &ended)) return 2;
    fprintf(stderr, "\nVETROFF_RESOURCE {\"user\":%.9f,\"system\":%.9f,\"rss_kib\":%ld,\"wall\":%.9f}\n",
            usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6,
            usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6,
            usage.ru_maxrss, ended.tv_sec - started.tv_sec +
            (ended.tv_nsec - started.tv_nsec) / 1e9);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
