#ifndef FT_NSS_BRIDGE_H
#define FT_NSS_BRIDGE_H
#include <stdint.h>
#include <prio.h>
int ft_init(void);
PRFileDesc *ft_new(uintptr_t handle, const char *name, const char *local, const char *remote, const char *protocol, int *error);
int ft_handshake(PRFileDesc *fd, const char *protocol, int *error);
int ft_read(PRFileDesc *fd, void *buffer, int length, int *error);
int ft_write(PRFileDesc *fd, const void *buffer, int length, int *error);
void ft_close(PRFileDesc *fd);
const char *ft_version(void);
#endif
