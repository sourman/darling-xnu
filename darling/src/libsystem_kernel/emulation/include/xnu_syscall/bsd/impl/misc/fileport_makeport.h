#ifndef LINUX_FILEPORT_MAKEPORT_H
#define LINUX_FILEPORT_MAKEPORT_H

#include <stdint.h>

struct fileport_makeport_args
{
	int fd;
	int port_out;
};

long sys_fileport_makeport(int fd, int* port);

/* Dup the fd stored for a fileport in this process, or -errno. */
int fileport_lookup_dup(uint32_t port);

#endif // LINUX_FILEPORT_MAKEPORT_H
