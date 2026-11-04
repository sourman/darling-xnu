#ifndef LINUX_CHANGE_FDGUARD_NP_H
#define LINUX_CHANGE_FDGUARD_NP_H

#include <stdint.h>

long sys_change_fdguard_np(int fd, const uint64_t *guard, unsigned guardflags,
		const uint64_t *nguard, unsigned nguardflags, unsigned *guardflags_out);

#endif
