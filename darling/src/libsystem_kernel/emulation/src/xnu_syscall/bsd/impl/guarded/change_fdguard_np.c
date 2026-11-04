#include <darling/emulation/xnu_syscall/bsd/impl/guarded/change_fdguard_np.h>

/*
 * Chromium guards a UDP socket with change_fdguard_np and treats ENOSYS as fatal.
 * The guard is not enforced here; accepting the call lets the socket stay open.
 */
long sys_change_fdguard_np(int fd, const uint64_t *guard, unsigned guardflags,
		const uint64_t *nguard, unsigned nguardflags, unsigned *guardflags_out)
{
	(void)fd;
	(void)guard;
	(void)guardflags;
	(void)nguard;
	(void)nguardflags;
	if (guardflags_out)
		*guardflags_out = 0;
	return 0;
}
