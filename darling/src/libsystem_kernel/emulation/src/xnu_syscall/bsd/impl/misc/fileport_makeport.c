#include <darling/emulation/xnu_syscall/bsd/impl/misc/fileport_makeport.h>

#include <darling/emulation/conversion/duct_errno.h>

long sys_fileport_makeport(int fd, int* port)
{
	/*
	 * The old LKM trap ud2s. There is no darlingserver fileport yet.
	 * Return an error so the caller can fail the syscall instead of
	 * taking down the process inside lkm_call.
	 */
	(void)fd;
	(void)port;
	return -ENOSYS;
}
