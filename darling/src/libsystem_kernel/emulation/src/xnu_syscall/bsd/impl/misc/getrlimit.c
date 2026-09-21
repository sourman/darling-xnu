#include <darling/emulation/xnu_syscall/bsd/impl/misc/getrlimit.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

long sys_getrlimit(unsigned int which, struct xnu_rlimit* rlp)
{
	int ret;
	int converted = 0;

	which = rlimit_bsd_to_linux(which);
	if (which == -1)
		return -EINVAL;

	ret = LINUX_SYSCALL(__NR_prlimit64, 0, which, 0, rlp);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	if (rlp->rlim_cur == LINUX_RLIM_INFINITY) {
		rlp->rlim_cur = BSD_RLIM_INFINITY;
		converted = 1;
	}
	if (rlp->rlim_max == LINUX_RLIM_INFINITY) {
		rlp->rlim_max = BSD_RLIM_INFINITY;
		converted = 1;
	}
	if (converted)
		__simple_printf("getrlimit_rlim_inf_v1 which=%u cur=%llx max=%llx\n",
			which, rlp->rlim_cur, rlp->rlim_max);

	if (which == LINUX_RLIMIT_NOFILE)
	{
		if (rlp->rlim_cur != BSD_RLIM_INFINITY && rlp->rlim_cur > 0)
			rlp->rlim_cur--;
		if (rlp->rlim_max != BSD_RLIM_INFINITY && rlp->rlim_max > 0)
			rlp->rlim_max--;
	}

	return 0;
}

unsigned int rlimit_bsd_to_linux(unsigned int which)
{
	which &= ~BSD_RLIMIT_POSIX;

	switch (which)
	{
		case BSD_RLIMIT_CPU:
			return LINUX_RLIMIT_CPU;
		case BSD_RLIMIT_FSIZE:
			return LINUX_RLIMIT_FSIZE;
		case BSD_RLIMIT_DATA:
			return LINUX_RLIMIT_DATA;
		case BSD_RLIMIT_STACK:
			return LINUX_RLIMIT_STACK;
		case BSD_RLIMIT_CORE:
			return LINUX_RLIMIT_CORE;
		case BSD_RLIMIT_AS:
			return LINUX_RLIMIT_AS;
		case BSD_RLIMIT_MEMLOCK:
			return LINUX_RLIMIT_MEMLOCK;
		case BSD_RLIMIT_NPROC:
			return LINUX_RLIMIT_NPROC;
		case BSD_RLIMIT_NOFILE:
			return LINUX_RLIMIT_NOFILE;
		default:
			return -1;
	}
}
