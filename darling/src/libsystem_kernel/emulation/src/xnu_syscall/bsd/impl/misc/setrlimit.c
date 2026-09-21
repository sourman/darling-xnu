#include <darling/emulation/xnu_syscall/bsd/impl/misc/setrlimit.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

long sys_setrlimit(unsigned int which, const struct xnu_rlimit* rlp)
{
	int ret;
	struct xnu_rlimit lim = { rlp->rlim_cur, rlp->rlim_max };

	which = rlimit_bsd_to_linux(which);
	if (which == -1)
		return -EINVAL;

	rlim_bsd_to_linux_val(&lim.rlim_cur);
	rlim_bsd_to_linux_val(&lim.rlim_max);

	if (which == LINUX_RLIMIT_NOFILE)
	{
		if (lim.rlim_cur != LINUX_RLIM_INFINITY)
			lim.rlim_cur++;
		if (lim.rlim_max != LINUX_RLIM_INFINITY)
			lim.rlim_max++;
	}

	ret = LINUX_SYSCALL(__NR_prlimit64, 0, which, &lim, 0);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
