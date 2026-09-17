#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent.h>

#include <stddef.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

int __attribute__((weak)) __attribute__((visibility("default"))) kevent_impl(int kq, ...) { return -ENOSYS; }

long sys_kevent(int	kq, const struct kevent	*changelist, int nchanges,
			struct	kevent *eventlist, int nevents,
			const struct timespec *timeout)
{
	int ret = kevent_impl(kq, changelist, nchanges, eventlist, nevents, timeout);
	if (ret < 0) {
		int err = errno;
		if (err > 0)
			ret = -err;
		else if (ret == -1)
			ret = -EINTR;
	}
	return ret;
}
