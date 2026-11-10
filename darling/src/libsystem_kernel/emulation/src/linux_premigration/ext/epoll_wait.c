#include <string.h>

#include <darling/emulation/linux_premigration/ext/sys/epoll.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/duct_errno.h>

extern long cerror(int __err);

VISIBLE
int epoll_wait (int __epfd, struct epoll_event *__events,
		int __maxevents, int __timeout)
{
	int rv;

	/* The raw syscall returns -EINTR in the register. Callers such as
	 * kevent treat that negative value as a count unless errno is set.
	 * Restart, matching the other interrupted waits in this library.
	 */
	do {
	#if defined(__NR_epoll_wait)
		rv = LINUX_SYSCALL(__NR_epoll_wait, __epfd, __events, __maxevents,
			__timeout);
	#else
		rv = LINUX_SYSCALL(__NR_epoll_pwait, __epfd, __events, __maxevents,
			__timeout, NULL);
	#endif
	} while (rv == -LINUX_EINTR);

	if (rv < 0)
	{
		cerror(errno_linux_to_bsd(-rv));
		return -1;
	}

	return rv;
}
