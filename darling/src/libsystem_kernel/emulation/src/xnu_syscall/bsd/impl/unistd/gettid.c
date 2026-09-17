#include <darling/emulation/xnu_syscall/bsd/impl/unistd/gettid.h>

#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getuid.h>

#include <darlingserver/rpc.h>

long sys_gettid(int* uid, int* gid)
{
	__getuidgid(uid, gid);
	return 0;
}

/*
 * XNU thread_selfusage (BSD 482) returns thread_get_runtime_self() in
 * mach_absolute_time units. Darling's timebase is 1:1 ns, so return
 * Linux CLOCK_THREAD_CPUTIME_ID as nanoseconds.
 */
long sys_thread_selfusage(void)
{
	struct {
		long tv_sec;
		long tv_nsec;
	} ts;
	long ret;

	ret = LINUX_SYSCALL(__NR_clock_gettime, 3 /* LINUX CLOCK_THREAD_CPUTIME_ID */, &ts);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	return ts.tv_sec * 1000000000ull + ts.tv_nsec;
}
