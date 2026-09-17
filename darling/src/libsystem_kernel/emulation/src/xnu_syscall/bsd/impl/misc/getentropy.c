#include <darling/emulation/xnu_syscall/bsd/impl/misc/getentropy.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

/*
 * libc syscall(SYS_getentropy) only. Chrome's GigaCage seed uses the
 * libsyscall _getentropy stub (raw getrandom, rax=0). Never /dev/urandom.
 */
long sys_getentropy(void* buf, unsigned long size)
{
	unsigned char *p = (unsigned char *)buf;
	unsigned long left = size;

	if (size > 256)
		return -EINVAL;

	while (left > 0) {
		long ret = LINUX_SYSCALL(__NR_getrandom, p, left, 0);

		if (ret < 0) {
			if (ret == -LINUX_EINTR)
				continue;
			__simple_kprintf("sys_getentropy getrandom err %ld left %lu\n",
					ret, left);
			return errno_linux_to_bsd(ret);
		}
		if (ret == 0) {
			__simple_kprintf("sys_getentropy getrandom 0-byte left %lu\n",
					left);
			return -EIO;
		}
		p += (unsigned long)ret;
		left -= (unsigned long)ret;
	}

	return 0;
}
