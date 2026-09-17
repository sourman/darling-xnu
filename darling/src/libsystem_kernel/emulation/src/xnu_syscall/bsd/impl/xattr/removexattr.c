#include <darling/emulation/xnu_syscall/bsd/impl/xattr/removexattr.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/xattr/name.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#define XATTR_NOFOLLOW	1

long sys_removexattr(const char* path, const char* name, int options)
{
	int ret;
	char linux_name[XATTR_LINUX_NAME_MAX];
	const char* lname;

	lname = xattr_name_to_linux(name, linux_name, sizeof(linux_name));
	if (lname == NULL)
		return -ENAMETOOLONG;

	if (options & XATTR_NOFOLLOW)
		ret = LINUX_SYSCALL(__NR_lremovexattr, path, lname);
	else
		ret = LINUX_SYSCALL(__NR_removexattr, path, lname);

	if (ret < 0)
		return xattr_ret_linux_to_bsd(ret);

	return ret;
}
