#include <darling/emulation/xnu_syscall/bsd/impl/xattr/fsetxattr.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/xattr/name.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

long sys_fsetxattr(int fd, const char* name, const void* value,
		unsigned long size, unsigned int pos, int options)
{
	int ret;
	char linux_name[XATTR_LINUX_NAME_MAX];
	const char* lname;

	if (pos != 0)
		return -ERANGE;

	lname = xattr_name_to_linux(name, linux_name, sizeof(linux_name));
	if (lname == NULL)
		return -ENAMETOOLONG;

	ret = LINUX_SYSCALL(__NR_fsetxattr, fd, lname, value, size);

	if (ret < 0)
		return xattr_ret_linux_to_bsd(ret);

	return ret;
}
