#include <darling/emulation/xnu_syscall/bsd/impl/stat/mkdirat.h>

#include <sys/errno.h>

#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/other/mach/lkm.h>

#undef strcpy
extern char* strcpy(char* dst, const char* src);

static const char k_mkdirat_overlay_tmp_v1[] = "mkdirat_overlay_tmp_v1";

long sys_mkdirat(int fd, const char* path, unsigned int mode)
{
	int ret;
	int tries;
	struct vchroot_expand_args vc;

	(void)k_mkdirat_overlay_tmp_v1;

	if (!path)
		return -EFAULT;

	vc.flags = 0;
	vc.dfd = atfd(fd);

	for (tries = 0; tries < 8; tries++) {
		strcpy(vc.path, path);
		ret = vchroot_expand(&vc);
		if (ret != -LINUX_ESTALE)
			break;
		__simple_printf("mkdirat_overlay_tmp_v1 vchroot ESTALE try=%d path=%s\n", tries, path);
	}
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	for (tries = 0; tries < 8; tries++) {
		ret = LINUX_SYSCALL(__NR_mkdirat, LINUX_AT_FDCWD, vc.path, mode);
		if (ret != -LINUX_ESTALE)
			break;
		__simple_printf("mkdirat_overlay_tmp_v1 linux ESTALE try=%d path=%s\n", tries, vc.path);
	}

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	return 0;
}
