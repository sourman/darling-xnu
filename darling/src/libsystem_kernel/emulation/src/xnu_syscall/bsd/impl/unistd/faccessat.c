#include <darling/emulation/xnu_syscall/bsd/impl/unistd/faccessat.h>

#include <sys/errno.h>

#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>

#undef strcpy
extern char* strcpy(char* dst, const char* src);

#ifndef __NR_faccessat2
#define __NR_faccessat2 439
#endif

static const char k_faccessat_overlay_tmp_v1[] = "faccessat_overlay_tmp_v1";

static int linux_faccessat(int dfd, const char* path, int amode, int linux_flags)
{
	int ret;

	ret = LINUX_SYSCALL(__NR_faccessat2, dfd, path, amode, linux_flags);
	if (ret == -LINUX_ENOSYS)
		ret = LINUX_SYSCALL(__NR_faccessat, dfd, path, amode);
	return ret;
}

long sys_faccessat(int fd, const char* filename, int amode, int flag)
{
	int ret;
	struct vchroot_expand_args vc;
	int linux_flags;
	int tries;

	(void)k_faccessat_overlay_tmp_v1;

	vc.flags = (flag & BSD_AT_SYMLINK_NOFOLLOW) ? 0 : VCHROOT_FOLLOW;
	vc.dfd = atfd(fd);

	linux_flags = atflags_bsd_to_linux(flag);
	if (linux_flags == LINUX_AT_INVALID)
		return -EINVAL;

	for (tries = 0; tries < 8; tries++) {
		strcpy(vc.path, filename);
		ret = vchroot_expand(&vc);
		if (ret != -LINUX_ESTALE)
			break;
		__simple_printf("faccessat_overlay_tmp_v1 vchroot ESTALE try=%d path=%s\n", tries, filename);
	}
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	/*
	 * vchroot_expand returns an absolute Linux path. Passing the original
	 * (possibly overlay-stale) dfd makes Linux faccessat return ESTALE even
	 * when the expanded path is valid. Always use AT_FDCWD after expand.
	 */
	for (tries = 0; tries < 8; tries++) {
		ret = linux_faccessat(LINUX_AT_FDCWD, vc.path, amode, linux_flags);
		if (ret != -LINUX_ESTALE)
			break;
		__simple_printf("faccessat_overlay_tmp_v1 linux ESTALE try=%d path=%s\n", tries, vc.path);
	}

	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
