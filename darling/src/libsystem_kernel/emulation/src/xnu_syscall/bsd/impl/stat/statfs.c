#include <darling/emulation/xnu_syscall/bsd/impl/stat/statfs.h>

#include <stddef.h>
#include <sys/fcntl.h>

#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/fcntl/open.h>

#undef strlcpy
#undef strcpy

extern char *strtok_r(char *str, const char *delim, char **saveptr);
extern __SIZE_TYPE__ strlcpy(char* dst, const char* src, __SIZE_TYPE__ size);
extern __SIZE_TYPE__ strlen(const char* str);
extern int strncmp(const char* s1, const char* s2, __SIZE_TYPE__ len);
extern char* strcpy(char* dst, const char* src);

static const char k_statfs_vchroot_follow_v1[] = "statfs_vchroot_follow_v1";

#define LINUX_OVERLAYFS_SUPER_MAGIC 0x794c7630
#define LINUX_TMPFS_MAGIC 0x01021994
#define LINUX_NFS_SUPER_MAGIC 0x6969

static void fill_fstypename_from_magic(struct bsd_statfs64* buf, long magic)
{
	if (buf->f_fstypename[0] != 0)
		return;
	if (magic == (long)LINUX_NFS_SUPER_MAGIC)
		strlcpy(buf->f_fstypename, "nfs", sizeof(buf->f_fstypename));
	else if (magic == (long)LINUX_OVERLAYFS_SUPER_MAGIC || magic == (long)LINUX_TMPFS_MAGIC)
		strlcpy(buf->f_fstypename, "hfs", sizeof(buf->f_fstypename));
	else
		strlcpy(buf->f_fstypename, "hfs", sizeof(buf->f_fstypename));
}

long sys_statfs(const char* path, struct bsd_statfs* buf)
{
#ifdef __x86_64__
	return sys_statfs64(path, (struct bsd_statfs64*) buf);
#else
#	warning Not implemented
	return 0;
#endif
}

long sys_statfs64(const char* path, struct bsd_statfs64* buf)
{
	int fd, ret;
	int tries;
	struct simple_readline_buf rbuf;
	struct linux_statfs64 lbuf;
	char line[512];
	int max_len = 0;

	(void)k_statfs_vchroot_follow_v1;

	struct vchroot_expand_args vc;
	/* Follow /tmp -> private/tmp inside the prefix. Without FOLLOW, Linux
	 * statfs() may resolve the symlink against the host root and return ENOENT.
	 */
	vc.flags = VCHROOT_FOLLOW;
	vc.dfd = get_perthread_wd();

	for (tries = 0; tries < 8; tries++) {
		strcpy(vc.path, path);
		ret = vchroot_expand(&vc);
		if (ret != -LINUX_ESTALE)
			break;
		__simple_printf("statfs_vchroot_follow_v1 vchroot ESTALE try=%d path=%s\n", tries, path);
	}
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	for (tries = 0; tries < 8; tries++) {
#ifdef __NR_statfs64
		ret = LINUX_SYSCALL2(__NR_statfs64, vc.path, &lbuf);
#else
		ret = LINUX_SYSCALL2(__NR_statfs, vc.path, &lbuf);
#endif
		if (ret != -LINUX_ESTALE)
			break;
		__simple_printf("statfs_vchroot_follow_v1 linux ESTALE try=%d path=%s\n", tries, vc.path);
	}

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	statfs_linux_to_bsd64(&lbuf, buf);
	buf->f_iosize = 512;
	buf->f_mntonname[0] = 0;
	buf->f_fstypename[0] = 0;
	buf->f_mntfromname[0] = 0;

	/* Mount-table lookup is best-effort. Chromium sqlite treats a failed
	 * statfs/fstatfs as SQLITE_IOERR_ACCESS (3338). */
	fd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, "/proc/self/mounts", LINUX_O_RDONLY, 0);
	if (fd < 0)
		goto out_default;

	__simple_readline_init(&rbuf);

	while (__simple_readline(fd, &rbuf, line, sizeof(line)))
	{
		char* p;
		char* saveptr;
		char* mntfrom;
		int len;

		p = strtok_r(line, " ", &saveptr);
		if (p == NULL)
			continue;

		mntfrom = p;
		p = strtok_r(NULL, " ", &saveptr);
		if (p == NULL)
			continue;

		len = strlen(p);
		if (strncmp(p, vc.path, len) != 0 || len < max_len)
			continue;

		max_len = len;
		strlcpy(buf->f_mntonname, p, sizeof(buf->f_mntonname));

		p = strtok_r(NULL, " ", &saveptr);
		if (p == NULL)
			continue;

		strlcpy(buf->f_fstypename, p, sizeof(buf->f_fstypename));
		strlcpy(buf->f_mntfromname, mntfrom, sizeof(buf->f_mntfromname));
	}

	LINUX_SYSCALL(__NR_close, fd);

out_default:
	fill_fstypename_from_magic(buf, lbuf.f_type);
	return 0;
}
