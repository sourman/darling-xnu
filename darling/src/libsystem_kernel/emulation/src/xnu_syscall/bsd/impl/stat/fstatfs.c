#include <darling/emulation/xnu_syscall/bsd/impl/stat/fstatfs.h>

#include <stddef.h>
#include <sys/fcntl.h>

#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/fcntl/open.h>

extern char *strtok_r(char *str, const char *delim, char **saveptr);
extern __SIZE_TYPE__ strlcpy(char* dst, const char* src, __SIZE_TYPE__ size);
extern __SIZE_TYPE__ strlen(const char* str);
extern int strncmp(const char* s1, const char* s2, __SIZE_TYPE__ len);
extern int sprintf(char *str, const char *format, ...);

static const char k_fstatfs_best_effort_v1[] = "fstatfs_best_effort_v1";

#define LINUX_OVERLAYFS_SUPER_MAGIC 0x794c7630
#define LINUX_TMPFS_MAGIC 0x01021994
#define LINUX_NFS_SUPER_MAGIC 0x6969

static void fill_fstypename_from_magic(struct bsd_statfs64* buf, long magic)
{
	if (buf->f_fstypename[0] != 0)
		return;
	if (magic == (long)LINUX_NFS_SUPER_MAGIC)
		strlcpy(buf->f_fstypename, "nfs", sizeof(buf->f_fstypename));
	else
		strlcpy(buf->f_fstypename, "hfs", sizeof(buf->f_fstypename));
}

long sys_fstatfs(int fd, struct bsd_statfs* buf)
{
#ifdef __x86_64__
	return sys_fstatfs64(fd, (struct bsd_statfs64*) buf);
#else
#	warning Not implemented
	return 0;
#endif
}

long sys_fstatfs64(int fd, struct bsd_statfs64* buf)
{
	int fd_m, ret;
	int tries;
	struct simple_readline_buf rbuf;
	struct linux_statfs64 lbuf;
	char line[512];
	char path[1024];
	char linkbuf[64];
	int max_len = 0;

	(void)k_fstatfs_best_effort_v1;

	for (tries = 0; tries < 8; tries++) {
#ifdef __NR_fstatfs64
		ret = LINUX_SYSCALL3(__NR_fstatfs64, fd, sizeof(lbuf), &lbuf);
#else
		ret = LINUX_SYSCALL2(__NR_fstatfs, fd, &lbuf);
#endif
		if (ret != -LINUX_ESTALE)
			break;
		__simple_printf("fstatfs_best_effort_v1 linux ESTALE try=%d fd=%d\n", tries, fd);
	}

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	statfs_linux_to_bsd64(&lbuf, buf);
	buf->f_iosize = 512;
	buf->f_mntonname[0] = 0;
	buf->f_fstypename[0] = 0;
	buf->f_mntfromname[0] = 0;

	/*
	 * Mount names are cosmetic. Previously fdpath() / sys_open("/proc/self/mounts")
	 * failures were returned to the caller. Apple sqlite unixOpen maps any
	 * fstatfs() error to SQLITE_IOERR_ACCESS (3338), leaving 0-byte History DBs.
	 * Read the Linux fd path and /proc/self/mounts directly; ignore lookup errors.
	 */
	sprintf(linkbuf, "/proc/self/fd/%d", fd);
#if defined(__NR_readlink)
	ret = LINUX_SYSCALL(__NR_readlink, linkbuf, path, sizeof(path) - 1);
#else
	ret = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, linkbuf, path, sizeof(path) - 1);
#endif
	if (ret < 0)
		goto out_default;
	path[ret] = '\0';

	fd_m = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, "/proc/self/mounts", LINUX_O_RDONLY, 0);
	if (fd_m < 0)
		goto out_default;

	__simple_readline_init(&rbuf);

	while (__simple_readline(fd_m, &rbuf, line, sizeof(line)))
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
		if (strncmp(p, path, len) != 0 || len < max_len)
			continue;

		max_len = len;
		strlcpy(buf->f_mntonname, p, sizeof(buf->f_mntonname));

		p = strtok_r(NULL, " ", &saveptr);
		if (p == NULL)
			continue;

		strlcpy(buf->f_fstypename, p, sizeof(buf->f_fstypename));
		strlcpy(buf->f_mntfromname, mntfrom, sizeof(buf->f_mntfromname));
	}

	LINUX_SYSCALL(__NR_close, fd_m);

out_default:
	fill_fstypename_from_magic(buf, lbuf.f_type);
	return 0;
}
