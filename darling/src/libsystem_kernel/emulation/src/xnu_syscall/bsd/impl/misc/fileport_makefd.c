#include <darling/emulation/xnu_syscall/bsd/impl/misc/fileport_makefd.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/fcntl.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#include <darlingserver/rpc.h>

long sys_fileport_makefd(int port)
{
	int newfd = -1;
	int err;
	int getfd;

	err = dserver_rpc_fileport_makefd((uint32_t)port, &newfd);
	if (err < 0) {
		__simple_printf("dserver_rpc_fileport_makefd failed internally: %d\n", err);
		__simple_abort();
	}
	if (err > 0) {
		__simple_kprintf("fileport_makefd_v3 port=0x%x err=%d\n", (unsigned)port, err);
		return errno_linux_to_bsd(-err);
	}

	getfd = LINUX_SYSCALL2(__NR_fcntl, newfd, LINUX_F_GETFD);
	__simple_kprintf("fileport_makefd_v3 port=0x%x fd=%d getfd=%d\n",
		(unsigned)port, newfd, getfd);
	return newfd;
}
