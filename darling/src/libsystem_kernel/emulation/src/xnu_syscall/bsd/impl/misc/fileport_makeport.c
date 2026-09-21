#include <darling/emulation/xnu_syscall/bsd/impl/misc/fileport_makeport.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/fcntl.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#include <darlingserver/rpc.h>

/* Overlay confirm: nsenter strings on libsystem_kernel.dylib. */
static const char comet_fileport_v1[] = "comet_fileport_v1";

long sys_fileport_makeport(int fd, int* port)
{
	uint32_t name = 0;
	int err;
	int chk;

	(void)comet_fileport_v1;

	if (!port)
		return -EFAULT;

	chk = LINUX_SYSCALL2(__NR_fcntl, fd, LINUX_F_GETFD);
	if (chk < 0)
		return errno_linux_to_bsd(chk);

	err = dserver_rpc_fileport_makeport(fd, &name);
	if (err < 0) {
		__simple_printf("dserver_rpc_fileport_makeport failed internally: %d\n", err);
		__simple_abort();
	}
	if (err > 0) {
		__simple_kprintf("fileport_makeport_v1 fd=%d err=%d\n", fd, err);
		return errno_linux_to_bsd(-err);
	}

	__simple_kprintf("fileport_makeport_v1 fd=%d port=0x%x\n", fd, (unsigned)name);
	*port = (int)name;
	return 0;
}
