#include <darling/emulation/xnu_syscall/bsd/impl/misc/fileport_makefd.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>

#include <darlingserver/rpc.h>

long sys_fileport_makefd(int port)
{
	int newfd = -1;
	int err;

	err = dserver_rpc_fileport_makefd((uint32_t)port, &newfd);
	if (err < 0) {
		__simple_printf("dserver_rpc_fileport_makefd failed internally: %d\n", err);
		__simple_abort();
	}
	if (err > 0)
		return errno_linux_to_bsd(-err);

	return newfd;
}
