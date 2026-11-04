#include <darling/emulation/xnu_syscall/bsd/impl/misc/fileport_makeport.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

#include <mach/mach_init.h>
#include <mach/mach_port.h>

#include <darling/emulation/conversion/duct_errno.h>
#include <darlingserver/rpc.h>

/*
 * Minimal fileports. The host has no LKM fileport, so keep a process-local
 * table from the allocated Mach port name to a dup of the fd. fileport_makefd
 * dups that fd again. Same-process Mojo traffic round-trips; a port name that
 * was moved into another task is not in that task's table.
 */
#define FILEPORT_SLOTS 256

struct fileport_slot {
	uint32_t port;
	int fd;
};

static struct fileport_slot fileport_slots[FILEPORT_SLOTS];
static int fileport_lock;

static void fileport_lock_acquire(void)
{
	while (__sync_lock_test_and_set(&fileport_lock, 1))
		;
}

static void fileport_lock_release(void)
{
	__sync_lock_release(&fileport_lock);
}

long sys_fileport_makeport(int fd, int* port)
{
	int dupfd;
	uint32_t name = 0;
	int code;
	int slot = -1;

	if (!port)
		return -EFAULT;

	dupfd = dup(fd);
	if (dupfd < 0)
		return -errno;
	fcntl(dupfd, F_SETFD, FD_CLOEXEC);

	code = dserver_rpc_mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &name);
	if (code != 0) {
		close(dupfd);
		return code < 0 ? code : -EIO;
	}

	code = dserver_rpc_mach_port_insert_right(mach_task_self(), name, name, MACH_MSG_TYPE_MAKE_SEND);
	if (code != 0) {
		close(dupfd);
		return code < 0 ? code : -EIO;
	}

	fileport_lock_acquire();
	for (int i = 0; i < FILEPORT_SLOTS; i++) {
		if (fileport_slots[i].port == 0) {
			fileport_slots[i].port = name;
			fileport_slots[i].fd = dupfd;
			slot = i;
			break;
		}
	}
	fileport_lock_release();

	if (slot < 0) {
		close(dupfd);
		return -ENOMEM;
	}

	*port = (int)name;
	return 0;
}

int fileport_lookup_dup(uint32_t port)
{
	int fd = -1;
	int dupfd;

	fileport_lock_acquire();
	for (int i = 0; i < FILEPORT_SLOTS; i++) {
		if (fileport_slots[i].port == port) {
			fd = fileport_slots[i].fd;
			break;
		}
	}
	fileport_lock_release();

	if (fd < 0)
		return -EINVAL;

	dupfd = dup(fd);
	if (dupfd < 0)
		return -errno;
	fcntl(dupfd, F_SETFD, FD_CLOEXEC);
	return dupfd;
}
