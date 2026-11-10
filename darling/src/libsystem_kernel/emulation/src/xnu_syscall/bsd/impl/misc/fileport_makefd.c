#include <darling/emulation/xnu_syscall/bsd/impl/misc/fileport_makefd.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/fileport_makeport.h>

#include <stdint.h>

long sys_fileport_makefd(int port)
{
	/*
	 * The receive right stays in this process with the dup'd fd. Callers that
	 * were handed the send right (including this process) look the name up
	 * here. Names moved into another task are not in that task's table.
	 */
	return fileport_lookup_dup((uint32_t)port);
}
