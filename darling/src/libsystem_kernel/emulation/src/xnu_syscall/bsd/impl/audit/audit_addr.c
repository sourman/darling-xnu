#include <darling/emulation/xnu_syscall/bsd/impl/audit/audit_addr.h>

#include <os/lock.h>

#include <darling/emulation/xnu_syscall/bsd/impl/unistd/geteuid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/getentropy.h>

#define min(a, b) ((a < b) ? a : b)

extern void* memcpy(void* dest, const void* src, __SIZE_TYPE__ n);

// global variable because we need to inherit this across child processes
static auditinfo_addr_t info = {
	.ai_auid = AU_DEFAUDITID,
	.ai_mask = {0},
	.ai_termid = { .at_type = AU_IPv4 },
	.ai_asid = AU_DEFAUDITSID,
	.ai_flags = 0,
};
// should be a rw lock but *shrug*. Not the libplatform symbol: defining that
// here exported an empty lock and broke every other image's unlock.
static os_unfair_lock info_lock = OS_UNFAIR_LOCK_INIT;
static void kernel_unfair_lock(os_unfair_lock_t lock) { (void)lock; }
static void kernel_unfair_unlock(os_unfair_lock_t lock) { (void)lock; }

long sys_getaudit_addr(struct auditinfo_addr* auditinfo_addr, int length) {
	kernel_unfair_lock(&info_lock);

	memcpy(auditinfo_addr, &info, min(length, sizeof(auditinfo_addr_t)));

	kernel_unfair_unlock(&info_lock);
	return 0;
};

long sys_setaudit_addr(struct auditinfo_addr* auditinfo_addr, int length) {
	kernel_unfair_lock(&info_lock);

	memcpy(&info, auditinfo_addr, min(length, sizeof(auditinfo_addr_t)));

	if (info.ai_asid == AU_ASSIGN_ASID) {
		// generate a new session ID
		sys_getentropy(&info.ai_asid, sizeof(info.ai_asid));
	}

	kernel_unfair_unlock(&info_lock);
	return 0;
};
