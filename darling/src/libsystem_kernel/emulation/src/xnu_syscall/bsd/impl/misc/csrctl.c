#include <darling/emulation/xnu_syscall/bsd/impl/misc/csrctl.h>

#define PRIVATE
#include <sys/csr.h>

#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/duct_errno.h>

long sys_csrctl(uint32_t op, void* useraddr, size_t usersize) {
	switch (op) {
		case CSR_SYSCALL_CHECK: {
			// allow everything
			return 0;
		} break;
		case CSR_SYSCALL_GET_ACTIVE_CONFIG: {
			// set everything to "allowed"
			*(uint32_t*)useraddr = CSR_VALID_FLAGS;
			return 0;
		} break;
		default:
			return ENOSYS;
	}
}

long sys_mac_syscall(const char* policy, int call, void* arg)
{
	char name[64];
	unsigned i;

	name[0] = 0;
	if (policy) {
		for (i = 0; i < sizeof(name) - 1; i++) {
			char c = policy[i];
			name[i] = c;
			if (c == 0)
				break;
		}
		name[sizeof(name) - 1] = 0;
	}

	__simple_printf("__mac_syscall subsystem %s call %d arg %p\n",
	    name[0] ? name : "(null)", call, arg);

	/*
	 * AMFI call 96 (0x60), and the older 0x5a, is dyld's policy query.
	 * arg points at { uint64_t input; uint64_t *output }. An unsigned
	 * process is allowed the dyld path and interposing bits.
	 */
	if ((call == 96 || call == 0x5a) && arg &&
	    name[0] == 'A' && name[1] == 'M' && name[2] == 'F' &&
	    name[3] == 'I' && name[4] == 0) {
		uint64_t *words = (uint64_t *)arg;
		uint64_t *out = (uint64_t *)words[1];
		if (out)
			*out = 0x3ff;
	}
	return 0;
}
