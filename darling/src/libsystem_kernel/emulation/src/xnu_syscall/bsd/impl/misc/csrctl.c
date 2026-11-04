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

	/*
	 * The only caller observed is AMFI call 96, dyld's policy query.
	 * The argument is not the {input, output*} pair from older dyld:
	 * writing through the second word faults the process. Success (0)
	 * is the allowed result and is what dyld treats as "no error".
	 */
	__simple_printf("__mac_syscall subsystem %s call %d arg %p\n",
	    name[0] ? name : "(null)", call, arg);
	return 0;
}
