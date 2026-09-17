#include <darling/emulation/xnu_syscall/bsd/impl/misc/mac_syscall.h>

#include <sys/errno.h>

#include <darling/emulation/common/simple.h>

#define MAC_MAX_POLICY_NAME 32

extern int strcmp(const char* s1, const char* s2);

long sys_mac_syscall(const char* policy, int call, void* arg)
{
	char name[MAC_MAX_POLICY_NAME];
	unsigned int i;
	static int logged = 0;

	if (policy == NULL)
		return -EFAULT;

	for (i = 0; i < MAC_MAX_POLICY_NAME; i++) {
		name[i] = policy[i];
		if (name[i] == '\0')
			break;
	}
	if (i == MAC_MAX_POLICY_NAME)
		return -ENAMETOOLONG;

	if (!logged) {
		logged = 1;
		__simple_printf("sys_mac_syscall policy=%s call=%d\n", name, call);
	}

	if (strcmp(name, "Sandbox") == 0 ||
	    strcmp(name, "Quarantine") == 0 ||
	    strcmp(name, "AMFI") == 0 ||
	    strcmp(name, "TMSafetyNet") == 0) {
		return 0;
	}

	return -ENOPOLICY;
}
