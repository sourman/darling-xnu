#ifndef LINUX_CSRCTL_H
#define LINUX_CSRCTL_H

#include <stdint.h>
#include <stddef.h>

long sys_csrctl(uint32_t op, void* useraddr, size_t usersize);

/* __mac_syscall(policy, call, arg). call is the policy operation. */
long sys_mac_syscall(const char* policy, int call, void* arg);

#endif // LINUX_CSRCTL_H
