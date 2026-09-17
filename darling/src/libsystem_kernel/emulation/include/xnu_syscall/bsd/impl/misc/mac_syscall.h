#ifndef LINUX_MAC_SYSCALL_H
#define LINUX_MAC_SYSCALL_H

long sys_mac_syscall(const char* policy, int call, void* arg);

#endif // LINUX_MAC_SYSCALL_H
