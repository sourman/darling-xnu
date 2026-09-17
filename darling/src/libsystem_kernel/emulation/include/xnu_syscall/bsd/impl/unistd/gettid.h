#ifndef LINUX_GETTID_H
#define LINUX_GETTID_H

long sys_gettid(int* uid, int* gid);

long sys_thread_selfusage(void);

#endif // LINUX_GETTID_H
