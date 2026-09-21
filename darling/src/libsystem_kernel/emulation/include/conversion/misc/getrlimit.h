#ifndef DARLING_CONVERSION_MISC_GETRLIMIT
#define DARLING_CONVERSION_MISC_GETRLIMIT

struct xnu_rlimit
{
	unsigned long long rlim_cur;
	unsigned long long rlim_max;
	long _dummy[20];
};

enum {
	LINUX_RLIMIT_CPU = 0,
	LINUX_RLIMIT_FSIZE,
	LINUX_RLIMIT_DATA,
	LINUX_RLIMIT_STACK,
	LINUX_RLIMIT_CORE,
	LINUX_RLIMIT_RSS,
	LINUX_RLIMIT_NPROC,
	LINUX_RLIMIT_NOFILE,
	LINUX_RLIMIT_MEMLOCK,
	LINUX_RLIMIT_AS,
	LINUX_RLIMIT_LOCKS,
	LINUX_RLIMIT_SIGPENDING,
	LINUX_RLIMIT_MSGQUEUE,
	LINUX_RLIMIT_NICE,
	LINUX_RLIMIT_RTPRIO,
	LINUX_RLIMIT_RTTIME,
};

enum {
	BSD_RLIMIT_CPU = 0,
	BSD_RLIMIT_FSIZE,
	BSD_RLIMIT_DATA,
	BSD_RLIMIT_STACK,
	BSD_RLIMIT_CORE,
	BSD_RLIMIT_AS,
	BSD_RLIMIT_MEMLOCK,
	BSD_RLIMIT_NPROC,
	BSD_RLIMIT_NOFILE,
	BSD_RLIMIT_POSIX = 0x1000
};

unsigned int rlimit_bsd_to_linux(unsigned int which);

/* Linux prlimit64 uses ~0ULL; Darwin RLIM_INFINITY is 2^63-1. Chromium
 * getrlimit(RLIMIT_DATA) ImmediateCrash()s if rlim_cur has the sign bit. */
#define LINUX_RLIM_INFINITY (~0ULL)
#define BSD_RLIM_INFINITY   (0x7fffffffffffffffULL)

static inline void rlim_linux_to_bsd(unsigned long long *v)
{
	if (*v == LINUX_RLIM_INFINITY)
		*v = BSD_RLIM_INFINITY;
}

static inline void rlim_bsd_to_linux_val(unsigned long long *v)
{
	if (*v == BSD_RLIM_INFINITY)
		*v = LINUX_RLIM_INFINITY;
}

#endif // DARLING_CONVERSION_MISC_GETRLIMIT
