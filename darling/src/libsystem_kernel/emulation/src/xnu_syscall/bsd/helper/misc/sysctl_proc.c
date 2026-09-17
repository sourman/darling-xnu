#include <darling/emulation/xnu_syscall/bsd/helper/misc/sysctl_proc.h>

#include <sys/sysctl.h>
#include <sys/errno.h>
#include <stdbool.h>

#include <darling/emulation/xnu_syscall/bsd/impl/dirent/getdirentries.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/read.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getuid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getgid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/dirent/getdirentries.h>
#include <darling/emulation/conversion/fcntl/open.h>

#include <darlingserver/rpc.h>

#ifndef isdigit
#	define isdigit(c) (c >= '0' && c <= '9')
#endif
#ifndef DT_DIR
#	define DT_DIR	4
#endif

static bool fill_proc(const char* name, int what, int flag, struct kinfo_proc* kinfo);

extern __SIZE_TYPE__ strlen(const char* ptr);
extern char* strcpy(char* dst, const char* src);
extern void* memset(void*, int, __SIZE_TYPE__);
extern void* memcpy(void* dest, const void*, __SIZE_TYPE__);
extern char *strncpy(char *dest, const char *src, __SIZE_TYPE__ n);

int _sysctl_proc(int what, int flag, struct kinfo_proc* out, unsigned long* buflen)
{
	int fd, ret = 0;
	char dents[256];
	long basep = 0;
	int nproc = 0;
	unsigned long max_out;

	if (buflen == NULL)
		return -EFAULT;
	if (*buflen > 0 && out == NULL)
		return -EFAULT;

	max_out = *buflen / sizeof(struct kinfo_proc);

	fd = sys_open_nocancel("/proc", BSD_O_RDONLY | BSD_O_DIRECTORY, 0);
	if (fd < 0)
		return fd;

	while ((ret = sys_getdirentries(fd, (char*) dents, sizeof(dents), &basep)) > 0)
	{
		int pos = 0;
		
		while (pos < ret)
		{
			struct bsd_dirent* dent = (struct bsd_dirent*) &dents[pos];
			struct kinfo_proc kinfo;
			// __simple_printf("Looking at %s\n", dent->d_name);

			if (dent->d_type != DT_DIR || !isdigit(dent->d_name[0]))
			{
				pos += dent->d_reclen;
				continue;
			}

			// Avoid loading process info unless really needed
			if (what != KERN_PROC_ALL || *buflen > 0)
			{
				if (fill_proc(dent->d_name, what, flag, &kinfo))
				{
					if (out != NULL && (unsigned long)nproc < max_out)
						memcpy(&out[nproc], &kinfo, sizeof(kinfo));
					nproc++;
				}
			}
			else
				nproc++;

			pos += dent->d_reclen;
		}
	}

	if (*buflen < nproc*sizeof(struct kinfo_proc))
	{
		*buflen = nproc*sizeof(struct kinfo_proc);
		ret = out ? -ENOSPC : 0;
	}
	else
	{
		*buflen = nproc*sizeof(struct kinfo_proc);
		ret = 0;
	}

	close_internal(fd);

	// __simple_printf("sysctl_proc returning %d, len %d\n", ret, *buflen);
	return ret;
}

bool read_string(const char* path, char* dst, int maxlen)
{
	int fd, rd;

	fd = sys_open(path, BSD_O_RDONLY, 0);
	if (fd < 0)
		return false;

	rd = sys_read(fd, dst, maxlen-1);
	if (rd >= 0)
		dst[rd] = '\0';

	close_internal(fd);
	return rd >= 0;
}

const char* next_stat_elem(char** buf)
{
	char* start;

	start = *buf;

	if (!*start)
		return NULL;
	else if (*start == '(')
	{
		char* end;

		start++;
		end = start;

		while (*end != ')' && *end)
			end++;
		*end = '\0';
		*buf = end+2;
	}
	else
	{
		char* end;

		end = start;
		while (*end != ' ' && *end)
			end++;
		*end = '\0';
		*buf = end+1;
	}

	// __simple_printf("Next stat elem: %s\n", start);
	return start;
}

void skip_stat_elems(char** buf, int count)
{
	int i;
	for (i = 0; i < count; i++)
		next_stat_elem(buf);
}

static bool fill_proc(const char* name, int what, int flag, struct kinfo_proc* kinfo)
{
	char path[56];
	char stat[1024];
	char *statptr;
	const char* elem;
	static int uid = -1, gid = -1;

	__simple_sprintf(path, "/proc/%s/stat", name);

	memset(kinfo, 0, sizeof(*kinfo));

	kinfo->kp_proc.p_pid = __simple_atoi(name, NULL);

	bool is_64_bit;
	if (dserver_rpc_task_is_64_bit(kinfo->kp_proc.p_pid, &is_64_bit) < 0) {
		is_64_bit = false;
	}
	if (is_64_bit)
		kinfo->kp_proc.p_flag |= P_LP64;

	if (!read_string(path, stat, sizeof(stat)))
		return false;

	statptr = stat;
	skip_stat_elems(&statptr, 1); // skip pid

#define READELEM() elem = next_stat_elem(&statptr); if (!elem) return false

	// comm
	READELEM();
	strncpy(kinfo->kp_proc.p_comm, elem, sizeof(kinfo->kp_proc.p_comm));

	// process state
	READELEM();
	switch (*elem)
	{
		case 'R':
			kinfo->kp_proc.p_stat = SRUN;
			break;
		case 'S':
		case 'D':
			kinfo->kp_proc.p_stat = SSLEEP;
			break;
		case 'T':
			kinfo->kp_proc.p_stat = SSTOP;
			break;
		case 'Z':
			kinfo->kp_proc.p_stat = SZOMB;
			break;
		default:
			kinfo->kp_proc.p_stat = SSLEEP;
	}

	// ppid
	READELEM();
	kinfo->kp_eproc.e_ppid = __simple_atoi(elem, NULL);

	// pgid
	READELEM();
	kinfo->kp_eproc.e_pgid = __simple_atoi(elem, NULL);

	// sid
	READELEM();
	if (what == KERN_PROC_SESSION)
	{
		int sid = __simple_atoi(elem, NULL);
		if (sid != flag)
			return false;
	}

	// tty_nr
	READELEM();
	kinfo->kp_eproc.e_tdev = __simple_atoi(elem, NULL);
	if (kinfo->kp_eproc.e_tdev != 0)
		kinfo->kp_proc.p_flag |= P_CONTROLT;

	skip_stat_elems(&statptr, NULL);

	READELEM();
	kinfo->kp_proc.p_priority = __simple_atoi(elem, NULL);

	READELEM();
	kinfo->kp_proc.p_nice = __simple_atoi(elem, NULL);

	// In the container, everything is owned by us
	if (uid == -1 || gid == -1)
	{
		uid = sys_getuid();
		gid = sys_getgid();
	}

	kinfo->kp_eproc.e_pcred.p_ruid = uid;
	kinfo->kp_eproc.e_pcred.p_svuid = uid;
	kinfo->kp_eproc.e_pcred.p_rgid = gid;
	kinfo->kp_eproc.e_pcred.p_svgid = gid;
	kinfo->kp_eproc.e_ucred.cr_uid = uid;

	switch (what)
	{
		case KERN_PROC_ALL:
			break;
		case KERN_PROC_PID:
			if (flag != kinfo->kp_proc.p_pid)
				return false;
			break;
		case KERN_PROC_TTY:
			if (flag != kinfo->kp_eproc.e_tdev)
				return false;
			break;
		case KERN_PROC_UID:
			if (flag != kinfo->kp_eproc.e_ucred.cr_uid)
				return false;
			break;
		case KERN_PROC_PGRP:
			if (flag != kinfo->kp_eproc.e_pgid)
				return false;
			break;
		case KERN_PROC_SESSION:
			// Not present in the struct
			// Apple plans to introduce ki_sid?
			// -> Evaluated above
			break;
		case KERN_PROC_RUID:
			if (flag != kinfo->kp_eproc.e_pcred.p_ruid)
				return false;
			break;
		case KERN_PROC_LCID:
			break;
		default:
			return false;
	}

	return true;
}

int _sysctl_procargs(int pid, char* buf, unsigned long* buflen)
{
	char path[56];
	char cmdline[2048];
	int argc = 0, i, arg0len = 0, argslen = 0;
	int totallen, ret = 0;

	__simple_sprintf(path, "/proc/%d/cmdline", pid);

	if (!read_string(path, cmdline, sizeof(cmdline)))
		return -ENOTDIR;

	if (!cmdline[0])
	{
		int len;

		// Provide comm instead
		__simple_sprintf(path, "/proc/%d/comm", pid);
		
		if (!read_string(path, cmdline, sizeof(cmdline)))
			return -ENOTDIR;

		len = strlen(cmdline);
		cmdline[len-1] = '\0'; // comm ends with \r
	}

	for (i = 0; i < sizeof(cmdline)-1; i++)
	{
		if (!cmdline[i])
		{
			argc++;
			if (argc == 1)
				arg0len = i;
		}
		if (i > 0 && !cmdline[i-1] && !cmdline[i])
		{
			argslen = i;
			break;
		}
	}
	totallen = sizeof(int) + arg0len + 2 + argslen + 1;

	if (*buflen < totallen)
	{
		*buflen = totallen;
		ret = (buf) ? -ENOSPC : 0;
	}
	else
	{
		*buflen = totallen;
		memcpy(buf, &argc, sizeof(argc));
		strcpy(buf+sizeof(argc), cmdline); // copy arg0 as executable_path (TODO: not 100% correct)
		buf[sizeof(argc)+arg0len+1] = 0;
		buf[sizeof(argc)+arg0len+2] = 0;
		memcpy(buf+sizeof(argc)+arg0len+2, cmdline, argslen+1);
	}

	return ret;
}
