#include <darling/emulation/xnu_syscall/bsd/impl/process/posix_spawn.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/spawn.h>
#include <sys/fcntl.h>
#include <sys/errno.h>
#include <_libkernel_init.h>

#include <darling/emulation/xnu_syscall/bsd/impl/process/execve.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/dirent/getdirentries.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/read.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/write.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/exit.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/pipe.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/dup2.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/dup.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getuid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getgid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/setuid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/setgid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/setpgid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/signal/sigprocmask.h>
#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/xnu_syscall/bsd/impl/process/fork.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/chdir.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/fchdir.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/fcntl.h>
#include <darling/emulation/xnu_syscall/bsd/impl/dirent/getdirentries.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>
#include <darling/emulation/common/guarded/table.h>

#include <darlingserver/rpc.h>
#include <mach/mach.h>
#include <mach/task_special_ports.h>

#ifndef _POSIX_SPAWN_DISABLE_ASLR
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif

#define LINUX_ADDR_NO_RANDOMIZE 0x40000
#define DARLING_MAX_FILEPORT_DUP2 64

extern _libkernel_functions_t _libkernel_functions;

/* Overlay confirm: nsenter strings on libsystem_kernel.dylib. */
static const char comet_posix_spawn_fileport_dup2_v1[] = "posix_spawn_fileport_dup2_v1";

static int
spawn_fileport_makefd(unsigned int port)
{
	int newfd = -1;
	int err;

	if (port == 0 || port == 0xffffffffu)
		return -EBADF;
	err = dserver_rpc_fileport_makefd(port, &newfd);
	if (err < 0)
		return err;
	if (err > 0)
		return -err;
	return newfd;
}

long sys_posix_spawn(int* pid, const char* path, const struct _posix_spawn_args_desc* desc,
		char** argvp, char** envp)
{
	int ret, my_pid;
	int pipe[2] = { -1, -1 };
	unsigned int spawn_flags = (desc && desc->attrp) ? desc->attrp->psa_flags : 0;
	int fp_tmpfd[DARLING_MAX_FILEPORT_DUP2];
	int fp_dest[DARLING_MAX_FILEPORT_DUP2];
	int fp_n = 0;
	int fp_i;

	(void)comet_posix_spawn_fileport_dup2_v1;
	for (fp_i = 0; fp_i < DARLING_MAX_FILEPORT_DUP2; fp_i++)
		fp_tmpfd[fp_i] = -1;

	__simple_kprintf("posix_spawn_v1 path=%s flags=0x%x fact=%d\n",
		path ? path : "(null)", spawn_flags,
		(desc && desc->factp) ? (int)desc->factp->psfa_act_count : 0);

	/*
	 * Darling posix_spawn is fork+exec. The child gets a fresh Mach ipc
	 * space (ipc_task_init), so FILEPORT_DUP2 cannot look up the parent's
	 * fileport name after fork. Resolve to a Linux fd in the parent first;
	 * Linux fork copies that fd, then the child dup2's it to dest.
	 * CLOEXEC_DEFAULT would otherwise drop every fd that is not a dest.
	 */
	if (desc && desc->factp) {
		int i;
		for (i = 0; i < desc->factp->psfa_act_count; i++) {
			const struct xnu__psfa_action* act = &desc->factp->psfa_act_acts[i];
			int dest = act->psfaa_dup2args.psfad_newfiledes;

			__simple_kprintf("posix_spawn_v1 fact i=%d type=%d fd=%d dest=%d port=0x%x\n",
				i, (int)act->psfaa_type, act->psfaa_filedes, dest,
				(unsigned)act->psfaa_fileport);
			if (act->psfaa_type != XNU_PSFA_FILEPORT_DUP2)
				continue;
			if (fp_n >= DARLING_MAX_FILEPORT_DUP2) {
				__simple_kprintf("posix_spawn_fileport_dup2_v1 overflow n=%d\n", fp_n);
				return -ENOMEM;
			}
			ret = spawn_fileport_makefd((unsigned)act->psfaa_fileport);
			__simple_kprintf("posix_spawn_fileport_dup2_v1 pre port=0x%x dest=%d tmp=%d\n",
				(unsigned)act->psfaa_fileport, dest, ret);
			if (ret < 0)
				return ret;
			fp_tmpfd[fp_n] = ret;
			fp_dest[fp_n] = dest;
			fp_n++;
		}
	}

	if (desc && desc->attrp && desc->attrp->psa_flags & POSIX_SPAWN_SETEXEC)
		goto no_fork;

	ret = LINUX_SYSCALL(__NR_pipe2, pipe, LINUX_O_CLOEXEC);
	if (ret < 0)
		goto out;

	// we don't want to call user atfork callbacks, but we *do* want to call most
	// libsystem atfork callbacks to set up the environment for some of the calls we need
	// to make for the setup

	_libkernel_functions->posix_spawn_prepare();

	if ((my_pid = sys_fork()) == 0)
	{
		// child
		// close the reading side
		close_internal(pipe[0]);

		_libkernel_functions->posix_spawn_child();

no_fork:
		if (desc && desc->attrp)
		{
			if (desc->attrp->psa_flags & POSIX_SPAWN_RESETIDS)
			{
				sys_setgid(sys_getgid());
				sys_setuid(sys_getuid());
			}
			if (desc->attrp->psa_flags & POSIX_SPAWN_SETPGROUP)
			{
				ret = sys_setpgid(0, desc->attrp->psa_pgroup);
				if (ret != 0)
					goto fail;
			}
			if (desc->attrp->psa_flags & POSIX_SPAWN_SETSIGMASK)
			{
				ret = sys_sigprocmask(3 /* SIG_SETMASK */, &desc->attrp->psa_sigmask, NULL);
				if (ret != 0)
					goto fail;
			}
			if (desc->attrp->psa_flags & _POSIX_SPAWN_DISABLE_ASLR)
			{
				unsigned int pers = LINUX_SYSCALL(__NR_personality, 0xffffffff);
				if (!(pers & LINUX_ADDR_NO_RANDOMIZE))
				{
					pers |= LINUX_ADDR_NO_RANDOMIZE;
					LINUX_SYSCALL(__NR_personality, pers);
				}
			}
			if (desc->attrp->psa_flags & POSIX_SPAWN_START_SUSPENDED)
			{
				int status = dserver_rpc_stop_after_exec();
				if (status < 0) {
					__simple_printf("Failed to tell darlingserver to stop us after exec: %d", status);
					__simple_abort();
				}
			}

			if (desc->attrp->psa_flags & POSIX_SPAWN_CLOEXEC_DEFAULT) {
				// Linux /proc/self/fd, not the vchrooted Darwin path
				// (guest sys_open("/proc/self/fd") is ENOENT on this overlay).
				int dir = LINUX_SYSCALL(__NR_open, "/proc/self/fd",
					LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_CLOEXEC, 0);
				char buf[4096];
				int len = 0;
				int rpc_fd = __dserver_per_thread_socket();
				int life_fd = __dserver_get_process_lifetime_pipe();

				__simple_kprintf("posix_spawn_v1 cloexec_default linux_open dir=%d rpc=%d life=%d pipe=%d,%d\n",
					dir, rpc_fd, life_fd, pipe[0], pipe[1]);

				if (dir < 0) {
					ret = dir;
					goto fail;
				}

				while ((len = LINUX_SYSCALL(__NR_getdents64, dir, buf, sizeof(buf))) > 0) {
					struct linux_dirent64* dirent = (struct linux_dirent64*)&buf[0];
					for (int i = 0; i < len; i += dirent->d_reclen, dirent = (struct linux_dirent64*)&buf[i]) {
						int fd = -1;

						//__simple_kprintf("dentry name: %s\n", dirent->d_name);
						if (dirent->d_name[0] == '.') {
							continue;
						}

						fd = __simple_atoi(dirent->d_name, NULL);

						// FIXME: pretty sure this should not be hardcoded
						if (fd == 1023) {
							// special commpage fd
							continue;
						}
						if (fd == rpc_fd || fd == life_fd || fd == pipe[0] || fd == pipe[1] || fd == dir) {
							continue;
						}
						/* Darling RPC / lifetime / thread sockets: CLOEXEC would
						 * drop them across exec of mldr and SIGTRAP the child. */
						if (guard_table_check(fd, guard_flag_prevent_close)) {
							continue;
						}

						if (desc && desc->factp) {
							// if this FD is one that we're creating, don't set O_CLOEXEC on it
							for (size_t j = 0; j < desc->factp->psfa_act_count; j++) {
								const struct xnu__psfa_action* act = &desc->factp->psfa_act_acts[j];
								int maybe_fd = act->psfaa_filedes;

								switch (act->psfaa_type) {
									case XNU_PSFA_DUP2:
									case XNU_PSFA_FILEPORT_DUP2:
										maybe_fd = act->psfaa_dup2args.psfad_newfiledes;
										// fall through

									case XNU_PSFA_OPEN:
									case XNU_PSFA_INHERIT:
										if (fd == maybe_fd) {
											maybe_fd = -1;
										}
										break;

									default:
										break;
								}

								// maybe_fd was set to -1, indicating the descriptors matched
								if (maybe_fd == -1) {
									fd = -1;
									break;
								}
							}
						}

						// fd was set to -1, indicating we should skip it
						if (fd == -1) {
							continue;
						}

						//__simple_kprintf("setting cloexec on %d\n", fd);

						ret = sys_fcntl(fd, F_GETFD, 0);
						if (ret < 0) {
							close_internal(dir);
							goto fail;
						}

						ret = sys_fcntl(fd, F_SETFD, ret | FD_CLOEXEC);
						if (ret < 0) {
							close_internal(dir);
							goto fail;
						}
					}
				}

				close_internal(dir);

				if (len < 0) {
					ret = len;
					goto fail;
				}
			}

			// TODO: other attributes
		}
		if (desc && desc->factp)
		{
			int i;

			//__simple_kprintf("act count: %d\n", desc->factp->psfa_act_count);

			//sys_kill(sys_getpid(), SIGSTOP, 0);

			for (i = 0; i < desc->factp->psfa_act_count; i++)
			{
				const struct xnu__psfa_action* act;

				act = &desc->factp->psfa_act_acts[i];

				//__simple_kprintf("act count (on iter %d): %d\n", i, desc->factp->psfa_act_count);

				if (act->psfaa_filedes == pipe[1] || (act->psfaa_type == XNU_PSFA_DUP2 && act->psfaa_dup2args.psfad_newfiledes == pipe[1]))
				{
					ret = sys_dup(pipe[1]);
					if (ret < 0)
						goto fail;

					close_internal(pipe[1]);
					pipe[1] = ret;
				}

				switch (act->psfaa_type)
				{
					case XNU_PSFA_CLOSE:
						//__simple_kprintf("closing %d\n", act->psfaa_filedes);
						ret = close_internal(act->psfaa_filedes);
						if (ret != 0)
							goto fail;
						break;

					case XNU_PSFA_DUP2:
						//__simple_kprintf("duping %d to %d\n", act->psfaa_filedes, act->psfaa_dup2args.psfad_newfiledes);
						ret = sys_dup2(act->psfaa_filedes, act->psfaa_dup2args.psfad_newfiledes);
						if (ret < 0)
							goto fail;
						break;

					case XNU_PSFA_FILEPORT_DUP2:
					{
						int dest = act->psfaa_dup2args.psfad_newfiledes;
						int tmp = -1;
						int k = fp_n;

						for (k = 0; k < fp_n; k++) {
							if (fp_dest[k] == dest && fp_tmpfd[k] >= 0) {
								tmp = fp_tmpfd[k];
								break;
							}
						}
						if (tmp < 0)
							tmp = spawn_fileport_makefd((unsigned)act->psfaa_fileport);
						__simple_kprintf("posix_spawn_fileport_dup2_v1 child port=0x%x tmp=%d dest=%d\n",
							(unsigned)act->psfaa_fileport, tmp, dest);
						if (tmp < 0) {
							ret = tmp;
							goto fail;
						}
						ret = sys_dup2(tmp, dest);
						if (ret < 0)
							goto fail;
						if (tmp != dest)
							close_internal(tmp);
						if (k < fp_n)
							fp_tmpfd[k] = -1;
						break;
					}

					case XNU_PSFA_OPEN:
					{
						//__simple_kprintf("opening %s to %d\n", act->psfaa_openargs.psfao_path, act->psfaa_filedes);
						ret = sys_open(act->psfaa_openargs.psfao_path,
								act->psfaa_openargs.psfao_oflag, act->psfaa_openargs.psfao_mode);
						if (ret < 0)
							goto fail;

						if (ret != act->psfaa_filedes)
						{
							int fd = ret;
							ret = sys_dup2(ret, act->psfaa_filedes);

							if (ret < 0)
							{
								close_internal(fd);
								goto fail;
							}
						}
						break;
					}

					case XNU_PSFA_CHDIR: {
						//__simple_kprintf("chdiring to %s\n", act->psfaa_chdirargs.psfac_path);
						ret = sys_chdir(act->psfaa_chdirargs.psfac_path);
						if (ret < 0) {
							goto fail;
						}
					} break;

					case XNU_PSFA_FCHDIR: {
						//__simple_kprintf("fchdiring to %d\n", act->psfaa_filedes);
						ret = sys_fchdir(act->psfaa_filedes);
						if (ret < 0) {
							goto fail;
						}
					} break;

					// unset CLOEXEC on this fd
					case XNU_PSFA_INHERIT: {
						//__simple_kprintf("inheriting %d\n", act->psfaa_filedes);
						ret = sys_fcntl(act->psfaa_filedes, F_GETFD, 0);
						if (ret < 0) {
							goto fail;
						}
						ret = sys_fcntl(act->psfaa_filedes, F_SETFD, ret & ~FD_CLOEXEC);
						if (ret < 0) {
							goto fail;
						}
					} break;

					default:
						//__simple_kprintf("unknown PSFA type %d\n", act->psfaa_type);
						;
				}
			}

			//__simple_kprintf("act count (on finish): %d\n", desc->factp->psfa_act_count);
		}

		if (desc && desc->pactp && desc->port_actions_size >= 8) {
			struct darling_ps_port_action {
				int port_type;
				unsigned int mask;
				unsigned int new_port;
				int behavior;
				int flavor;
				int which;
			};
			struct darling_ps_port_actions {
				int pspa_alloc;
				int pspa_count;
				struct darling_ps_port_action pspa_actions[];
			};
			const struct darling_ps_port_actions* ports = desc->pactp;
			int n = ports->pspa_count;
			int i;

			__simple_kprintf("posix_spawn_v1 port_actions count=%d size=%lu\n",
				n, (unsigned long)desc->port_actions_size);
			if (n < 0 || n > 32)
				n = 0;
			for (i = 0; i < n; i++) {
				const struct darling_ps_port_action* act = &ports->pspa_actions[i];
				__simple_kprintf("posix_spawn_v1 port_action i=%d type=%d which=%d port=0x%x\n",
					i, act->port_type, act->which, act->new_port);
				/* PSPA_SPECIAL: set task special port (bootstrap is which=4). */
				if (act->port_type == 0 && act->new_port) {
					kern_return_t kr = task_set_special_port(mach_task_self(),
						act->which, act->new_port);
					__simple_kprintf("posix_spawn_v1 task_set_special_port which=%d port=0x%x kr=%d\n",
						act->which, act->new_port, kr);
					if (kr != 0) {
						ret = kr;
						goto fail;
					}
				}
			}
		}

		char binprefs[64];
		if (desc && desc->attrp && desc->attrp->psa_binprefs[0])
		{
			char** new_envp;
			int i, env_len = 0;

			while (envp[env_len])
				env_len++;
			env_len++; // terminating NULL

			// +1 for our new entry
			new_envp = (char**) __builtin_alloca((env_len + 1) * sizeof(char*));

			__simple_sprintf(binprefs, "__mldr_bprefs=%x,%x,%x,%x",
				desc->attrp->psa_binprefs[0],
				desc->attrp->psa_binprefs[1],
				desc->attrp->psa_binprefs[2],
				desc->attrp->psa_binprefs[3]);

			new_envp[0] = binprefs;
			for (i = 0; i < env_len; i++)
				new_envp[i+1] = envp[i];
			envp = new_envp;
		}

		{
			mach_port_t bsp = 0;
			kern_return_t bkr = task_get_special_port(mach_task_self(),
				TASK_BOOTSTRAP_PORT, &bsp);
			__simple_kprintf("posix_spawn_v1 child bootstrap kr=%d port=0x%x exec=%s\n",
				bkr, bsp, path ? path : "(null)");
		}
		__simple_kprintf("posix_spawn_v1 child execve %s\n", path ? path : "(null)");
		ret = sys_execve((char*) path, argvp, envp);
fail:
		__simple_kprintf("posix_spawn_v1 child fail ret=%d path=%s\n", ret, path ? path : "(null)");
		if (desc && desc->attrp && desc->attrp->psa_flags & POSIX_SPAWN_SETEXEC)
		{
			// no_fork case
			ret = errno_linux_to_bsd(ret);
			goto out;
		}
		else
		{
			sys_write(pipe[1], &ret, sizeof(ret));
			sys_exit(127);
			__builtin_unreachable();
		}
	}
	else
	{
		// parent
		int err;

		// close the writing side
		close_internal(pipe[1]);

		_libkernel_functions->posix_spawn_parent();

		if (my_pid < 0)
		{
			ret = my_pid;
			goto out;
		}

		if (pid != NULL)
			*pid = my_pid;

		if (sys_read(pipe[0], &ret, sizeof(ret)) != sizeof(ret))
			ret = 0;
		close_internal(pipe[0]);
	}

out:
	for (fp_i = 0; fp_i < fp_n; fp_i++) {
		if (fp_tmpfd[fp_i] >= 0)
			close_internal(fp_tmpfd[fp_i]);
	}
	return ret;
}
