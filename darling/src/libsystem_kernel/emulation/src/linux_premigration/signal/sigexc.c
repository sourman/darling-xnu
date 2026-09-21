#include <darling/emulation/linux_premigration/signal/sigexc.h>

#include <stddef.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <_libkernel_init.h>

#include <darling/emulation/xnu_syscall/bsd/impl/signal/sigaction.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/exit.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/signal/sigaltstack.h>
#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/xnu_syscall/bsd/impl/mman/mman.h>
#include <darling/emulation/conversion/mman/duct_mman.h>
#include <darling/emulation/xnu_syscall/bsd/impl/signal/kill.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/fcntl/open.h>

#include <darlingserver/rpc.h>

// Support for Darwin debugging.
// Unlike other Unix-like systems, macOS doesn't use wait() to handle events in the debugged process.
// wait() only receives termination events.

static volatile bool am_i_ptraced = false;
static void handle_rt_signal(int signum);
static void sigexc_fake_suspend(struct linux_ucontext* ctxt);
extern void sig_restorer(void);
extern int getpid(void);

extern _libkernel_functions_t _libkernel_functions;

__attribute__((used)) const char sigexc_kill_self_v1[] = "sigexc_kill_self_v1";
__attribute__((used)) const char sigexc_crash_pid_v1[] = "sigexc_crash_pid_v1";
__attribute__((used)) const char sigexc_setnext_dump_v1[] = "sigexc_setnext_dump_v1";
__attribute__((used)) const char sigexc_pa_pagein_v1[] = "sigexc_pa_pagein_v1";
__attribute__((used)) const char sigexc_meta18_vis_v1[] = "sigexc_meta18_vis_v1";

static int linux_self_pid(void)
{
	return (int)LINUX_SYSCALL0(__NR_getpid);
}

void darling_sigexc_uninstall(void);
void sigrt_handler(int signum, struct linux_siginfo* info, struct linux_ucontext* ctxt);

#define SIGEXC_STACK_SIZE (48ULL * 1024ULL)

#ifndef SIGALTSTACK_GUARD
	#define SIGALTSTACK_GUARD 1
#endif

#if SIGALTSTACK_GUARD
// align it on a page boundary so mprotect works properly
static char sigexc_altstack[SIGEXC_STACK_SIZE + 4096ULL] __attribute__((aligned(4096)));
#else
static char sigexc_altstack[SIGEXC_STACK_SIZE];
#endif
size_t default_sigaltstack_size = SIGEXC_STACK_SIZE;

#if defined(__x86_64__)
static void mcontext_to_thread_state(const struct linux_gregset* regs, x86_thread_state64_t* s);
static void mcontext_to_float_state(const linux_fpregset_t fx, x86_float_state64_t* s);
static void thread_state_to_mcontext(const x86_thread_state64_t* s, struct linux_gregset* regs);
static void float_state_to_mcontext(const x86_float_state64_t* s, linux_fpregset_t fx);
#elif defined(__i386__)
static void mcontext_to_thread_state(const struct linux_gregset* regs, x86_thread_state32_t* s);
static void mcontext_to_float_state(const linux_fpregset_t fx, x86_float_state32_t* s);
static void thread_state_to_mcontext(const x86_thread_state32_t* s, struct linux_gregset* regs);
static void float_state_to_mcontext(const x86_float_state32_t* s, linux_fpregset_t fx);
#endif

static void state_from_kernel(struct linux_ucontext* ctxt, const void* tstate, const void* fstate);
static void state_to_kernel(struct linux_ucontext* ctxt, void* tstate, void* fstate);

/* Nested kern_printf on the RT stack overflows __simple_vsnprintf (~944B frame). */
#ifdef DEBUG_SIGEXC
#define kern_printf(...) __simple_kprintf(__VA_ARGS__)
#else
#define kern_printf(...)
#endif

void sigexc_setup1(void)
{
	handle_rt_signal(SIGNAL_SIGEXC_SUSPEND);
	handle_rt_signal(SIGNAL_S2C);
}

void sigexc_setup2(void)
{
	linux_sigset_t set;
	set = (1ull << (SIGNAL_SIGEXC_SUSPEND-1));
	set |= (1ull << (SIGNAL_S2C-1));

	LINUX_SYSCALL(__NR_rt_sigprocmask, 1 /* LINUX_SIG_UNBLOCK */,
		&set, NULL, sizeof(linux_sigset_t));
}

static void dump_gregs(const struct linux_gregset* regs)
{
	unsigned long long* p = (unsigned long long*) regs;
	for (int i = 0; i < 23; i++)
	{
		kern_printf("sigexc:   gregs 0x%llx\n", p[i]);
	}
}

static void handle_rt_signal(int signum)
{
	int rv;
	struct linux_sigaction sa;

	sa.sa_sigaction = (linux_sig_handler*)sigrt_handler;
	sa.sa_mask = (1ull << (SIGNAL_SIGEXC_SUSPEND-1)) | (1ull << (signum-1));
	sa.sa_flags = LINUX_SA_RESTORER | LINUX_SA_SIGINFO | LINUX_SA_RESTART | LINUX_SA_ONSTACK;
	sa.sa_restorer = sig_restorer;

	rv = LINUX_SYSCALL(__NR_rt_sigaction, signum,
			&sa, NULL,
			sizeof(sa.sa_mask));

	//char buf[128];
	//__simple_sprintf(xyzbuf, "Setting handler for RT signal %d: %d", signum, rv);
	//external/lkm_call(0x1028, buf);
}

void sigexc_setup(void)
{
	darling_sigexc_self();
	sigexc_setup1();
	sigexc_setup2();

#ifdef VARIANT_DYLD
	bool started_suspended;
	int code = dserver_rpc_started_suspended(&started_suspended);
	if (code < 0) {
		__simple_printf("Failed to get started_suspended status: %d\n", code);
		__simple_abort();
	}
	if (started_suspended) {
		kern_printf("sigexc: start_suspended -> suspending (ret to %p)\n", __builtin_return_address(0));
		task_suspend(mach_task_self());
		kern_printf("sigexc: start_suspended -> wokenup (ret to %p)\n", __builtin_return_address(0));
	} else {
		int32_t tracer;
		code = dserver_rpc_get_tracer(&tracer);
		if (code < 0) {
			__simple_printf("Failed to get tracer status: %d\n", code);
			__simple_abort();
		}
		if (tracer != 0) {
			kern_printf("sigexc: already traced -> SIGTRAP\n");
			sys_kill(linux_self_pid(), SIGTRAP, 0);
		}
	}
#else

#endif
}

void sigrt_handler(int signum, struct linux_siginfo* info, struct linux_ucontext* ctxt)
{
	int status = dserver_rpc_interrupt_enter();

	if (status != 0) {
		__simple_printf("*** dserver_rpc_interrupt_enter failed with code %d ***\n", status);
		__simple_abort();
	}

	if (signum == SIGNAL_SIGEXC_SUSPEND) {
#if defined(__x86_64__)
	x86_thread_state64_t tstate;
	x86_float_state64_t fstate;
#elif defined(__i386__)
	x86_thread_state32_t tstate;
	x86_float_state32_t fstate;
#endif

	kern_printf("sigexc: sigrt_handler SUSPEND\n");

	thread_t thread = mach_thread_self();
	state_to_kernel(ctxt, &tstate, &fstate);

	int ret = dserver_rpc_thread_suspended(&tstate, &fstate);
	if (ret < 0) {
		__simple_printf("dserver_rpc_thread_suspended failed internally: %d", ret);
		__simple_abort();
	}

	state_from_kernel(ctxt, &tstate, &fstate);
	} else if (signum == SIGNAL_S2C) {
		__simple_kprintf("sigexc: sigrt_handler S2C");

		int ret = dserver_rpc_s2c_perform();
		if (ret < 0) {
			__simple_printf("dserver_rpc_s2c_perform failed internally: %d", ret);
			__simple_abort();
		}
	} else {
		__simple_printf("Unknown/unrecognized real-time signal: %d", signum);
	}

	status = dserver_rpc_interrupt_exit();

	if (status != 0) {
		__simple_printf("*** dserver_rpc_interrupt_exit failed with code %d ***\n", status);
		__simple_abort();
	}
}


void darling_sigexc_self(void)
{
	am_i_ptraced = true;

	__simple_kprintf("darling_sigexc_self()\n");
	// Make sigexc_handler the handler for all signals in the process
	for (int i = 1; i <= 31; i++)
	{
		if (i == LINUX_SIGSTOP || i == LINUX_SIGKILL || i == LINUX_SIGCHLD)
			continue;

		struct linux_sigaction sa;
		sa.sa_sigaction = (linux_sig_handler*) sigexc_handler;
		sa.sa_mask = 0x7fffffff; // all other standard Unix signals should be blocked while the handler is run
		sa.sa_mask |= (1ull << (SIGNAL_SIGEXC_SUSPEND-1));
		sa.sa_flags = LINUX_SA_RESTORER | LINUX_SA_SIGINFO | LINUX_SA_RESTART | LINUX_SA_ONSTACK;
		sa.sa_restorer = sig_restorer;

		LINUX_SYSCALL(__NR_rt_sigaction, i,
				&sa, NULL,
				sizeof(sa.sa_mask));
	}

#if SIGALTSTACK_GUARD
	sys_mprotect(sigexc_altstack, 4096, PROT_NONE);
#endif

	struct bsd_stack newstack = {
#if SIGALTSTACK_GUARD
		.ss_sp = sigexc_altstack + 4096,
#else
		.ss_sp = sigexc_altstack,
#endif
		.ss_size = SIGEXC_STACK_SIZE,
		.ss_flags = 0
	};
	sys_sigaltstack(&newstack, NULL);
}


static void state_to_kernel(struct linux_ucontext* ctxt, void* tstate, void* fstate)
{
#if defined(__x86_64__)

	dump_gregs(&ctxt->uc_mcontext.gregs);
	mcontext_to_thread_state(&ctxt->uc_mcontext.gregs, (x86_thread_state64_t*) tstate);
	mcontext_to_float_state(ctxt->uc_mcontext.fpregs, (x86_float_state64_t*) fstate);

#elif defined(__i386__)
	mcontext_to_thread_state(&ctxt->uc_mcontext.gregs, (x86_thread_state32_t*) tstate);
	mcontext_to_float_state(ctxt->uc_mcontext.fpregs, (x86_float_state32_t*) fstate);
#endif

}

static void state_from_kernel(struct linux_ucontext* ctxt, const void* tstate, const void* fstate)
{
#if defined(__x86_64__)

	thread_state_to_mcontext((const x86_thread_state64_t*) tstate, &ctxt->uc_mcontext.gregs);
	float_state_to_mcontext((const x86_float_state64_t*) fstate, ctxt->uc_mcontext.fpregs);

	dump_gregs(&ctxt->uc_mcontext.gregs);

#elif defined(__i386__)
	thread_state_to_mcontext((const x86_thread_state32_t*) tstate, &ctxt->uc_mcontext.gregs);
	float_state_to_mcontext((const x86_float_state32_t*) fstate, ctxt->uc_mcontext.fpregs);
#endif
}

void sigexc_handler(int linux_signum, struct linux_siginfo* info, struct linux_ucontext* ctxt)
{
	int status = dserver_rpc_interrupt_enter();

	if (status != 0) {
		__simple_printf("*** dserver_rpc_interrupt_enter failed with code %d ***\n", status);
		__simple_abort();
	}

	kern_printf("sigexc_handler(%d, %p, %p)\n", linux_signum, info, ctxt);


	if (linux_signum == LINUX_SIGCONT)
		goto out;

	int bsd_signum = signum_linux_to_bsd(linux_signum);
	if (bsd_signum <= 0)
	{
		kern_printf("sigexc: Unmapped signal!\n");
		goto out;
	}

#ifdef __x86_64__
	kern_printf("sigexc: have RIP 0x%llx\n", ctxt->uc_mcontext.gregs.rip);
	/*
	 * Darwin T_PAGE_FAULT calls vm_fault() and retries. Linux PROT_NONE
	 * in a PA cage reservation SIGSEGVs instead. Occupancy is already
	 * bumped for a full system-page of slots; the next SetNext is the
	 * first store on the following 4K. Page-in that 4K (zeros) and
	 * return so the store lands. Do not skip RIP. Alignment faults
	 * (SIGBUS code 1) stay fatal.
	 */
	if ((linux_signum == LINUX_SIGSEGV || linux_signum == LINUX_SIGBUS) &&
	    info != 0 && ctxt != 0) {
		unsigned long fa = (unsigned long)info->si_addr;
		int sc = info->si_code;
		int do_pagein = 0;

		(void)sigexc_pa_pagein_v1;
		if (fa >= (1UL << 40)) {
			if (linux_signum == LINUX_SIGSEGV &&
			    (sc == 1 || sc == 2))
				do_pagein = 1;
			else if (linux_signum == LINUX_SIGBUS && sc != 1)
				do_pagein = 1;
		}
		if (do_pagein) {
			unsigned long page = fa & ~4095UL;
			long nr;
			char pbuf[192];
			int pn, pfd;

			nr = LINUX_SYSCALL3(__NR_mprotect, page, 4096UL,
			    LINUX_PROT_READ | LINUX_PROT_WRITE);
			if (nr != 0) {
				void *mp;
#ifdef __NR_mmap2
				mp = (void *)LINUX_SYSCALL6(__NR_mmap2, page, 4096UL,
				    LINUX_PROT_READ | LINUX_PROT_WRITE,
				    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
				    -1, 0);
#else
				mp = (void *)LINUX_SYSCALL6(__NR_mmap, page, 4096UL,
				    LINUX_PROT_READ | LINUX_PROT_WRITE,
				    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
				    -1, 0);
#endif
				if ((unsigned long)mp == page)
					nr = 0;
			}
			pn = __simple_snprintf(pbuf, sizeof(pbuf),
			    "PAGEIN pid=%d sig=%d code=%d addr=0x%lx page=0x%lx nr=%ld\n",
			    linux_self_pid(), linux_signum, sc, fa, page, nr);
			if (pn > (int)sizeof(pbuf) - 1)
				pn = (int)sizeof(pbuf) - 1;
			__simple_printf("%s", pbuf);
			pfd = LINUX_SYSCALL(__NR_open, "/tmp/sigtrap-rip.log",
			    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
			if (pfd >= 0) {
				LINUX_SYSCALL3(__NR_write, pfd, pbuf, pn);
				LINUX_SYSCALL1(__NR_close, pfd);
			}
			if (nr == 0) {
				darling_pa_twva_consider(page);
				goto out;
			}
		}
	}
	if (linux_signum == LINUX_SIGTRAP || linux_signum == LINUX_SIGILL
			|| linux_signum == LINUX_SIGABRT || linux_signum == LINUX_SIGBUS
			|| linux_signum == LINUX_SIGSEGV) {
		char buf[768];
		unsigned long long rip = ctxt->uc_mcontext.gregs.rip;
		unsigned char bytes[16];
		int nbytes = 0;
		int n;
		int fd;
		for (int i = 0; i < 16; i++) {
			/* Best-effort: RIP is executable, so this should not fault. */
			bytes[i] = ((unsigned char*)(unsigned long)rip)[i];
			nbytes++;
		}
		int self = linux_self_pid();
		unsigned long long rbp = ctxt->uc_mcontext.gregs.rbp;
		unsigned long long retaddr = 0;
		if (rbp != 0)
			retaddr = *(unsigned long long *)(unsigned long)(rbp + 8);
		n = __simple_snprintf(buf, sizeof(buf),
			"CRASH pid=%d sig=%d code=%d addr=%p rip=0x%llx rsp=0x%llx rbp=0x%llx rdi=0x%llx rsi=0x%llx rax=0x%llx rcx=0x%llx rdx=0x%llx rbx=0x%llx r8=0x%llx r12=0x%llx r13=0x%llx r14=0x%llx r15=0x%llx ret=0x%llx bytes=%x %x %x %x %x %x %x %x\n",
			self,
			linux_signum,
			info ? info->si_code : -1,
			info ? info->si_addr : (void*)0,
			rip,
			ctxt->uc_mcontext.gregs.rsp,
			rbp,
			ctxt->uc_mcontext.gregs.rdi,
			ctxt->uc_mcontext.gregs.rsi,
			ctxt->uc_mcontext.gregs.rax,
			ctxt->uc_mcontext.gregs.rcx,
			ctxt->uc_mcontext.gregs.rdx,
			ctxt->uc_mcontext.gregs.rbx,
			ctxt->uc_mcontext.gregs.r8,
			ctxt->uc_mcontext.gregs.r12,
			ctxt->uc_mcontext.gregs.r13,
			ctxt->uc_mcontext.gregs.r14,
			ctxt->uc_mcontext.gregs.r15,
			retaddr,
			(unsigned)bytes[0], (unsigned)bytes[1], (unsigned)bytes[2], (unsigned)bytes[3],
			(unsigned)bytes[4], (unsigned)bytes[5], (unsigned)bytes[6], (unsigned)bytes[7]);
		(void)nbytes;
		(void)sigexc_setnext_dump_v1;
		__simple_printf("%s", buf);
		fd = LINUX_SYSCALL(__NR_open, "/tmp/sigtrap-rip.log",
			LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
		if (fd >= 0) {
			LINUX_SYSCALL3(__NR_write, fd, buf, n);
			LINUX_SYSCALL1(__NR_close, fd);
		}
		{
			/* SetNext vs GetNext: qword at rbx (slot) and rcx (decoded next). */
			unsigned long long slot_addrs[6];
			int si, memfd;
			char dump[512];
			int dn;
			unsigned char *cp = (unsigned char *)0x7fffffe00000ULL;

			slot_addrs[0] = ctxt->uc_mcontext.gregs.rbx;
			slot_addrs[1] = ctxt->uc_mcontext.gregs.rcx;
			slot_addrs[2] = ctxt->uc_mcontext.gregs.rcx + 0x21B0ULL;
			slot_addrs[3] = ctxt->uc_mcontext.gregs.rcx + 0x4360ULL;
			slot_addrs[4] = ctxt->uc_mcontext.gregs.rcx + 0x10ULL;
			slot_addrs[5] = ctxt->uc_mcontext.gregs.rcx + 152ULL;
			dn = __simple_snprintf(dump, sizeof(dump),
			    "COMMPAGE pid=%d ver=%u kshift=%u ushift=%u\n",
			    self, (unsigned)((unsigned short *)(cp + 0x1e))[0],
			    (unsigned)cp[0x4d], (unsigned)cp[0x4e]);
			if (dn > (int)sizeof(dump) - 1)
				dn = (int)sizeof(dump) - 1;
			__simple_printf("%s", dump);
			fd = LINUX_SYSCALL(__NR_open, "/tmp/sigtrap-rip.log",
			    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
			if (fd >= 0) {
				LINUX_SYSCALL3(__NR_write, fd, dump, dn);
				LINUX_SYSCALL1(__NR_close, fd);
			}
			memfd = LINUX_SYSCALL(__NR_open, "/proc/self/mem",
			    LINUX_O_RDONLY, 0);
			for (si = 0; si < 6; si++) {
				unsigned long long a = slot_addrs[si];
				unsigned long long w0 = 0, w1 = 0;
				long got0 = -1, got1 = -1;
				unsigned long long bswap0, decoded;
				unsigned char vec = 0;
				long mc;

				if (a < (1ULL << 40))
					continue;
				mc = LINUX_SYSCALL3(__NR_mincore, a & ~0xfffULL, 4096UL, &vec);
				if (memfd >= 0) {
					got0 = LINUX_SYSCALL(__NR_pread64, memfd, &w0, 8, LL_ARG(a));
					got1 = LINUX_SYSCALL(__NR_pread64, memfd, &w1, 8, LL_ARG(a + 8));
				}
				bswap0 = __builtin_bswap64(w0);
				decoded = (a & 0xFFFFFFFC00000000ULL) | (bswap0 & 0x3FFFFFFFFULL);
				dn = __simple_snprintf(dump, sizeof(dump),
				    "SETNEXT pid=%d slot=0x%llx enc=0x%llx sh=0x%llx got=%ld,%ld mc=%ld vec=%d bswap=0x%llx decoded=0x%llx\n",
				    self, a, w0, w1, got0, got1, mc, (int)vec, bswap0, decoded);
				if (dn > (int)sizeof(dump) - 1)
					dn = (int)sizeof(dump) - 1;
				__simple_printf("%s", dump);
				fd = LINUX_SYSCALL(__NR_open, "/tmp/sigtrap-rip.log",
				    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
				if (fd >= 0) {
					LINUX_SYSCALL3(__NR_write, fd, dump, dn);
					LINUX_SYSCALL1(__NR_close, fd);
				}
			}
			{
				unsigned long long slot, super, meta, span;
				unsigned long long w[6];
				unsigned int packed, alloc, unprov;
				unsigned char vec = 0;
				long got, mc;
				int pi, qi, hit;
				char m18[640];
				int mn;

				(void)sigexc_meta18_vis_v1;
				slot = ctxt->uc_mcontext.gregs.rcx;
				if (slot < (1ULL << 40))
					slot = ctxt->uc_mcontext.gregs.r14;
				if (slot < (1ULL << 40))
					slot = ctxt->uc_mcontext.gregs.rbx;
				if (slot >= (1ULL << 40) && slot < (4ULL << 40)) {
				super = slot & ~0x1FFFFFULL;
				meta = super + 0x1000ULL;
				mn = __simple_snprintf(m18, sizeof(m18),
				    "META18 pid=%d slot=0x%llx super=0x%llx meta=0x%llx r8=0x%llx r12=0x%llx rax=0x%llx\n",
				    self, slot, super, meta,
				    ctxt->uc_mcontext.gregs.r8,
				    ctxt->uc_mcontext.gregs.r12,
				    ctxt->uc_mcontext.gregs.rax);
				if (mn > (int)sizeof(m18) - 1)
					mn = (int)sizeof(m18) - 1;
				__simple_printf("%s", m18);
				fd = LINUX_SYSCALL(__NR_open, "/tmp/sigtrap-rip.log",
				    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
				if (fd >= 0) {
					LINUX_SYSCALL3(__NR_write, fd, m18, mn);
					LINUX_SYSCALL1(__NR_close, fd);
				}
				darling_pa_twva_report((unsigned long)super);
				darling_pa_root98_report((unsigned long)super, slot);
				darling_pa_root98_crash((unsigned long)rbp,
				    (unsigned long)slot);
				if (memfd < 0)
					memfd = LINUX_SYSCALL(__NR_open, "/proc/self/mem",
					    LINUX_O_RDONLY, 0);
				for (pi = 0; pi < 3; pi++) {
					unsigned long long mbase = super + (pi == 0 ? 0x1000ULL :
					    (pi == 1 ? 0x2000ULL : 0x4000ULL));
					unsigned char page[4096];
					long pg = -1;

					mc = LINUX_SYSCALL3(__NR_mincore, mbase & ~0xfffULL, 4096UL, &vec);
					if (memfd >= 0)
						pg = LINUX_SYSCALL(__NR_pread64, memfd, page, 4096, LL_ARG(mbase));
					mn = __simple_snprintf(m18, sizeof(m18),
					    "META18PAGE pid=%d base=0x%llx got=%ld mc=%ld vec=%d\n",
					    self, mbase, pg, mc, (int)vec);
					if (mn > (int)sizeof(m18) - 1)
						mn = (int)sizeof(m18) - 1;
					__simple_printf("%s", m18);
					fd = LINUX_SYSCALL(__NR_open, "/tmp/sigtrap-rip.log",
					    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
					if (fd >= 0) {
						LINUX_SYSCALL3(__NR_write, fd, m18, mn);
						LINUX_SYSCALL1(__NR_close, fd);
					}
					if (pg < 32)
						continue;
					hit = 0;
					for (qi = 0; qi + 32 <= (int)pg; qi += 8) {
						unsigned long long h = 0;
						int b;

						for (b = 0; b < 8; b++)
							h |= ((unsigned long long)page[qi + b]) << (8 * b);
						if (h != slot)
							continue;
						if ((qi & 31) != 0)
							continue;
						span = mbase + (unsigned long long)qi;
						for (b = 0; b < 6; b++) {
							w[b] = 0;
							if (qi + b * 8 + 8 <= (int)pg) {
								int k;
								for (k = 0; k < 8; k++)
									w[b] |= ((unsigned long long)page[qi + b * 8 + k]) << (8 * k);
							}
						}
						packed = (unsigned int)w[3];
						alloc = packed & 0x7fffU;
						unprov = (packed >> 15) & 0x7fffU;
						mn = __simple_snprintf(m18, sizeof(m18),
						    "META18HIT pid=%d span=0x%llx off=%d packed=0x%x alloc=%u unprov=%u sum=%u freeish=%u head=0x%llx next=0x%llx bucket=0x%llx w18=0x%llx\n",
						    self, span, qi, packed, alloc, unprov,
						    alloc + unprov,
						    (unsigned)ctxt->uc_mcontext.gregs.rax - (alloc + unprov),
						    w[0], w[1], w[2], w[3]);
						if (mn > (int)sizeof(m18) - 1)
							mn = (int)sizeof(m18) - 1;
						__simple_printf("%s", m18);
						fd = LINUX_SYSCALL(__NR_open, "/tmp/sigtrap-rip.log",
						    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
						if (fd >= 0) {
							LINUX_SYSCALL3(__NR_write, fd, m18, mn);
							LINUX_SYSCALL1(__NR_close, fd);
						}
						hit = 1;
						break;
					}
					if (!hit) {
						unsigned int p4, p16;
						unsigned long long o4, o16;

						p4 = (unsigned int)((slot - super) >> 12);
						p16 = (unsigned int)((slot - super) >> 14);
						o4 = mbase + (unsigned long long)p4 * 32ULL;
						o16 = mbase + (unsigned long long)p16 * 32ULL;
						got = -1;
						w[0] = w[1] = w[2] = w[3] = 0;
						if (memfd >= 0)
							got = LINUX_SYSCALL(__NR_pread64, memfd, w, 32, LL_ARG(o4));
						packed = (unsigned int)w[3];
						alloc = packed & 0x7fffU;
						unprov = (packed >> 15) & 0x7fffU;
						mn = __simple_snprintf(m18, sizeof(m18),
						    "META18IDX pid=%d idx4=%u a4=0x%llx got=%ld packed=0x%x alloc=%u unprov=%u sum=%u head=0x%llx bucket=0x%llx idx16=%u a16=0x%llx\n",
						    self, p4, o4, got, packed, alloc, unprov,
						    alloc + unprov, w[0], w[2], p16, o16);
						if (mn > (int)sizeof(m18) - 1)
							mn = (int)sizeof(m18) - 1;
						__simple_printf("%s", m18);
						fd = LINUX_SYSCALL(__NR_open, "/tmp/sigtrap-rip.log",
						    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
						if (fd >= 0) {
							LINUX_SYSCALL3(__NR_write, fd, m18, mn);
							LINUX_SYSCALL1(__NR_close, fd);
						}
						w[0] = w[1] = w[2] = w[3] = 0;
						got = -1;
						if (memfd >= 0)
							got = LINUX_SYSCALL(__NR_pread64, memfd, w, 32, LL_ARG(o16));
						packed = (unsigned int)w[3];
						alloc = packed & 0x7fffU;
						unprov = (packed >> 15) & 0x7fffU;
						mn = __simple_snprintf(m18, sizeof(m18),
						    "META18I16 pid=%d a16=0x%llx got=%ld packed=0x%x alloc=%u unprov=%u head=0x%llx bucket=0x%llx\n",
						    self, o16, got, packed, alloc, unprov, w[0], w[2]);
						if (mn > (int)sizeof(m18) - 1)
							mn = (int)sizeof(m18) - 1;
						__simple_printf("%s", m18);
						fd = LINUX_SYSCALL(__NR_open, "/tmp/sigtrap-rip.log",
						    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
						if (fd >= 0) {
							LINUX_SYSCALL3(__NR_write, fd, m18, mn);
							LINUX_SYSCALL1(__NR_close, fd);
						}
						if (mn > (int)sizeof(m18) - 1)
							mn = (int)sizeof(m18) - 1;
						__simple_printf("%s", m18);
						fd = LINUX_SYSCALL(__NR_open, "/tmp/sigtrap-rip.log",
						    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
						if (fd >= 0) {
							LINUX_SYSCALL3(__NR_write, fd, m18, mn);
							LINUX_SYSCALL1(__NR_close, fd);
						}
					}
				}
				}
			}
			if (memfd >= 0)
				LINUX_SYSCALL1(__NR_close, memfd);
		}
		{
			char line[512];
			char chunk[256];
			int linelen = 0;
			int found = 0;
			int mfd = LINUX_SYSCALL(__NR_open, "/proc/self/maps", LINUX_O_RDONLY, 0);
			if (mfd >= 0) {
				long got;
				while (!found && (got = LINUX_SYSCALL3(__NR_read, mfd, chunk, sizeof(chunk))) > 0) {
					for (long i = 0; i < got; i++) {
						if (linelen < (int)sizeof(line) - 1)
							line[linelen++] = chunk[i];
						if (chunk[i] != '\n' && linelen != (int)sizeof(line) - 1)
							continue;
						line[linelen] = 0;
						unsigned long lo = 0, hi = 0;
						const char *p = line;
						while (*p && *p != '-') {
							unsigned v;
							if (*p >= '0' && *p <= '9')
								v = (unsigned)(*p - '0');
							else if (*p >= 'a' && *p <= 'f')
								v = (unsigned)(*p - 'a' + 10);
							else if (*p >= 'A' && *p <= 'F')
								v = (unsigned)(*p - 'A' + 10);
							else
								break;
							lo = (lo << 4) | v;
							p++;
						}
						if (*p == '-')
							p++;
						while (*p && *p != ' ') {
							unsigned v;
							if (*p >= '0' && *p <= '9')
								v = (unsigned)(*p - '0');
							else if (*p >= 'a' && *p <= 'f')
								v = (unsigned)(*p - 'a' + 10);
							else if (*p >= 'A' && *p <= 'F')
								v = (unsigned)(*p - 'A' + 10);
							else
								break;
							hi = (hi << 4) | v;
							p++;
						}
						if (rip >= lo && rip < hi) {
							char out[640];
							int on = __simple_snprintf(out, sizeof(out),
								"CRASHMAP pid=%d rip=0x%llx %s",
								self, rip, line);
							if (on > (int)sizeof(out) - 1)
								on = (int)sizeof(out) - 1;
							__simple_printf("%s", out);
							fd = LINUX_SYSCALL(__NR_open, "/tmp/sigtrap-rip.log",
								LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
							if (fd >= 0) {
								LINUX_SYSCALL3(__NR_write, fd, out, on);
								LINUX_SYSCALL1(__NR_close, fd);
							}
							found = 1;
							break;
						}
						linelen = 0;
					}
				}
				LINUX_SYSCALL1(__NR_close, mfd);
			}
		}
	}
#endif

	thread_t thread = mach_thread_self();

#if defined(__x86_64__)
	x86_thread_state64_t tstate;
	x86_float_state64_t fstate;
#elif defined(__i386__)
	x86_thread_state32_t tstate;
	x86_float_state32_t fstate;
#endif

	state_to_kernel(ctxt, &tstate, &fstate);
	int ret = dserver_rpc_sigprocess(bsd_signum, linux_signum, info->si_pid, info->si_code, info->si_addr, &tstate, &fstate, &bsd_signum);
	if (ret < 0) {
		__simple_printf("sigprocess failed internally while processing Linux signal %d: %d", linux_signum, ret);
		__simple_abort();
	}
	state_from_kernel(ctxt, &tstate, &fstate);

	if (!bsd_signum)
	{
		kern_printf("sigexc: drop signal\n");
		goto out;
	}

	linux_signum = signum_bsd_to_linux(bsd_signum);

	if (sig_handlers[linux_signum] != SIG_IGN)
	{
		if (sig_handlers[linux_signum])
		{
			kern_printf("sigexc: will forward signal to app handler (%p)\n", sig_handlers[linux_signum]);

			// Update the signal mask to what the application actually wanted
			linux_sigset_t set = sig_masks[linux_signum];

			// Keep the current signal blocked, which is the default behavior
			if (!(sig_flags[linux_signum] & LINUX_SA_NODEFER))
				set |= (1ull << (linux_signum-1));

			LINUX_SYSCALL(__NR_rt_sigprocmask, 2 /* LINUX_SIG_SETMASK */,
				&set, NULL, sizeof(linux_sigset_t));

			handler_linux_to_bsd(linux_signum, info, ctxt);
		}
		else
		{
			if (bsd_signum == SIGTSTP || bsd_signum == SIGSTOP)
			{
				kern_printf("sigexc: emulating SIGTSTP/SIGSTOP\n");
				LINUX_SYSCALL(__NR_kill, linux_self_pid(), LINUX_SIGSTOP);
			}
			else
			{
				kern_printf("sigexc: emulating default signal effects\n");
				// Set handler to SIG_DFL
				struct linux_sigaction sa;
				sa.sa_sigaction = (linux_sig_handler*) NULL; // SIG_DFL
				sa.sa_mask = 0x7fffffff; // all other standard Unix signals should be blocked while the handler is run
				sa.sa_flags = LINUX_SA_RESTORER | LINUX_SA_SIGINFO | LINUX_SA_RESTART | LINUX_SA_ONSTACK;
				sa.sa_restorer = sig_restorer;

				LINUX_SYSCALL(__NR_rt_sigaction, linux_signum,
						&sa, NULL,
						sizeof(sa.sa_mask));

				/*
				 * Linux kill(0, sig) is the whole process group.
				 * Chrome helpers share the browser pgrp, so a
				 * default SIGSEGV (ImmediateCrash movl $0,0)
				 * used to SIGSEGV GPU/network/storage together.
				 */
				int self = linux_self_pid();
				__simple_printf("sigexc_kill_self_v1 pid=%d sig=%d\n", self, linux_signum);
				LINUX_SYSCALL(__NR_kill, self, linux_signum);
			}
		}
	}

	kern_printf("sigexc: handler (%d) returning\n", linux_signum);

out:
	status = dserver_rpc_interrupt_exit();

	if (status != 0) {
		__simple_printf("*** dserver_rpc_interrupt_exit failed with code %d ***\n", status);
		__simple_abort();
	}
}

#define DUMPREG(regname) kern_printf("sigexc:   " #regname ": 0x%llx\n", regs->regname);

#if defined(__x86_64__)
void mcontext_to_thread_state(const struct linux_gregset* regs, x86_thread_state64_t* s)
{
	s->__rax = regs->rax;
	s->__rbx = regs->rbx;
	s->__rcx = regs->rcx;
	s->__rdx = regs->rdx;
	s->__rdi = regs->rdi;
	s->__rsi = regs->rsi;
	s->__rbp = regs->rbp;
	s->__rsp = regs->rsp;
	s->__r8 = regs->r8;
	s->__r9 = regs->r9;
	s->__r10 = regs->r10;
	s->__r11 = regs->r11;
	s->__r12 = regs->r12;
	s->__r13 = regs->r13;
	s->__r14 = regs->r14;
	s->__r15 = regs->r15;
	s->__rip = regs->rip;
	s->__rflags = regs->efl;
	s->__cs = regs->cs;
	s->__fs = regs->fs;
	s->__gs = regs->gs;

	kern_printf("sigexc: saving to kernel:\n");
	DUMPREG(rip);
	DUMPREG(efl);
	DUMPREG(rax);
	DUMPREG(rbx);
	DUMPREG(rcx);
	DUMPREG(rdx);
	DUMPREG(rdi);
	DUMPREG(rsi);
	DUMPREG(rbp);
	DUMPREG(rsp);
}

void mcontext_to_float_state(const linux_fpregset_t fx, x86_float_state64_t* s)
{
	// fpregs is NULL on WSL1. See https://github.com/microsoft/WSL/issues/2555.
	if (fx == NULL)
	{
		memset(s, 0, sizeof(x86_float_state64_t));
		return;
	}

	kern_printf("sigexc: fcw out: 0x%x", fx->cwd);
	kern_printf("sigexc: xmm0 out: 0x%x", fx->_xmm[0].element[0]);
	*((uint16_t*)&s->__fpu_fcw) = fx->cwd;
	*((uint16_t*)&s->__fpu_fsw) = fx->swd;
	s->__fpu_ftw = fx->ftw;
	s->__fpu_fop = fx->fop;
	s->__fpu_ip = fx->rip;
	s->__fpu_cs = 0;
	s->__fpu_dp = fx->rdp;
	s->__fpu_ds = 0;
	s->__fpu_mxcsr = fx->mxcsr;
	s->__fpu_mxcsrmask = fx->mxcr_mask;

	memcpy(&s->__fpu_stmm0, fx->_st, 128);
	memcpy(&s->__fpu_xmm0, fx->_xmm, 256);
}

void thread_state_to_mcontext(const x86_thread_state64_t* s, struct linux_gregset* regs)
{
	regs->rax = s->__rax;
	regs->rbx = s->__rbx;
	regs->rcx = s->__rcx;
	regs->rdx = s->__rdx;
	regs->rdi = s->__rdi;
	regs->rsi = s->__rsi;
	regs->rbp = s->__rbp;
	regs->rsp = s->__rsp;
	regs->r8 = s->__r8;
	regs->r9 = s->__r9;
	regs->r10 = s->__r10;
	regs->r11 = s->__r11;
	regs->r12 = s->__r12;
	regs->r13 = s->__r13;
	regs->r14 = s->__r14;
	regs->r15 = s->__r15;
	regs->rip = s->__rip;
	regs->efl = s->__rflags;
	regs->cs = s->__cs;
	regs->fs = s->__fs;
	regs->gs = s->__gs;

	kern_printf("sigexc: restored from kernel:\n");
	DUMPREG(rip);
	DUMPREG(efl);
	DUMPREG(rax);
	DUMPREG(rbx);
	DUMPREG(rcx);
	DUMPREG(rdx);
	DUMPREG(rdi);
	DUMPREG(rsi);
	DUMPREG(rbp);
	DUMPREG(rsp);
}

void float_state_to_mcontext(const x86_float_state64_t* s, linux_fpregset_t fx)
{
	if (fx == NULL)
	{
		return;
	}

	fx->cwd = *((uint16_t*)&s->__fpu_fcw);
	fx->swd = *((uint16_t*)&s->__fpu_fsw);
	fx->ftw = s->__fpu_ftw;
	fx->fop = s->__fpu_fop;
	fx->rip = s->__fpu_ip;
	fx->rdp = s->__fpu_dp;
	fx->mxcsr = s->__fpu_mxcsr;
	fx->mxcr_mask = s->__fpu_mxcsrmask;

	memcpy(fx->_st, &s->__fpu_stmm0, 128);
	memcpy(fx->_xmm, &s->__fpu_xmm0, 256);
	kern_printf("sigexc: fcw in: 0x%x", fx->cwd);
	kern_printf("sigexc: xmm0 in: 0x%x", fx->_xmm[0].element[0]);
}

#elif defined(__i386__)
void mcontext_to_thread_state(const struct linux_gregset* regs, x86_thread_state32_t* s)
{
	s->__eax = regs->eax;
	s->__ebx = regs->ebx;
	s->__ecx = regs->ecx;
	s->__edx = regs->edx;
	s->__edi = regs->edi;
	s->__esi = regs->esi;
	s->__ebp = regs->ebp;
	s->__esp = regs->esp;
	s->__ss = regs->ss;
	s->__eflags = regs->efl;
	s->__eip = regs->eip;
	s->__cs = regs->cs;
	s->__ds = regs->ds;
	s->__es = regs->es;
	s->__fs = regs->fs;
	s->__gs = regs->gs;
}

void mcontext_to_float_state(const linux_fpregset_t fx, x86_float_state32_t* s)
{
	*((uint16_t*)&s->__fpu_fcw) = fx->cw;
	*((uint16_t*)&s->__fpu_fsw) = fx->sw;
	s->__fpu_ftw = fx->tag;
	s->__fpu_fop = 0;
	s->__fpu_ip = fx->ipoff;
	s->__fpu_cs = fx->cssel;
	s->__fpu_dp = fx->dataoff;
	s->__fpu_ds = fx->datasel;
	s->__fpu_mxcsr = fx->mxcsr;
	s->__fpu_mxcsrmask = 0;

	memcpy(&s->__fpu_stmm0, fx->_st, 128);
	memcpy(&s->__fpu_xmm0, fx->_xmm, 128);
	memset(((char*) &s->__fpu_xmm0) + 128, 0, 128);
}

void thread_state_to_mcontext(const x86_thread_state32_t* s, struct linux_gregset* regs)
{
	regs->eax = s->__eax;
	regs->ebx = s->__ebx;
	regs->ecx = s->__ecx;
	regs->edx = s->__edx;
	regs->edi = s->__edi;
	regs->esi = s->__esi;
	regs->ebp = s->__ebp;
	regs->esp = s->__esp;
	regs->ss = s->__ss;
	regs->efl = s->__eflags;
	regs->eip = s->__eip;
	regs->cs = s->__cs;
	regs->ds = s->__ds;
	regs->es = s->__es;
	regs->fs = s->__fs;
	regs->gs = s->__gs;
}

void float_state_to_mcontext(const x86_float_state32_t* s, linux_fpregset_t fx)
{
	fx->cw = *((uint16_t*)&s->__fpu_fcw);
	fx->sw = *((uint16_t*)&s->__fpu_fsw);
	fx->tag = s->__fpu_ftw;
	fx->ipoff = s->__fpu_ip;
	fx->cssel = s->__fpu_cs;
	fx->dataoff = s->__fpu_dp;
	fx->datasel = s->__fpu_ds;
	fx->mxcsr = s->__fpu_mxcsr;

	memcpy(fx->_st, &s->__fpu_stmm0, 128);
	memcpy(fx->_xmm, &s->__fpu_xmm0, 128);
}
#endif

void sigexc_thread_setup(void)
{
	struct bsd_stack newstack = {
		.ss_size = default_sigaltstack_size,
		.ss_flags = 0
	};

#if SIGALTSTACK_GUARD
	newstack.ss_sp = (void*) sys_mmap(NULL, newstack.ss_size + 4096, PROT_READ | PROT_WRITE,
			MAP_ANON | MAP_PRIVATE, -1, 0);
	sys_mprotect(newstack.ss_sp, 4096, PROT_NONE);
	newstack.ss_sp = (char*)newstack.ss_sp + 4096;
#else
	newstack.ss_sp = (void*) sys_mmap(NULL, newstack.ss_size, PROT_READ | PROT_WRITE,
			MAP_ANON | MAP_PRIVATE, -1, 0);
#endif
	sys_sigaltstack(&newstack, NULL);
}

void sigexc_thread_exit(void)
{
	struct bsd_stack oldstack;
	sys_sigaltstack(NULL, &oldstack);

#if SIGALTSTACK_GUARD
	sys_munmap((char*)oldstack.ss_sp - 4096, oldstack.ss_size + 4096);
#else
	sys_munmap(oldstack.ss_sp, oldstack.ss_size);
#endif
}
