#define __SYSCALL_32BIT_ARG_BYTES 8
#include "SYS.h"

#ifndef SYS_getentropy
#error "SYS_getentropy not defined. The header files libsyscall is building against do not match syscalls.master."
#endif

#if defined(__x86_64__) && defined(DARLING)
/*
 * Darwin getentropy(2): 0 on a full fill, never a Linux byte count.
 * Chrome's GigaCage seed tests rax after _getentropy; nonzero takes a
 * urandom fallback while the RNG os_unfair_lock is still held.
 *
 * Do not call __darling_bsd_syscall (dyld stubs / C). Raw Linux getrandom
 * (318), flags=0, restart -EINTR, loop short reads. No C between syscall
 * and ret. Never /dev/urandom.
 */
	.globl	cerror_nocancel
LEAF(_getentropy, 0)
	testq	%rsi, %rsi
	jz	Lzero
	cmpq	$256, %rsi
	ja	Leinval

Lfill:
	movl	$318, %eax		/* __NR_getrandom */
	xorl	%edx, %edx		/* flags = 0 */
	syscall
	cmpq	$-4, %rax		/* -EINTR */
	je	Lfill
	testq	%rax, %rax
	js	Lerr
	jz	Leio
	addq	%rax, %rdi
	subq	%rax, %rsi
	jnz	Lfill
Lzero:
	xorl	%eax, %eax		/* Darwin: rax=0 on full fill */
	ret

Leinval:
	movl	$22, %edi		/* EINVAL */
	BRANCH_EXTERN(_cerror_nocancel)

Leio:
	movl	$5, %edi		/* EIO */
	BRANCH_EXTERN(_cerror_nocancel)

Lerr:
	negq	%rax
	movq	%rax, %rdi
	BRANCH_EXTERN(_cerror_nocancel)
#elif defined(__arm64__)
MI_ENTRY_POINT(_getentropy)
ZERO_EXTEND(1)
SYSCALL_NONAME(getentropy, 2, cerror_nocancel)
ret
#else
#if defined(__arm64__) || defined(__i386__) || defined(__x86_64__) || defined(__ppc__)
__SYSCALL2(_getentropy, getentropy, 2, cerror_nocancel)
#endif

#endif
