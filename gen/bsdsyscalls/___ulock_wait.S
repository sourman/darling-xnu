#define __SYSCALL_32BIT_ARG_BYTES 20
#include "SYS.h"

#ifndef SYS_ulock_wait
#error "SYS_ulock_wait not defined. The header files libsyscall is building against do not match syscalls.master."
#endif

#if defined(__x86_64__) && defined(DARLING)
/*
 * ULF_NO_ERRNO (0x01000000): XNU returns -errno in rax with carry clear.
 * Darling's generic stub treats rax in [-4095,-1] as cerror, which turns
 * ETIMEDOUT into -1 and crashes libplatform's switch(-ret).
 */
	.globl	cerror_nocancel
LEAF(___ulock_wait, 0)
	pushq	%rdi
	movl	$ SYS_ulock_wait, %eax
	call	__darling_bsd_syscall
	popq	%rdi
	testl	$0x01000000, %edi
	jnz	1f
	cmpq	$-4095, %rax
	jb	1f
	movq	%rax, %rdi
	negq	%rdi
	BRANCH_EXTERN(_cerror_nocancel)
1:
	ret
#elif defined(__arm64__)
MI_ENTRY_POINT(___ulock_wait)
SYSCALL_NONAME(ulock_wait, 4, cerror_nocancel)
ret
#else
#if defined(__arm64__) || defined(__i386__) || defined(__x86_64__) || defined(__ppc__)
__SYSCALL2(___ulock_wait, ulock_wait, 4, cerror_nocancel)
#endif

#endif
