#define __SYSCALL_32BIT_ARG_BYTES 16
#include "SYS.h"

#ifndef SYS_ulock_wake
#error "SYS_ulock_wake not defined. The header files libsyscall is building against do not match syscalls.master."
#endif

#if defined(__x86_64__) && defined(DARLING)
	.globl	cerror_nocancel
LEAF(___ulock_wake, 0)
	pushq	%rdi
	movl	$ SYS_ulock_wake, %eax
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
MI_ENTRY_POINT(___ulock_wake)
SYSCALL_NONAME(ulock_wake, 3, cerror_nocancel)
ret
#else
#if defined(__arm64__) || defined(__i386__) || defined(__x86_64__) || defined(__ppc__)
__SYSCALL2(___ulock_wake, ulock_wake, 3, cerror_nocancel)
#endif

#endif
