#include <darling/emulation/xnu_syscall/bsd/impl/mman/mman.h>

#include <darling/emulation/conversion/mman/duct_mman.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

/* Darwin user page size; match duct-tape mach_vm_protect rounding. */
#define DARLING_PAGE_SIZE 4096UL
#define darling_trunc_page(x) ((x) & ~(DARLING_PAGE_SIZE - 1UL))
#define darling_round_page(x) darling_trunc_page((x) + (DARLING_PAGE_SIZE - 1UL))

/* Darwin MAP_ALIGNED(n) / MAP_ALIGNED_SUPER live in flags bits 24–31. */
#define DARWIN_MAP_ALIGNMENT_SHIFT 24
#define DARWIN_MAP_ALIGNMENT_MASK  0xff000000U
#define DARWIN_MAP_ALIGNED_SUPER_N 24
#define DARWIN_SUPERPAGE_SIZE      (2UL * 1024UL * 1024UL)

static int prot_bsd_to_linux(int prot)
{
	int linux_prot = 0;

	if (prot & PROT_READ)
		linux_prot |= LINUX_PROT_READ;
	if (prot & PROT_WRITE)
		linux_prot |= LINUX_PROT_WRITE;
	if (prot & PROT_EXEC)
		linux_prot |= LINUX_PROT_EXEC;

	return linux_prot;
}

static int linux_mmap_failed(void *p)
{
	return (unsigned long)p > (unsigned long)-4096UL;
}

static void *linux_mmap_raw(void *addr, unsigned long size, int prot, int linux_flags, int fd, long pos)
{
#ifdef __NR_mmap2
	return (void*) LINUX_SYSCALL6(__NR_mmap2, addr, size, prot, linux_flags, fd, pos / 4096);
#else
	return (void*) LINUX_SYSCALL6(__NR_mmap, addr, size, prot, linux_flags, fd, pos);
#endif
}

static int linux_munmap_raw(void *addr, unsigned long size)
{
	return (int)LINUX_SYSCALL2(__NR_munmap, addr, size);
}

static unsigned long darwin_mmap_align(int flags)
{
	unsigned n = ((unsigned)flags & DARWIN_MAP_ALIGNMENT_MASK) >> DARWIN_MAP_ALIGNMENT_SHIFT;
	unsigned long align;

	if (n == 0)
		return 0;
	/* MAP_ALIGNED_SUPER: superpage (2MB on x86_64), not 2^24. */
	if (n == DARWIN_MAP_ALIGNED_SUPER_N)
		return DARWIN_SUPERPAGE_SIZE;
	if (n >= 64)
		return 0;
	align = 1UL << n;
	if (align < DARLING_PAGE_SIZE)
		return 0;
	return align;
}

/*
 * Honor Darwin MAP_ALIGNED: over-map, then anonymous MAP_FIXED overwrite at
 * aligned q for exactly `len` so the returned range is one VMA. Hint is never
 * treated as MAP_FIXED. Prefix/suffix of the over-map are dropped after.
 */
static void *mmap_aligned_contiguous(void *hint, unsigned long len, int linux_prot, int linux_flags, int fd, long pos, unsigned long align)
{
	unsigned long over;
	void *iaddr;
	void *mapped;
	unsigned long q, diff, over_end, map_end;

	iaddr = linux_mmap_raw(hint, len, linux_prot, linux_flags, fd, pos);
	if (linux_mmap_failed(iaddr))
		return iaddr;
	if (((unsigned long)iaddr & (align - 1UL)) == 0)
		return iaddr;

	linux_munmap_raw(iaddr, len);

	if (len > ~0UL - align)
		return (void*)(long)-LINUX_ENOMEM;

	over = len + align;
	iaddr = linux_mmap_raw(hint, over, linux_prot, linux_flags, fd, pos);
	if (linux_mmap_failed(iaddr))
		return iaddr;

	q = ((unsigned long)iaddr + (align - 1UL)) & ~(align - 1UL);
	diff = q - (unsigned long)iaddr;

	mapped = linux_mmap_raw((void*)q, len, linux_prot, linux_flags | LINUX_MAP_FIXED, fd, pos);
	if (linux_mmap_failed(mapped) || mapped != (void*)q) {
		linux_munmap_raw(iaddr, over);
		if (linux_mmap_failed(mapped))
			return mapped;
		return (void*)(long)-LINUX_ENOMEM;
	}

	if (diff > 0)
		linux_munmap_raw(iaddr, diff);
	over_end = (unsigned long)iaddr + over;
	map_end = q + len;
	if (over_end > map_end)
		linux_munmap_raw((void*)map_end, over_end - map_end);

	return mapped;
}

void* sys_mmap(void* start, unsigned long len, int prot, int flags, int fd, long pos)
{
	int linux_prot;
	int linux_flags = 0;
	int linux_fd = fd;
	unsigned long align;
	void* ret;

	linux_prot = prot_bsd_to_linux(prot);

	// if (flags & MAP_32BIT)
	// 	linux_flags |= LINUX_MAP_32BIT;
	if (flags & MAP_ANON) {
		linux_flags |= LINUX_MAP_ANONYMOUS;
		/* Apple fd=VM_MAKE_TAG is a vmmap label, not a Linux fd. */
		linux_fd = -1;
		pos = 0;
	}
	if (flags & MAP_FIXED)
		linux_flags |= LINUX_MAP_FIXED;
	if (flags & MAP_SHARED)
		linux_flags |= LINUX_MAP_SHARED;
	if (flags & MAP_PRIVATE)
		linux_flags |= LINUX_MAP_PRIVATE;
	// if (flags & MAP_STACK)
	// 	linux_flags |= LINUX_MAP_STACK;

#ifdef __NR_mmap2
#ifdef __i386__
	linux_flags |= LINUX_MAP_32BIT;
#endif
#endif

	align = darwin_mmap_align(flags);
	if (align != 0 && !(flags & MAP_FIXED))
		ret = mmap_aligned_contiguous(start, len, linux_prot, linux_flags, linux_fd, pos, align);
	else
		ret = linux_mmap_raw(start, len, linux_prot, linux_flags, linux_fd, pos);

	if (linux_mmap_failed(ret))
		ret = (void*)(long) errno_linux_to_bsd((int)(long) ret);

	return ret;
}

long sys_munmap(void* addr, unsigned long len)
{
	int ret;
	unsigned long start = (unsigned long)addr;
	unsigned long end;

	/* XNU: size 0 is success; otherwise trunc address, round end. */
	if (len == 0)
		return 0;

	end = start + len;
	if (end < start)
		return errno_linux_to_bsd(-LINUX_EINVAL);
	start = darling_trunc_page(start);
	end = darling_round_page((unsigned long)addr + len);
	len = end - start;
	addr = (void*)start;

	ret = linux_munmap_raw(addr, len);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}

long sys_mprotect(void* addr, unsigned long len, int prot)
{
	int linux_prot, ret;
	unsigned long start = (unsigned long)addr;
	unsigned long end;

	linux_prot = prot_bsd_to_linux(prot);

	/* XNU / duct-tape: trunc address, round end, then protect that span.
	 * Linux mprotect requires a page-aligned address; unaligned
	 * sizeof(malloc_zone_t) still needs trunc/round so the object is covered. */
	end = start + len;
	if (end < start)
		return errno_linux_to_bsd(-LINUX_EINVAL);
	start = darling_trunc_page(start);
	end = darling_round_page((unsigned long)addr + len);
	len = end - start;
	addr = (void*)start;

	ret = LINUX_SYSCALL3(__NR_mprotect, addr, len, linux_prot);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}

long sys_mincore(void* addr, unsigned long len, unsigned char* vec)
{
	int ret;

	ret = LINUX_SYSCALL3(__NR_mincore, addr, len, vec);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}

long sys_mlock(void* addr, unsigned long len)
{
	int ret;

	ret = LINUX_SYSCALL2(__NR_mlock, addr, len);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}

long sys_munlock(void* addr, unsigned long len)
{
	int ret;

	ret = LINUX_SYSCALL2(__NR_munlock, addr, len);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
