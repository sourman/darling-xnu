#include <darling/emulation/xnu_syscall/bsd/impl/mman/madvise.h>
#include <darling/emulation/xnu_syscall/bsd/impl/mman/mman.h>

#include <sys/errno.h>

#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/mman/duct_mman.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#define MADV_DONTNEED 4
#define MADV_FREE 5
#define MADV_FREE_REUSABLE 7
#define MADV_FREE_REUSE 8
/* Linux MADV_FREE: discard under pressure, keep contents until then. */
#define LINUX_MADV_FREE 8
#define LINUX_MADV_DONTNEED 4

#define DARLING_PAGE_SIZE 4096UL
#define darling_trunc_page(x) ((x) & ~(DARLING_PAGE_SIZE - 1UL))
#define darling_round_page(x) darling_trunc_page((x) + (DARLING_PAGE_SIZE - 1UL))

__attribute__((used)) static const char dtape_madvise_darwin_dontneed_v1[] = "madvise_darwin_dontneed_v1";
__attribute__((used)) static const char dtape_madvise_darwin_free_reuse_v1[] = "madvise_darwin_free_reuse_v1";

long sys_madvise(void* addr, unsigned long len, int advice)
{
	int ret;
	int darwin_advice = advice;
	unsigned long packed;
	unsigned long start, end;

	(void)dtape_madvise_darwin_dontneed_v1;
	(void)dtape_madvise_darwin_free_reuse_v1;

	/*
	 * Darwin MADV_DONTNEED does not zero-fill. Linux MADV_DONTNEED does,
	 * which drops PartitionAlloc encoded-next while occupancy still
	 * claims the slot-span is live. Never pass Linux 4. FREE_REUSABLE
	 * is Apple success = lazy, not discard (no-op here). If MADV_FREE
	 * is missing, succeed as a no-op. Do not fall back to DONTNEED.
	 *
	 * Darwin MADV_FREE_REUSE recommits a reusable range in place.
	 * Linux 8 is MADV_FREE (the opposite); never pass Darwin 8 through.
	 * mprotect RW if the span is still inaccessible. No munmap, no
	 * MAP_FIXED, no MAP_POPULATE. First-touch lazy-zero is the commit.
	 */
	if (advice == MADV_DONTNEED || advice == MADV_FREE) {
		advice = LINUX_MADV_FREE;
	} else if (advice == MADV_FREE_REUSE) {
		if (len == 0)
			return 0;
		start = (unsigned long)addr;
		end = start + len;
		if (end < start)
			return errno_linux_to_bsd(-LINUX_EINVAL);
		start = darling_trunc_page(start);
		end = darling_round_page((unsigned long)addr + len);
		len = end - start;
		addr = (void*)start;
		/*
		 * Darwin MADV_FREE_REUSE is accounting + in-place RW.
		 * Inaccessible (maps prot 0) first commit is empty zeros.
		 * Live RW keeps. Do not DONTNEED from the FRESH tag.
		 */
		darling_zero_if_not_live(addr, len);
		ret = darling_mprotect_inplace(addr, len,
		    LINUX_PROT_READ | LINUX_PROT_WRITE);
		darling_page_state_note((unsigned long)addr, len,
		    DARLING_PS_FRESH);
		packed = ((unsigned long)(unsigned int)darwin_advice << 16) |
		    (unsigned long)(unsigned int)(LINUX_PROT_READ | LINUX_PROT_WRITE);
		darling_gpu_slot_log("madvise", (unsigned long)addr, len,
		    packed, (unsigned long)(unsigned int)ret);
		if (ret < 0)
			ret = errno_linux_to_bsd(ret);
		return ret;
	} else if (advice == MADV_FREE_REUSABLE) {
		/*
		 * Darwin MADV_FREE_REUSABLE is lazy. Linux DONTNEED zeros
		 * payload while slot-span occupancy at the superpage head
		 * still says unprovisioned=0 allocated=0 (26-slot chain).
		 * Linux MADV_FREE matches Darwin until pressure.
		 */
		darling_page_state_note((unsigned long)addr, len,
		    DARLING_PS_REUSABLE);
		if (len != 0)
			LINUX_SYSCALL(__NR_madvise, addr, len, LINUX_MADV_FREE);
		packed = ((unsigned long)(unsigned int)darwin_advice << 16);
		darling_gpu_slot_log("madvise", (unsigned long)addr, len,
		    packed, 0);
		return 0;
	} else if (advice >= 5) {
		packed = ((unsigned long)(unsigned int)darwin_advice << 16);
		darling_gpu_slot_log("madvise", (unsigned long)addr, len,
		    packed, 0);
		return 0;
	}

	if (advice == LINUX_MADV_DONTNEED)
		advice = LINUX_MADV_FREE;

	ret = LINUX_SYSCALL(__NR_madvise, addr, len, advice);
	if (ret == -LINUX_EINVAL && advice == LINUX_MADV_FREE)
		ret = 0;
	packed = ((unsigned long)(unsigned int)darwin_advice << 16) |
	    (unsigned long)(unsigned int)advice;
	darling_gpu_slot_log("madvise", (unsigned long)addr, len,
	    packed, (unsigned long)(unsigned int)ret);

	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
