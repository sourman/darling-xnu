#ifndef LINUX_MMAN_H
#define LINUX_MMAN_H

void* sys_mmap(void* start, unsigned long len, int prot, int flags, int fd, long pos);
long sys_munmap(void* addr, unsigned long len);
long sys_mprotect(void* addr, unsigned long len, int prot);
long sys_mincore(void* addr, unsigned long len, unsigned char* vec);
long sys_mlock(void* addr, unsigned long len);
long sys_munlock(void* addr, unsigned long len);

/* Darwin page-query state for PA commit vs REUSE. 1TiB+ only. */
#define DARLING_PS_RESERVED 1
#define DARLING_PS_FRESH 2
#define DARLING_PS_REUSABLE 3
void darling_page_state_note(unsigned long addr, unsigned long len, int kind);
int darling_page_state_at(unsigned long page);
/* 1TiB+ anonymous: Linux DONTNEED so the range is zeros, not dirty keep. */
void darling_discard_anonymous(void *addr, unsigned long len);
/*
 * First commit of inaccessible pages is empty zeros (superpage metadata).
 * Live RW OVERWRITE keeps. Maps prot is the Darwin-faithful signal;
 * the FRESH tag is not, and mincore is unused by PA.
 */
void darling_zero_if_not_live(void *addr, unsigned long len);

/* mmap MAP_FIXED keep: already-mapped anon, not malloc heap (objc must replace). */
void darling_pa_cage_note(unsigned long addr, unsigned long size);
int darling_pa_cage_contains(unsigned long addr, unsigned long size);
int darling_pa_cage_occupies_shadow(unsigned long addr, unsigned long size);
int darling_pa_range_mapped(unsigned long addr, unsigned long size);
int darling_pa_range_resident(unsigned long addr, unsigned long size);
int darling_in_malloc_heap(unsigned long addr, unsigned long size);
int darling_is_pa_helper(void);
int darling_gpu_fixed_pre(unsigned long addr, unsigned long size,
	int *cage_n, int *contains, int *mapped, int *resident);
void darling_gpu_fixed_post(const char *via, unsigned long addr, unsigned long size, int prot,
	int cage_n, int contains, int mapped, int resident, void *result, int kept);
void darling_gpu_slot_log(const char *op, unsigned long addr, unsigned long size,
	unsigned long flags, unsigned long result);
void darling_log_mmap_prot(unsigned long addr, unsigned long size,
	unsigned long linux_prot, unsigned long mapped);
/* Darwin vm_protect / mprotect: Linux mprotect in place. Never munmap+mmap. */
int darling_mprotect_inplace(void *addr, unsigned long len, int linux_prot);
/* s2c_mmap notes the range dserver created. s2c_munmap unmaps only that. */
void darling_s2c_map_note(unsigned long addr, unsigned long size);
int darling_s2c_munmap(unsigned long addr, unsigned long size);
/* MapMetadata: SHARED pool_fd at SuperPage file offset, or in-place Recommit. */
void darling_pa_note_shadow_map(unsigned long addr, unsigned long len, int fd, long pos);
/* Real ToWritable: occupancy whose freelist_head is in this super's payload. */
void darling_pa_twva_consider(unsigned long super);
void darling_pa_twva_report(unsigned long super);
/* After NONE→RW: dedicated shadow at super+*(root+0x98), not steal 0x104. */
void darling_pa_after_commit(unsigned long addr, unsigned long len);
void darling_pa_root98_report(unsigned long super, unsigned long slot);
void darling_pa_root98_crash(unsigned long rbp, unsigned long slot);

#endif // LINUX_MMAN_H
