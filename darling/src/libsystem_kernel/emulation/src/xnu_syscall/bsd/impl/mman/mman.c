#include <darling/emulation/xnu_syscall/bsd/impl/mman/mman.h>

#include <darling/emulation/conversion/mman/duct_mman.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
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
/* PartitionAlloc kPtrTagMask 0xFFFFFFFC00000000 → 16GiB buckets. */
#define PA_PTR_TAG_ALIGN           (1UL << 34)
/* Match 8/16GiB PA cages including ±4MiB of superpage guards. */
#define PA_CAGE_SLOP               (4UL * DARWIN_SUPERPAGE_SIZE)
/* 47-bit user VA. Surviving GPU cages sat at 1TiB, not 0x7f… next to stack. */
#define LINUX_USER_END             (1UL << 47)
#define PA_PROBE_BASE              (1UL << 40)
#define PA_PROBE_SLOTS             96
#define PA_SAFE_OVERMAP_END        (0x700000000000UL)

__attribute__((used)) static const char dtape_mmap_superpage_align_v1[] = "mmap_superpage_align_v1";
__attribute__((used)) static const char dtape_mmap_pool_stride_align_v1[] = "mmap_pool_stride_align_v1";
__attribute__((used)) static const char dtape_mmap_pool_stride_align_v2[] = "mmap_pool_stride_align_v2";
__attribute__((used)) static const char dtape_mmap_pool_stride_align_v3[] = "mmap_pool_stride_align_v3";
__attribute__((used)) static const char dtape_mmap_pool_stride_align_v4[] = "mmap_pool_stride_align_v4";
__attribute__((used)) static const char dtape_mmap_commit_keep_v1[] = "mmap_commit_keep_v1";
__attribute__((used)) static const char dtape_mmap_commit_keep_v2[] = "mmap_commit_keep_v2";
__attribute__((used)) static const char dtape_mmap_commit_keep_v3[] = "mmap_commit_keep_v3";
__attribute__((used)) static const char dtape_gpu_map_fixed_log_v1[] = "gpu_map_fixed_log_v1";
__attribute__((used)) static const char dtape_gpu_slot_vm_log_v1[] = "gpu_slot_vm_log_v1";
__attribute__((used)) static const char dtape_gpu_sp_watch_v1[] = "gpu_sp_watch_v1";
__attribute__((used)) static const char dtape_s2c_mmap_commit_keep_v1[] = "s2c_mmap_commit_keep_v1";
__attribute__((used)) static const char dtape_s2c_munmap_overtrim_split_v1[] = "s2c_munmap_overtrim_split_v1";
__attribute__((used)) static const char dtape_mprotect_inplace_v1[] = "mprotect_inplace_v1";
__attribute__((used)) static const char dtape_mmap_cage_slide_v1[] = "mmap_cage_slide_v1";
__attribute__((used)) static const char dtape_mincore_darwin_fresh_v1[] = "mincore_darwin_fresh_v1";
__attribute__((used)) static const char dtape_first_commit_zeros_v1[] = "first_commit_zeros_v1";
__attribute__((used)) static const char dtape_pa_meta18_commit_v1[] = "pa_meta18_commit_v1";
__attribute__((used)) static const char dtape_pa_meta18_map_v1[] = "pa_meta18_map_v1";
__attribute__((used)) static const char dtape_pa_meta18_twva_v1[] = "pa_meta18_twva_v1";
__attribute__((used)) static const char dtape_pa_meta18_hole_commit_v1[] = "pa_meta18_hole_commit_v1";
__attribute__((used)) static const char dtape_pa_mapmeta_brp_shared_v1[] = "pa_mapmeta_brp_shared_v1";
__attribute__((used)) static const char dtape_pa_root98_shared_v1[] = "pa_root98_shared_v1";
__attribute__((used)) static const char dtape_pa_root98_invself_v1[] = "pa_root98_invself_v1";
__attribute__((used)) static const char dtape_pa_mapmeta_shadow_v1[] = "pa_mapmeta_shadow_v1";
__attribute__((used)) static const char dtape_pa_shadow_pool_reserve_v1[] = "pa_shadow_pool_reserve_v1";
__attribute__((used)) static const char dtape_pa_mapmeta_shadow_hole_only_v1[] = "pa_mapmeta_shadow_hole_only_v1";
/* GPU PA crash slot: 1TiB probe base, 3MiB+16MiB RW in dying helpers. */
#define GPU_SLOT_LO PA_PROBE_BASE
#define GPU_SLOT_HI (PA_PROBE_BASE + 0x2000000UL)
/* First GPU/network 32GiB reservation + first …204000 8MiB superpage. */
#define PA_RES_LEN 0x800000000UL
#define PA_SP_OFF  0x204000UL
#define PA_SP_LEN  0x800000UL
#define PA_WATCH_MAX 4
#define DARWIN_MINCORE_INCORE     0x1
#define DARWIN_MINCORE_ANONYMOUS  0x80
#define PS_MAX 256

static unsigned long ps_lo[PS_MAX];
static unsigned long ps_hi[PS_MAX];
static unsigned char ps_kind[PS_MAX];
static int ps_n;

static int pa_is_cage_len(unsigned long len);
static int linux_mmap_failed(void *p);
static void *linux_mmap_raw(void *addr, unsigned long size, int prot, int linux_flags, int fd, long pos);
static int linux_munmap_raw(void *addr, unsigned long size);
static void darling_pa_mapmeta(unsigned long super);
static unsigned long pa_load_le64(const unsigned char *p);
static void darling_pa_root98_shared(unsigned long addr);
void darling_pa_root98_crash(unsigned long rbp, unsigned long slot);

#define PA_CAGE_TRACK_MAX 32
static unsigned long pa_cage_start[PA_CAGE_TRACK_MAX];
static unsigned long pa_cage_end[PA_CAGE_TRACK_MAX];
static int pa_cage_n;

void darling_pa_cage_note(unsigned long addr, unsigned long size)
{
	unsigned long end;
	int i, n, slot;

	if (!pa_is_cage_len(size) || addr == 0)
		return;
	end = addr + size;
	if (end < addr)
		return;
	n = pa_cage_n;
	if (n < 0)
		n = 0;
	if (n > PA_CAGE_TRACK_MAX)
		n = PA_CAGE_TRACK_MAX;
	for (i = 0; i < n; i++) {
		if (pa_cage_start[i] == addr && pa_cage_end[i] == end)
			return;
		if (addr <= pa_cage_end[i] && end >= pa_cage_start[i] &&
		    pa_cage_end[i] > pa_cage_start[i]) {
			if (addr < pa_cage_start[i])
				pa_cage_start[i] = addr;
			if (end > pa_cage_end[i])
				pa_cage_end[i] = end;
			return;
		}
	}
	slot = __sync_fetch_and_add(&pa_cage_n, 1);
	if (slot < 0 || slot >= PA_CAGE_TRACK_MAX) {
		if (slot >= PA_CAGE_TRACK_MAX)
			__sync_bool_compare_and_swap(&pa_cage_n, slot + 1, PA_CAGE_TRACK_MAX);
		return;
	}
	pa_cage_start[slot] = addr;
	pa_cage_end[slot] = end;
}

int darling_pa_cage_contains(unsigned long addr, unsigned long size)
{
	unsigned long end;
	int i, n;

	if (addr == 0 || size == 0)
		return 0;
	end = addr + size;
	if (end < addr)
		return 0;
	n = pa_cage_n;
	if (n < 0)
		return 0;
	if (n > PA_CAGE_TRACK_MAX)
		n = PA_CAGE_TRACK_MAX;
	for (i = 0; i < n; i++) {
		unsigned long cs = pa_cage_start[i];
		unsigned long ce = pa_cage_end[i];

		if (ce <= cs)
			continue;
		/* Commit into a reservation, not a whole-cage MAP_FIXED replace. */
		if (addr >= cs && end <= ce && size < (ce - cs))
			return 1;
	}
	return 0;
}

int darling_pa_range_mapped(unsigned long addr, unsigned long size)
{
	unsigned char vec[512];
	unsigned long done = 0;

	if (size == 0)
		return 1;
	if ((addr & (DARLING_PAGE_SIZE - 1UL)) != 0)
		return 0;
	while (done < size) {
		unsigned long chunk = size - done;
		long nr;

		if (chunk > 512UL * DARLING_PAGE_SIZE)
			chunk = 512UL * DARLING_PAGE_SIZE;
		nr = LINUX_SYSCALL3(__NR_mincore, addr + done, chunk, vec);
		if (nr != 0)
			return 0;
		done += chunk;
	}
	return 1;
}

/*
 * objc / libmalloc MAP_FIXED must still replace (SIGSEGV 0x74).
 * 1TiB-only keep aborted the browser: 0x7f heap is also above 1TiB.
 * PA reservations this GPU actually kept sit in [1TiB, 0x70…).
 */
int darling_in_malloc_heap(unsigned long addr, unsigned long size)
{
	unsigned long end;

	if (addr == 0 || size == 0)
		return 1;
	end = addr + size;
	if (end < addr)
		return 1;
	if (addr < PA_PROBE_BASE)
		return 1;
	if (addr >= PA_SAFE_OVERMAP_END || end > PA_SAFE_OVERMAP_END)
		return 1;
	return 0;
}

int darling_pa_range_resident(unsigned long addr, unsigned long size)
{
	unsigned char vec[512];
	unsigned long done = 0;

	if (size == 0)
		return 1;
	if ((addr & (DARLING_PAGE_SIZE - 1UL)) != 0)
		return 0;
	while (done < size) {
		unsigned long chunk = size - done;
		unsigned long pages, i;
		long nr;

		if (chunk > 512UL * DARLING_PAGE_SIZE)
			chunk = 512UL * DARLING_PAGE_SIZE;
		nr = LINUX_SYSCALL3(__NR_mincore, addr + done, chunk, vec);
		if (nr != 0)
			return 0;
		pages = chunk / DARLING_PAGE_SIZE;
		for (i = 0; i < pages; i++) {
			if ((vec[i] & 1) == 0)
				return 0;
		}
		done += chunk;
	}
	return 1;
}

/*
 * First-GPU MAP_FIXED trace. LINUX_SYSCALL write, never __simple_printf
 * (that aborted the browser from mmap). Do not cache a miss: a fork
 * helper can inherit BSS from a non-GPU parent.
 */
static int darling_cmdline_is_gpu(void)
{
	static int cached;
	char buf[4096];
	long fd, n, i, k;
	const char needle[] = "--type=gpu-process";
	const int nlen = 18;

	if (cached > 0)
		return 1;
	fd = LINUX_SYSCALL(__NR_open, "/proc/self/cmdline", LINUX_O_RDONLY, 0);
	if (fd < 0)
		return 0;
	n = LINUX_SYSCALL3(__NR_read, fd, buf, (long)sizeof(buf) - 1);
	LINUX_SYSCALL1(__NR_close, fd);
	if (n <= 0)
		return 0;
	for (i = 0; i + nlen <= n; i++) {
		if (i != 0 && buf[i - 1] != '\0')
			continue;
		for (k = 0; k < nlen; k++) {
			if (buf[i + k] != needle[k])
				break;
		}
		if (k != nlen)
			continue;
		if (i + nlen != n && buf[i + nlen] != '\0')
			continue;
		cached = 1;
		return 1;
	}
	return 0;
}

static int darling_cmdline_contains(const char *needle, int nlen)
{
	char buf[4096];
	long fd, n, i, k;

	if (!needle || nlen <= 0)
		return 0;
	fd = LINUX_SYSCALL(__NR_open, "/proc/self/cmdline", LINUX_O_RDONLY, 0);
	if (fd < 0)
		return 0;
	n = LINUX_SYSCALL3(__NR_read, fd, buf, (long)sizeof(buf) - 1);
	LINUX_SYSCALL1(__NR_close, fd);
	if (n <= 0)
		return 0;
	for (i = 0; i + nlen <= n; i++) {
		for (k = 0; k < nlen; k++) {
			if (buf[i + k] != needle[k])
				break;
		}
		if (k == nlen)
			return 1;
	}
	return 0;
}

/* GPU/network PA reservations. Do not cache a miss (fork inherits BSS). */
int darling_is_pa_helper(void)
{
	static int cached;

	if (cached > 0)
		return 1;
	if (darling_cmdline_is_gpu() ||
	    darling_cmdline_contains("network.mojom.NetworkService", 28)) {
		cached = 1;
		return 1;
	}
	return 0;
}

static int darling_is_first_gpu(void)
{
	static int first_pid;
	char pbuf[16];
	int pid, pfd, got, claimed;

	if (!darling_cmdline_is_gpu())
		return 0;
	pid = (int)LINUX_SYSCALL0(__NR_getpid);
	if (first_pid)
		return first_pid == pid;
	pfd = LINUX_SYSCALL(__NR_open, "/tmp/gpu-mmap-fixed.pid",
	    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_EXCL, 0644);
	if (pfd >= 0) {
		got = __simple_snprintf(pbuf, sizeof(pbuf), "%d\n", pid);
		LINUX_SYSCALL3(__NR_write, pfd, pbuf, got);
		LINUX_SYSCALL1(__NR_close, pfd);
		first_pid = pid;
		return 1;
	}
	pfd = LINUX_SYSCALL(__NR_open, "/tmp/gpu-mmap-fixed.pid", LINUX_O_RDONLY, 0);
	if (pfd < 0)
		return 1;
	got = (int)LINUX_SYSCALL3(__NR_read, pfd, pbuf, (long)sizeof(pbuf) - 1);
	LINUX_SYSCALL1(__NR_close, pfd);
	if (got <= 0)
		return 1;
	pbuf[got] = 0;
	claimed = (int)__simple_atoi(pbuf, NULL);
	first_pid = claimed;
	return claimed == pid;
}

static int darling_in_pa_probe(unsigned long addr)
{
	unsigned long lo = PA_PROBE_BASE;
	unsigned long hi = PA_PROBE_BASE +
	    (2UL * (unsigned long)PA_PROBE_SLOTS * PA_PTR_TAG_ALIGN);

	return addr >= lo && addr < hi;
}

static int pa_watch_pid[PA_WATCH_MAX];
static unsigned long pa_watch_res_lo[PA_WATCH_MAX];
static unsigned long pa_watch_res_hi[PA_WATCH_MAX];
static unsigned long pa_watch_sp_lo[PA_WATCH_MAX];
static unsigned long pa_watch_sp_hi[PA_WATCH_MAX];
static int pa_watch_sp_rw[PA_WATCH_MAX];
static int pa_watch_n;

static int pa_watch_idx_for_pid(int pid)
{
	int i;

	for (i = 0; i < pa_watch_n; i++) {
		if (pa_watch_pid[i] == pid)
			return i;
	}
	return -1;
}

static int pa_watch_alloc(int pid)
{
	int i;

	i = pa_watch_idx_for_pid(pid);
	if (i >= 0)
		return i;
	if (pa_watch_n >= PA_WATCH_MAX)
		return -1;
	i = pa_watch_n++;
	pa_watch_pid[i] = pid;
	pa_watch_res_lo[i] = 0;
	pa_watch_res_hi[i] = 0;
	pa_watch_sp_lo[i] = 0;
	pa_watch_sp_hi[i] = 0;
	pa_watch_sp_rw[i] = 0;
	return i;
}

static void pa_watch_note(const char *op, unsigned long addr, unsigned long size,
	unsigned long flags, unsigned long result)
{
	int pid, i;
	int mmap_op = 0;
	int mprotect_op = 0;
	unsigned long mapped;

	(void)dtape_gpu_sp_watch_v1;
	if (!darling_is_pa_helper() || !op)
		return;
	pid = (int)LINUX_SYSCALL0(__NR_getpid);
	if (op[0] == 'm' && op[1] == 'm')
		mmap_op = 1;
	else if (op[0] == 'm' && op[1] == 'p')
		mprotect_op = 1;
	else if (op[0] == 'v' && op[1] == 'm' && op[2] == '_' && op[3] == 'p')
		mprotect_op = 1;
	else if (op[0] == 'v' && op[1] == 'm' && op[2] == '_' &&
	    (op[3] == 'a' || op[3] == 'm'))
		mmap_op = 1;
	else if (op[0] == 's' && op[1] == '2' && op[2] == 'c' && op[3] == '_' &&
	    op[4] == 'm' && op[5] == 'm')
		mmap_op = 1;
	else if (op[0] == 's' && op[1] == '2' && op[2] == 'c' && op[3] == '_' &&
	    op[4] == 'm' && op[5] == 'p')
		mprotect_op = 1;

	mapped = result;
	if (mmap_op && size == PA_RES_LEN && mapped != 0 &&
	    mapped < (unsigned long)-4096UL) {
		i = pa_watch_alloc(pid);
		if (i >= 0 && pa_watch_res_lo[i] == 0) {
			pa_watch_res_lo[i] = mapped;
			pa_watch_res_hi[i] = mapped + size;
			/* Shadow is super+*(root+0x98), not first-32GiB+0x1000. */
		}
	}
	if (mprotect_op && size >= PA_SP_LEN && size <= PA_SP_LEN + 0x1000UL &&
	    (addr & 0xfffffUL) == PA_SP_OFF) {
		i = pa_watch_alloc(pid);
		if (i >= 0 && pa_watch_sp_lo[i] == 0) {
			pa_watch_sp_lo[i] = addr;
			pa_watch_sp_hi[i] = addr + size;
		}
		if (i >= 0)
			pa_watch_sp_rw[i] =
			    (flags & (LINUX_PROT_READ | LINUX_PROT_WRITE)) ? 1 : 0;
	}
}

static int pa_watch_overlap(unsigned long addr, unsigned long size)
{
	int pid, i;
	unsigned long end;

	if (addr == 0 || size == 0)
		return 0;
	pid = (int)LINUX_SYSCALL0(__NR_getpid);
	end = addr + size;
	if (end < addr)
		return 0;
	for (i = 0; i < pa_watch_n; i++) {
		if (pa_watch_pid[i] != pid)
			continue;
		if (pa_watch_res_hi[i] > pa_watch_res_lo[i] &&
		    end > pa_watch_res_lo[i] && addr < pa_watch_res_hi[i])
			return 1;
		if (pa_watch_sp_hi[i] > pa_watch_sp_lo[i] &&
		    end > pa_watch_sp_lo[i] && addr < pa_watch_sp_hi[i])
			return 1;
	}
	return 0;
}

static unsigned long pa_watch_word(int *mc_out)
{
	int pid, i;
	unsigned char vec;
	long nr;
	unsigned long word = 0;

	*mc_out = -1;
	pid = (int)LINUX_SYSCALL0(__NR_getpid);
	for (i = 0; i < pa_watch_n; i++) {
		if (pa_watch_pid[i] != pid || pa_watch_sp_lo[i] == 0)
			continue;
		if (!pa_watch_sp_rw[i]) {
			*mc_out = -2;
			return 0;
		}
		nr = LINUX_SYSCALL3(__NR_mincore, pa_watch_sp_lo[i],
		    DARLING_PAGE_SIZE, &vec);
		if (nr != 0) {
			*mc_out = (int)nr;
			return 0;
		}
		*mc_out = (int)(vec & 1);
		if ((vec & 1) == 0)
			return 0;
		word = *(volatile unsigned long *)pa_watch_sp_lo[i];
		return word;
	}
	return 0;
}

static int darling_slot_overlap(unsigned long addr, unsigned long size,
	unsigned long flags)
{
	unsigned long end;

	if (addr == 0 || size == 0)
		return 0;
	/* Cage-sized NOREPLACE (8/16GiB) is the measured 1TiB EEXIST wipe. */
	if (size >= (PA_PTR_TAG_ALIGN / 2UL))
		return 1;
	end = addr + size;
	if (end < addr)
		return 0;
	if (end > GPU_SLOT_LO && addr < GPU_SLOT_HI)
		return 1;
	/* Superpage commits into the cage this GPU actually kept (0x104…). */
	if (size >= DARWIN_SUPERPAGE_SIZE &&
	    (darling_in_pa_probe(addr) || darling_in_pa_probe(end - 1UL)))
		return 1;
	/* MAP_FIXED into 0x130… was below 2MiB so the wipe was invisible. */
	if ((flags & LINUX_MAP_FIXED) && size >= DARLING_PAGE_SIZE &&
	    (darling_in_pa_probe(addr) || darling_in_pa_probe(end - 1UL)))
		return 1;
	if (pa_watch_overlap(addr, size))
		return 1;
	return 0;
}

static unsigned long darling_maps_prot(unsigned long addr)
{
	char buf[512];
	char line[192];
	int fd, n, li, i;
	unsigned long prot = 0xff;

	fd = LINUX_SYSCALL(__NR_open, "/proc/self/maps", LINUX_O_RDONLY, 0);
	if (fd < 0)
		return 0xff;
	li = 0;
	while ((n = (int)LINUX_SYSCALL3(__NR_read, fd, buf, sizeof(buf))) > 0) {
		for (i = 0; i < n; i++) {
			if (buf[i] != '\n' && li < (int)sizeof(line) - 1) {
				line[li++] = buf[i];
				continue;
			}
			line[li] = 0;
			li = 0;
			if (line[0] >= '0') {
				unsigned long lo = 0, hi = 0;
				char *p = line;
				int d, dash = 0;

				for (; *p && *p != ' '; p++) {
					if (*p == '-') {
						lo = hi;
						hi = 0;
						dash = 1;
						continue;
					}
					d = -1;
					if (*p >= '0' && *p <= '9')
						d = *p - '0';
					else if (*p >= 'a' && *p <= 'f')
						d = *p - 'a' + 10;
					else if (*p >= 'A' && *p <= 'F')
						d = *p - 'A' + 10;
					if (d < 0)
						break;
					hi = (hi << 4) | (unsigned long)d;
				}
				if (!dash)
					continue;
				if (addr < lo || addr >= hi)
					continue;
				while (*p == ' ')
					p++;
				prot = 0;
				if (p[0] == 'r')
					prot |= LINUX_PROT_READ;
				if (p[1] == 'w')
					prot |= LINUX_PROT_WRITE;
				if (p[2] == 'x')
					prot |= LINUX_PROT_EXEC;
				LINUX_SYSCALL1(__NR_close, fd);
				return prot;
			}
		}
	}
	LINUX_SYSCALL1(__NR_close, fd);
	return prot;
}

void darling_log_mmap_prot(unsigned long addr, unsigned long size,
	unsigned long linux_prot, unsigned long mapped)
{
	unsigned long vma;

	darling_gpu_slot_log("mmap_prot", addr, size, linux_prot, mapped);
	if (size != PA_RES_LEN || mapped >= (unsigned long)-4096UL)
		return;
	vma = darling_maps_prot(mapped);
	darling_gpu_slot_log("mmap_vma", mapped, size, vma, linux_prot);
}

void darling_page_state_note(unsigned long addr, unsigned long len, int kind)
{
	unsigned long start, end;
	int i, slot;

	(void)dtape_mincore_darwin_fresh_v1;
	if (addr < PA_PROBE_BASE || len == 0 || kind == 0)
		return;
	start = darling_trunc_page(addr);
	end = darling_round_page(addr + len);
	if (end <= start)
		return;
	for (i = 0; i < ps_n; i++) {
		if (ps_kind[i] != (unsigned char)kind)
			continue;
		if (end < ps_lo[i] || start > ps_hi[i])
			continue;
		if (start < ps_lo[i])
			ps_lo[i] = start;
		if (end > ps_hi[i])
			ps_hi[i] = end;
		return;
	}
	if (ps_n < PS_MAX)
		slot = ps_n++;
	else
		slot = (ps_n - 1);
	ps_lo[slot] = start;
	ps_hi[slot] = end;
	ps_kind[slot] = (unsigned char)kind;
}

int darling_page_state_at(unsigned long page)
{
	int i, kind = 0;

	if (page < PA_PROBE_BASE)
		return 0;
	for (i = 0; i < ps_n; i++) {
		if (page >= ps_lo[i] && page < ps_hi[i])
			kind = (int)ps_kind[i];
	}
	return kind;
}

void darling_discard_anonymous(void *addr, unsigned long len)
{
	if ((unsigned long)addr < PA_PROBE_BASE || len == 0)
		return;
	LINUX_SYSCALL(__NR_madvise, addr, len, LINUX_MADV_DONTNEED);
}

/*
 * Darwin first NONE→RW and FREE_REUSE of inaccessible pages are empty
 * zeros (slot-span metadata at the superpage head). Live RW OVERWRITE
 * keeps. The FRESH tag is not the signal: a merged 32GiB FRESH range
 * covering still-PROT_NONE pages skipped discard, so PA read
 * unprovisioned=0 allocated=0 (GetFreelistLength = slots_per_span)
 * and took REUSE while the freelist was never filled. Maps prot==0
 * is first commit. mincore is unused.
 *
 * SuperPage Initialize is MapMetadata: 4K mmap(MAP_FIXED|MAP_SHARED)
 * of pool_fd at the Chromium SuperPage file offset
 * ((super >> 21) % (fd_size/4K)) * 4K onto +0x1000. A 4K named-entry
 * or memfd uses off=0 (the object is the page), not the VA offset
 * 0x2000000. Linux MAP_FIXED SHARED unmaps first; a failed map leaves
 * a hole. maps_prot used to return 0xff for that hole, so the
 * pool_fd==-1 in-place Recommit skipped mprotect and Initialize never
 * stored occupancy (PAGEIN mprotect also fails on a hole). Darwin
 * first OVERWRITE fills the 4K island with anonymous RW zeros.
 * Configurable in-place (still in the PROT_NONE VMA) already stores.
 */
#define PA_META_PAGE 0x1000UL
#define PA_META_SUPER 0x200000UL
#define PA_POOL_SHADOW_MIN 0x1000000UL /* 16MiB: 8GiB pool, one 4K per super */
#define PA_POOL_FD_MAX 8
#define PA_PAGE4K_MAX 16
#define PA_MAPMETA_DONE_MAX 32

static int pa_pool_fd[PA_POOL_FD_MAX];
static unsigned long pa_pool_sz[PA_POOL_FD_MAX];
static int pa_pool_n;
static unsigned long pa_page4k_super[PA_PAGE4K_MAX];
static int pa_page4k_fd[PA_PAGE4K_MAX];
static unsigned long pa_page4k_off[PA_PAGE4K_MAX];
static int pa_page4k_n;
static unsigned long pa_mapmeta_done[PA_MAPMETA_DONE_MAX];
static int pa_mapmeta_n;

static void darling_pa_mapmeta_log(unsigned long super, unsigned long meta,
	int fd, unsigned long off, int nr)
{
	char line[256];
	int n, logfd;

	n = __simple_snprintf(line, sizeof(line),
	    "MAPMETA pid=%d super=0x%lx meta=0x%lx fd=%d off=0x%lx nr=%d\n",
	    (int)LINUX_SYSCALL0(__NR_getpid), super, meta, fd, off, nr);
	if (n <= 0)
		return;
	if (n > (int)sizeof(line) - 1)
		n = (int)sizeof(line) - 1;
	logfd = LINUX_SYSCALL(__NR_open, "/tmp/sigtrap-rip.log",
	    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
	if (logfd >= 0) {
		LINUX_SYSCALL3(__NR_write, logfd, line, n);
		LINUX_SYSCALL1(__NR_close, logfd);
	}
}

static int darling_pa_mapmeta_already(unsigned long super)
{
	int i;

	for (i = 0; i < pa_mapmeta_n; i++) {
		if (pa_mapmeta_done[i] == super)
			return 1;
	}
	return 0;
}

static void darling_pa_mapmeta_mark(unsigned long super)
{
	int i;

	if (pa_mapmeta_n >= PA_MAPMETA_DONE_MAX)
		return;
	for (i = 0; i < pa_mapmeta_n; i++) {
		if (pa_mapmeta_done[i] == super)
			return;
	}
	pa_mapmeta_done[pa_mapmeta_n++] = super;
}

static unsigned long darling_pa_fd_size(int fd)
{
	unsigned char st[144];
	unsigned long sz = 0;
	int b;

	if (fd < 0)
		return 0;
	if (LINUX_SYSCALL(__NR_fstat, fd, st) < 0)
		return 0;
	for (b = 0; b < 8; b++)
		sz |= ((unsigned long)st[48 + b]) << (8 * b);
	return sz;
}

static void darling_pa_record_pool_fd(int fd, unsigned long sz)
{
	int i;

	if (fd < 0 || sz < PA_POOL_SHADOW_MIN || (sz & (PA_META_PAGE - 1UL)))
		return;
	for (i = 0; i < pa_pool_n; i++) {
		if (pa_pool_fd[i] == fd)
			return;
	}
	if (pa_pool_n >= PA_POOL_FD_MAX)
		return;
	pa_pool_fd[pa_pool_n] = fd;
	pa_pool_sz[pa_pool_n] = sz;
	pa_pool_n++;
}

static void darling_pa_record_page4k(unsigned long super, int fd, unsigned long off)
{
	int i;

	if (fd < 0)
		return;
	for (i = 0; i < pa_page4k_n; i++) {
		if (pa_page4k_super[i] == super)
			return;
	}
	if (pa_page4k_n >= PA_PAGE4K_MAX)
		return;
	pa_page4k_super[pa_page4k_n] = super;
	pa_page4k_fd[pa_page4k_n] = fd;
	pa_page4k_off[pa_page4k_n] = off;
	pa_page4k_n++;
}

/* Chromium MapMetadata file_offset: SuperPage index * 4K, not the VA offset. */
static unsigned long darling_pa_file_off(unsigned long super, unsigned long fsz)
{
	unsigned long pages;

	if (fsz < PA_META_PAGE)
		return (unsigned long)-1;
	if (fsz == PA_META_PAGE)
		return 0;
	pages = fsz / PA_META_PAGE;
	return ((super >> 21) % pages) * PA_META_PAGE;
}

static int darling_pa_mmap_shared(unsigned long island, int fd, unsigned long off)
{
	void *p;

	if (fd < 0)
		return 0;
	p = linux_mmap_raw((void *)island, PA_META_PAGE,
	    LINUX_PROT_READ | LINUX_PROT_WRITE,
	    LINUX_MAP_SHARED | LINUX_MAP_FIXED, fd, (long)off);
	return (!linux_mmap_failed(p) && p == (void *)island) ? 1 : 0;
}

static void pa_twva_note_rw4k(unsigned long addr, unsigned long len);

#define PA_ROOT98_DONE_MAX 32
#define PA_TWVA_MAX 48
static unsigned long pa_cached_root;
static unsigned long pa_cached_off;
static unsigned long pa_root98_done[PA_ROOT98_DONE_MAX];
static int pa_root98_done_n;
static unsigned long pa_rw4k[PA_TWVA_MAX];
static int pa_rw4k_n;

static void darling_pa_root98_log(unsigned long super, unsigned long root,
	unsigned long off, unsigned long store, unsigned long island, int nr)
{
	char line[320];
	int n, logfd;

	(void)dtape_pa_root98_shared_v1;
	(void)dtape_pa_mapmeta_brp_shared_v1;
	n = __simple_snprintf(line, sizeof(line),
	    "ROOT98 pid=%d super=0x%lx root=0x%lx off=0x%lx store=0x%lx island=0x%lx nr=%d\n",
	    (int)LINUX_SYSCALL0(__NR_getpid), super, root, off, store, island, nr);
	if (n <= 0)
		return;
	if (n > (int)sizeof(line) - 1)
		n = (int)sizeof(line) - 1;
	logfd = LINUX_SYSCALL(__NR_open, "/tmp/sigtrap-rip.log",
	    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
	if (logfd >= 0) {
		LINUX_SYSCALL3(__NR_write, logfd, line, n);
		LINUX_SYSCALL1(__NR_close, logfd);
	}
}

static int pa_root98_listed(unsigned long super)
{
	int i;

	for (i = 0; i < pa_root98_done_n; i++) {
		if (pa_root98_done[i] == super)
			return 1;
	}
	return 0;
}

static void pa_root98_mark(unsigned long super)
{
	if (pa_root98_done_n >= PA_ROOT98_DONE_MAX)
		return;
	if (pa_root98_listed(super))
		return;
	pa_root98_done[pa_root98_done_n++] = super;
}

#define PA_ROOT_INVSELF 0x3678UL

static int pa_looks_like_root(unsigned long root, unsigned long *off_out)
{
	unsigned char buf[0xa8];
	unsigned char invb[8];
	int mem;
	long got;
	unsigned long off, inv;

	if (root < 0x10000UL || (root & 7UL))
		return 0;
	mem = LINUX_SYSCALL(__NR_open, "/proc/self/mem", LINUX_O_RDONLY, 0);
	if (mem < 0)
		return 0;
	got = LINUX_SYSCALL(__NR_pread64, mem, buf, 0xa8, LL_ARG(root));
	if (got < 0xa8) {
		LINUX_SYSCALL1(__NR_close, mem);
		return 0;
	}
	off = pa_load_le64(buf + 0x98);
	/* Do not treat +0xa0 in {0,1} as a root. +0x98 must be a page offset. */
	if (off == 0 || (off & (PA_META_PAGE - 1UL))) {
		LINUX_SYSCALL1(__NR_close, mem);
		return 0;
	}
	got = LINUX_SYSCALL(__NR_pread64, mem, invb, 8, LL_ARG(root + PA_ROOT_INVSELF));
	LINUX_SYSCALL1(__NR_close, mem);
	if (got < 8)
		return 0;
	inv = pa_load_le64(invb);
	if (inv != ~root)
		return 0;
	if (off_out)
		*off_out = off;
	return 1;
}

static unsigned long pa_read_u64(unsigned long addr)
{
	unsigned char buf[8];
	int mem;
	long got;

	mem = LINUX_SYSCALL(__NR_open, "/proc/self/mem", LINUX_O_RDONLY, 0);
	if (mem < 0)
		return 0;
	got = LINUX_SYSCALL(__NR_pread64, mem, buf, 8, LL_ARG(addr));
	LINUX_SYSCALL1(__NR_close, mem);
	if (got < 8)
		return 0;
	return pa_load_le64(buf);
}

static unsigned long pa_find_root(unsigned long super, unsigned long *off_out)
{
	unsigned long cand, off;
	int i;

	(void)dtape_pa_root98_invself_v1;
	if (pa_cached_root && pa_looks_like_root(pa_cached_root, &off)) {
		if (off_out)
			*off_out = off;
		pa_cached_off = off;
		return pa_cached_root;
	}
	pa_cached_root = 0;
	pa_cached_off = 0;
	cand = pa_read_u64(super + PA_META_PAGE);
	if (pa_looks_like_root(cand, &off)) {
		pa_cached_root = cand;
		pa_cached_off = off;
		if (off_out)
			*off_out = off;
		return cand;
	}
	for (i = 0; i < pa_rw4k_n; i++) {
		cand = pa_read_u64(pa_rw4k[i]);
		if (!pa_looks_like_root(cand, &off))
			continue;
		pa_cached_root = cand;
		pa_cached_off = off;
		if (off_out)
			*off_out = off;
		return cand;
	}
	if (off_out)
		*off_out = 0;
	return 0;
}

/*
 * CheckFreeList store is super+*(root+0x98), not first-32GiB+0x1000.
 * Hole / PROT_NONE (maps 0xff or 0): first-time zeros.
 * Live RW 0x104 island: do not steal. A cage mmap that occupies a
 * reserved shadow wrap fails KERN_NO_SPACE (elsewhere), not a layout slide.
 */
#define PA_SHADOW_MAX 16
static unsigned long pa_shadow_va[PA_SHADOW_MAX];
static int pa_shadow_fd[PA_SHADOW_MAX];
static int pa_shadow_n;

static int pa_prot_first_commit(unsigned long prot)
{
	return prot == 0 || prot == 0xff;
}

static int pa_prot_live_rw(unsigned long prot)
{
	return prot != 0 && prot != 0xff && (prot & LINUX_PROT_WRITE) != 0;
}

int darling_pa_cage_occupies_shadow(unsigned long addr, unsigned long size)
{
	int i;
	unsigned long end;

	if (addr == 0 || size <= PA_META_PAGE)
		return 0;
	end = addr + size;
	if (end < addr)
		return 0;
	if (!(size == PA_RES_LEN || (size + PA_CAGE_SLOP >= PA_PTR_TAG_ALIGN / 2UL &&
	    size <= PA_PTR_TAG_ALIGN + PA_CAGE_SLOP)))
		return 0;
	for (i = 0; i < pa_shadow_n; i++) {
		if (pa_shadow_va[i] >= addr && pa_shadow_va[i] < end)
			return 1;
	}
	return 0;
}

static void pa_shadow_note(unsigned long store, int fd)
{
	int i;

	if (store == 0 || fd < 0)
		return;
	for (i = 0; i < pa_shadow_n; i++) {
		if (pa_shadow_va[i] == store) {
			if (pa_shadow_fd[i] < 0)
				pa_shadow_fd[i] = fd;
			return;
		}
	}
	if (pa_shadow_n >= PA_SHADOW_MAX)
		return;
	pa_shadow_va[pa_shadow_n] = store;
	pa_shadow_fd[pa_shadow_n] = fd;
	pa_shadow_n++;
}

static int pa_shadow_fd_for_store(unsigned long store)
{
	int i;

	store &= ~(PA_META_PAGE - 1UL);
	for (i = 0; i < pa_shadow_n; i++) {
		if (pa_shadow_va[i] == store)
			return pa_shadow_fd[i];
	}
	return -1;
}

static int pa_shadow_pool_reserve_store(unsigned long store)
{
	unsigned long prot;
	int fd, have;
	void *p;

	(void)dtape_pa_shadow_pool_reserve_v1;
	if (!darling_in_pa_probe(store))
		return -1;
	store &= ~(PA_META_PAGE - 1UL);
	have = pa_shadow_fd_for_store(store);
	if (have >= 0)
		return have;
	prot = darling_maps_prot(store);
	if (pa_prot_live_rw(prot))
		return -2;
	if (!pa_prot_first_commit(prot))
		return -2;
	fd = LINUX_SYSCALL(__NR_memfd_create, "pa_shadow", 1L);
	if (fd < 0)
		return -4;
	if (LINUX_SYSCALL(__NR_ftruncate, fd, LL_ARG(PA_META_PAGE)) < 0) {
		LINUX_SYSCALL1(__NR_close, fd);
		return -4;
	}
	p = linux_mmap_raw((void *)store, PA_META_PAGE,
	    LINUX_PROT_READ | LINUX_PROT_WRITE,
	    LINUX_MAP_SHARED | LINUX_MAP_FIXED, fd, 0);
	if (linux_mmap_failed(p) || p != (void *)store) {
		LINUX_SYSCALL1(__NR_close, fd);
		return -6;
	}
	pa_shadow_note(store, fd);
	return fd;
}

/*
 * First-time zeros on the hole CheckFreeList store VA only.
 * Do not MAP_FIXED|SHARED the island onto that object: that unmaps
 * live SuperPage metadata (ChoosePixelFormat / viz-compositor) and
 * the first GPU dies Z with no CheckFreeList dump. Live RW store
 * (0x104 island) and in-place island (store==island): leave them.
 */
static int pa_mapmeta_shadow_memfd(unsigned long store, unsigned long island,
	unsigned long super)
{
	int fd;
	unsigned long sprot;

	(void)dtape_pa_mapmeta_shadow_v1;
	(void)dtape_pa_mapmeta_shadow_hole_only_v1;
	(void)super;
	(void)island;
	if (store == island)
		return 0;
	sprot = darling_maps_prot(store);
	if (pa_prot_live_rw(sprot))
		return 0;
	fd = pa_shadow_fd_for_store(store);
	if (fd < 0)
		fd = pa_shadow_pool_reserve_store(store);
	if (fd < 0)
		return fd;
	return 5;
}

/*
 * CheckFreeList slot_span = super + *(PartitionRoot+0x98) + (idx<<5).
 * Hole store gets first-time zeros; island stays on its own object.
 */
static void darling_pa_root98_shared(unsigned long addr)
{
	unsigned long super, island, store, root, off;
	int nr;

	if (!darling_is_pa_helper() || !darling_in_pa_probe(addr))
		return;
	if ((addr & (PA_META_SUPER - 1UL)) != PA_META_PAGE &&
	    (addr & (PA_META_SUPER - 1UL)) != 2UL * PA_META_PAGE)
		return;
	super = addr & ~(PA_META_SUPER - 1UL);
	island = super + PA_META_PAGE;
	if (pa_root98_listed(super))
		return;
	root = pa_find_root(super, &off);
	if (!root) {
		darling_pa_root98_log(super, 0, 0, 0, island, -3);
		return;
	}
	store = (super + off) & ~(PA_META_PAGE - 1UL);
	if (store == island) {
		darling_pa_root98_log(super, root, off, store, island, 0);
		pa_root98_mark(super);
		return;
	}
	nr = pa_mapmeta_shadow_memfd(store, island, super);
	darling_pa_root98_log(super, root, off, store, island, nr);
	if (nr == 7 || nr == 5 || nr == 0)
		pa_root98_mark(super);
}

void darling_pa_root98_report(unsigned long super, unsigned long slot)
{
	unsigned long island, store, root, off, span, packed_w, head, island0, inv;
	unsigned char buf[32];
	unsigned char invb[8];
	unsigned int packed, alloc, unprov, idx;
	int mem, nr;
	long got;
	char line[448];
	int n, logfd;

	if (!darling_in_pa_probe(super))
		return;
	super &= ~(PA_META_SUPER - 1UL);
	island = super + PA_META_PAGE;
	island0 = pa_read_u64(island);
	root = pa_find_root(super, &off);
	store = root ? ((super + off) & ~(PA_META_PAGE - 1UL)) : 0;
	idx = 0;
	span = 0;
	head = packed_w = inv = 0;
	packed = alloc = unprov = 0;
	got = -1;
	if (root && slot >= super) {
		idx = (unsigned int)((slot & (PA_META_SUPER - 1UL)) >> 14);
		span = super + off + ((unsigned long)idx << 5);
		mem = LINUX_SYSCALL(__NR_open, "/proc/self/mem", LINUX_O_RDONLY, 0);
		if (mem >= 0) {
			got = LINUX_SYSCALL(__NR_pread64, mem, buf, 32, LL_ARG(span));
			if (LINUX_SYSCALL(__NR_pread64, mem, invb, 8,
			    LL_ARG(root + PA_ROOT_INVSELF)) >= 8)
				inv = pa_load_le64(invb);
			LINUX_SYSCALL1(__NR_close, mem);
		}
		if (got >= 32) {
			head = pa_load_le64(buf);
			packed_w = pa_load_le64(buf + 24);
			packed = (unsigned int)packed_w;
			alloc = packed & 0x7fffU;
			unprov = (packed >> 15) & 0x7fffU;
		}
	}
	nr = pa_root98_listed(super) ? 8 : (root ? 9 : -3);
	n = __simple_snprintf(line, sizeof(line),
	    "ROOT98CHK pid=%d super=0x%lx root=0x%lx off=0x%lx store=0x%lx island=0x%lx island0=0x%lx inv=0x%lx slot=0x%lx idx=%u span=0x%lx packed=0x%x alloc=%u unprov=%u head=0x%lx got=%ld nr=%d\n",
	    (int)LINUX_SYSCALL0(__NR_getpid), super, root, off, store, island,
	    island0, inv, slot, idx, span, packed, alloc, unprov, head, got, nr);
	if (n <= 0)
		return;
	if (n > (int)sizeof(line) - 1)
		n = (int)sizeof(line) - 1;
	logfd = LINUX_SYSCALL(__NR_open, "/tmp/sigtrap-rip.log",
	    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
	if (logfd >= 0) {
		LINUX_SYSCALL3(__NR_write, logfd, line, n);
		LINUX_SYSCALL1(__NR_close, logfd);
	}
}

void darling_pa_root98_crash(unsigned long rbp, unsigned long slot)
{
	unsigned long prev, span, page, root, off, super, packed_w, head, inv;
	unsigned char buf[32];
	unsigned char invb[8];
	unsigned int packed, alloc, unprov, idx;
	int mem, n, logfd;
	long got;
	char line[448];

	(void)dtape_pa_root98_invself_v1;
	if (rbp < 0x1000UL)
		return;
	prev = pa_read_u64(rbp);
	if (prev <= rbp || prev - rbp > 0x800UL)
		return;
	span = pa_read_u64(prev - 8UL);
	if (!span)
		return;
	super = slot ? (slot & ~(PA_META_SUPER - 1UL)) : (span & ~(PA_META_SUPER - 1UL));
	if (super && (span < super || span >= super + PA_META_SUPER)) {
		/* slot_span may be a shadow VA; still take extent from its 4K. */
	}
	page = span & ~(PA_META_PAGE - 1UL);
	root = pa_read_u64(page);
	off = 0;
	inv = 0;
	idx = 0;
	head = packed_w = 0;
	packed = alloc = unprov = 0;
	got = -1;
	mem = LINUX_SYSCALL(__NR_open, "/proc/self/mem", LINUX_O_RDONLY, 0);
	if (mem >= 0) {
		unsigned char offb[8];

		if (root) {
			if (LINUX_SYSCALL(__NR_pread64, mem, offb, 8, LL_ARG(root + 0x98)) >= 8)
				off = pa_load_le64(offb);
			if (LINUX_SYSCALL(__NR_pread64, mem, invb, 8,
			    LL_ARG(root + PA_ROOT_INVSELF)) >= 8)
				inv = pa_load_le64(invb);
		}
		got = LINUX_SYSCALL(__NR_pread64, mem, buf, 32, LL_ARG(span));
		LINUX_SYSCALL1(__NR_close, mem);
	}
	if (got >= 32) {
		head = pa_load_le64(buf);
		packed_w = pa_load_le64(buf + 24);
		packed = (unsigned int)packed_w;
		alloc = packed & 0x7fffU;
		unprov = (packed >> 15) & 0x7fffU;
	}
	if (slot >= super && super)
		idx = (unsigned int)((slot & (PA_META_SUPER - 1UL)) >> 14);
	if (root && pa_looks_like_root(root, &off)) {
		pa_cached_root = root;
		pa_cached_off = off;
	}
	n = __simple_snprintf(line, sizeof(line),
	    "ROOT98SPAN pid=%d rbp=0x%lx prev=0x%lx span=0x%lx page=0x%lx root=0x%lx off=0x%lx inv=0x%lx expect=0x%lx slot=0x%lx idx=%u packed=0x%x alloc=%u unprov=%u head=0x%lx got=%ld\n",
	    (int)LINUX_SYSCALL0(__NR_getpid), rbp, prev, span, page, root, off, inv,
	    root ? ~root : 0UL, slot, idx, packed, alloc, unprov, head, got);
	if (n <= 0)
		return;
	if (n > (int)sizeof(line) - 1)
		n = (int)sizeof(line) - 1;
	logfd = LINUX_SYSCALL(__NR_open, "/tmp/sigtrap-rip.log",
	    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
	if (logfd >= 0) {
		LINUX_SYSCALL3(__NR_write, logfd, line, n);
		LINUX_SYSCALL1(__NR_close, logfd);
	}
}

void darling_pa_after_commit(unsigned long addr, unsigned long len)
{
	if (len == 0)
		return;
	pa_twva_note_rw4k(addr, len);
	if (darling_is_pa_helper() && darling_in_pa_probe(addr))
		darling_pa_root98_shared(addr);
	if (darling_in_pa_probe(addr) && len >= 0x4000UL)
		darling_pa_twva_consider(addr);
}

#define PA_TWVA_DONE_MAX 32
#define PA_PAYLOAD_GUARD 0x4000UL

static unsigned long pa_twva_done[PA_TWVA_DONE_MAX];
static int pa_twva_done_n;
static unsigned long pa_twva_missed[PA_TWVA_DONE_MAX];
static int pa_twva_missed_n;

static unsigned long pa_load_le64(const unsigned char *p)
{
	unsigned long v = 0;
	int b;

	for (b = 0; b < 8; b++)
		v |= ((unsigned long)p[b]) << (8 * b);
	return v;
}

static int pa_twva_foreign_super(unsigned long page, unsigned long super)
{
	unsigned long owner, island, brp;

	island = super + PA_META_PAGE;
	brp = super + 2UL * PA_META_PAGE;
	if (page == island || page == brp)
		return 0;
	if (page < PA_PROBE_BASE)
		return 0;
	owner = page & ~(PA_META_SUPER - 1UL);
	/* Same super: island, BRP extras (+0x2000), payload — not foreign. */
	if (owner == super)
		return 0;
	if (darling_in_pa_probe(owner))
		return 1;
	return 0;
}

static int pa_twva_listed(const unsigned long *arr, int n, unsigned long v)
{
	int i;

	for (i = 0; i < n; i++) {
		if (arr[i] == v)
			return 1;
	}
	return 0;
}

static void pa_twva_note_rw4k(unsigned long addr, unsigned long len)
{
	unsigned long page;

	if (!darling_is_pa_helper() || len != PA_META_PAGE)
		return;
	page = addr & ~(PA_META_PAGE - 1UL);
	if (page < PA_PROBE_BASE)
		return;
	if (pa_twva_listed(pa_rw4k, pa_rw4k_n, page))
		return;
	if (pa_rw4k_n >= PA_TWVA_MAX)
		return;
	pa_rw4k[pa_rw4k_n++] = page;
}

static int pa_head_in_payload(unsigned long head, unsigned long super)
{
	unsigned long lo = super + PA_PAYLOAD_GUARD;
	unsigned long hi = super + PA_META_SUPER - PA_PAYLOAD_GUARD;

	/* Occupancy freelist_head is a raw in-pool pointer, not encoded-next. */
	if ((head & ~(PA_META_SUPER - 1UL)) != super)
		return 0;
	if (head >= lo && head < hi)
		return 1;
	return 0;
}

static int pa_twva_page_match(unsigned long page, unsigned long super,
	unsigned int *packed_out, unsigned long *head_out)
{
	unsigned char buf[4096];
	unsigned char vec = 0;
	int memfd, off;
	long got, mc;
	unsigned long head, packed_w;
	unsigned int packed;

	if ((page & (PA_META_PAGE - 1UL)) != 0)
		return 0;
	mc = LINUX_SYSCALL3(__NR_mincore, page, PA_META_PAGE, &vec);
	if (mc < 0 || (vec & 1) == 0)
		return 0;
	memfd = LINUX_SYSCALL(__NR_open, "/proc/self/mem", LINUX_O_RDONLY, 0);
	if (memfd < 0)
		return 0;
	got = LINUX_SYSCALL(__NR_pread64, memfd, buf, 4096, LL_ARG(page));
	LINUX_SYSCALL1(__NR_close, memfd);
	if (got < 32)
		return 0;
	for (off = 0; off + 32 <= (int)got; off += 32) {
		head = pa_load_le64(buf + off);
		packed_w = pa_load_le64(buf + off + 24);
		packed = (unsigned int)packed_w;
		if (packed == 0)
			continue;
		if (!pa_head_in_payload(head, super))
			continue;
		/* SlotSpanMetadata index must name that partition page. */
		if ((int)((head - super) >> 14) != off / 32)
			continue;
		if (packed_out)
			*packed_out = packed;
		if (head_out)
			*head_out = head;
		return 1;
	}
	return 0;
}

static int pa_twva_island_identity(unsigned long island, unsigned int *packed_out)
{
	unsigned char buf[4096];
	unsigned char vec = 0;
	int memfd, off;
	long got, mc;
	unsigned int packed;

	mc = LINUX_SYSCALL3(__NR_mincore, island, PA_META_PAGE, &vec);
	if (mc < 0 || (vec & 1) == 0)
		return 0;
	memfd = LINUX_SYSCALL(__NR_open, "/proc/self/mem", LINUX_O_RDONLY, 0);
	if (memfd < 0)
		return 0;
	got = LINUX_SYSCALL(__NR_pread64, memfd, buf, 4096, LL_ARG(island));
	LINUX_SYSCALL1(__NR_close, memfd);
	if (got < 32)
		return 0;
	for (off = 0; off + 32 <= (int)got; off += 32) {
		packed = (unsigned int)pa_load_le64(buf + off + 24);
		/* Extent at +0 can read as packed=0x1; that is not occupancy. */
		if (packed == 0 || packed == 1)
			continue;
		if (off == 0)
			continue;
		if (packed_out)
			*packed_out = packed;
		return 1;
	}
	return 0;
}

static void pa_twva_log(unsigned long super, unsigned long island,
	unsigned long tw, unsigned int packed, unsigned long head, int nr)
{
	char line[320];
	int n, logfd;

	(void)dtape_pa_meta18_twva_v1;
	n = __simple_snprintf(line, sizeof(line),
	    "TWVA pid=%d super=0x%lx island=0x%lx tw=0x%lx packed=0x%x head=0x%lx nr=%d\n",
	    (int)LINUX_SYSCALL0(__NR_getpid), super, island, tw,
	    packed, head, nr);
	if (n <= 0)
		return;
	if (n > (int)sizeof(line) - 1)
		n = (int)sizeof(line) - 1;
	logfd = LINUX_SYSCALL(__NR_open, "/tmp/sigtrap-rip.log",
	    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
	if (logfd >= 0) {
		LINUX_SYSCALL3(__NR_write, logfd, line, n);
		LINUX_SYSCALL1(__NR_close, logfd);
	}
}

static int pa_twva_alias(unsigned long island, unsigned long tw)
{
	unsigned char buf[4096];
	int memfd, fd;
	void *p;
	long got;

	if (island == tw)
		return 1;
	memfd = LINUX_SYSCALL(__NR_open, "/proc/self/mem", LINUX_O_RDONLY, 0);
	if (memfd < 0)
		return 0;
	got = LINUX_SYSCALL(__NR_pread64, memfd, buf, 4096, LL_ARG(tw));
	LINUX_SYSCALL1(__NR_close, memfd);
	if (got < 4096)
		return 0;
	fd = LINUX_SYSCALL(__NR_memfd_create, "pa_twva", 1L);
	if (fd < 0)
		return 0;
	if (LINUX_SYSCALL(__NR_ftruncate, fd, LL_ARG(4096)) < 0) {
		LINUX_SYSCALL1(__NR_close, fd);
		return 0;
	}
	if (LINUX_SYSCALL(__NR_pwrite64, fd, buf, 4096, LL_ARG(0)) < 4096) {
		LINUX_SYSCALL1(__NR_close, fd);
		return 0;
	}
	p = linux_mmap_raw((void *)tw, PA_META_PAGE,
	    LINUX_PROT_READ | LINUX_PROT_WRITE,
	    LINUX_MAP_SHARED | LINUX_MAP_FIXED, fd, 0);
	if (linux_mmap_failed(p) || p != (void *)tw) {
		LINUX_SYSCALL1(__NR_close, fd);
		return 0;
	}
	p = linux_mmap_raw((void *)island, PA_META_PAGE,
	    LINUX_PROT_READ | LINUX_PROT_WRITE,
	    LINUX_MAP_SHARED | LINUX_MAP_FIXED, fd, 0);
	LINUX_SYSCALL1(__NR_close, fd);
	return (!linux_mmap_failed(p) && p == (void *)island) ? 1 : 0;
}

static unsigned long pa_twva_find(unsigned long super, unsigned int *packed_out,
	unsigned long *head_out)
{
	unsigned long island, page, lo, hi, off, sz, cand;
	char buf[512];
	char line[192];
	int fd, n, li, i, dash;
	unsigned int packed;
	unsigned long head;

	island = super + PA_META_PAGE;
	if (pa_twva_page_match(island, super, packed_out, head_out))
		return island;
	if (pa_twva_island_identity(island, packed_out)) {
		if (head_out)
			*head_out = 0;
		return island;
	}
	/* BRP extras page is the Darwin writable metadata (ToWritable). */
	if (pa_twva_page_match(super + 2UL * PA_META_PAGE, super, packed_out,
	    head_out))
		return super + 2UL * PA_META_PAGE;
	for (i = 0; i < pa_rw4k_n; i++) {
		page = pa_rw4k[i];
		if (pa_twva_foreign_super(page, super))
			continue;
		if (pa_twva_page_match(page, super, packed_out, head_out))
			return page;
	}
	fd = LINUX_SYSCALL(__NR_open, "/proc/self/maps", LINUX_O_RDONLY, 0);
	if (fd < 0)
		return 0;
	li = 0;
	while ((n = (int)LINUX_SYSCALL3(__NR_read, fd, buf, sizeof(buf))) > 0) {
		for (i = 0; i < n; i++) {
			if (buf[i] != '\n' && li < (int)sizeof(line) - 1) {
				line[li++] = buf[i];
				continue;
			}
			line[li] = 0;
			li = 0;
			if (line[0] < '0')
				continue;
			{
				char *p = line;
				int d;

				lo = hi = 0;
				dash = 0;
				for (; *p && *p != ' '; p++) {
					if (*p == '-') {
						lo = hi;
						hi = 0;
						dash = 1;
						continue;
					}
					d = -1;
					if (*p >= '0' && *p <= '9')
						d = *p - '0';
					else if (*p >= 'a' && *p <= 'f')
						d = *p - 'a' + 10;
					else if (*p >= 'A' && *p <= 'F')
						d = *p - 'A' + 10;
					if (d < 0)
						break;
					hi = (hi << 4) | (unsigned long)d;
				}
				if (!dash || hi <= lo)
					continue;
				while (*p == ' ')
					p++;
				if (p[1] != 'w')
					continue;
				while (*p && *p != ' ')
					p++;
				/* skip offset dev inode; anonymous has no path */
				{
					int fields = 0;

					while (*p == ' ')
						p++;
					while (*p && fields < 3) {
						if (*p != ' ') {
							while (*p && *p != ' ')
								p++;
							fields++;
							while (*p == ' ')
								p++;
						} else
							p++;
					}
				}
				if (*p != 0 && *p != '\n')
					continue;
				sz = hi - lo;
				if (lo < PA_PROBE_BASE)
					continue;
				if (sz == PA_META_PAGE) {
					if (pa_twva_foreign_super(lo, super))
						continue;
					if (pa_twva_page_match(lo, super, packed_out,
					    head_out)) {
						LINUX_SYSCALL1(__NR_close, fd);
						return lo;
					}
					continue;
				}
				/* Indexed SuperPage slot only — not a packed-word scan. */
				if (sz < PA_POOL_SHADOW_MIN || sz > 0x2000000UL ||
				    (sz & (PA_META_PAGE - 1UL)))
					continue;
				off = darling_pa_file_off(super, sz);
				if (off == (unsigned long)-1 || off + PA_META_PAGE > sz)
					continue;
				cand = lo + off;
				if (pa_twva_foreign_super(cand, super))
					continue;
				if (pa_twva_page_match(cand, super, &packed, &head)) {
					if (packed_out)
						*packed_out = packed;
					if (head_out)
						*head_out = head;
					LINUX_SYSCALL1(__NR_close, fd);
					return cand;
				}
			}
		}
	}
	LINUX_SYSCALL1(__NR_close, fd);
	return 0;
}

void darling_pa_twva_consider(unsigned long super)
{
	unsigned long island, tw, head;
	unsigned int packed;
	int nr;

	if (!darling_is_pa_helper() || !darling_in_pa_probe(super))
		return;
	super &= ~(PA_META_SUPER - 1UL);
	island = super + PA_META_PAGE;
	if (pa_twva_listed(pa_twva_done, pa_twva_done_n, super))
		return;
	packed = 0;
	head = 0;
	tw = pa_twva_find(super, &packed, &head);
	if (tw == 0) {
		if (!pa_twva_listed(pa_twva_missed, pa_twva_missed_n, super) &&
		    pa_twva_missed_n < PA_TWVA_DONE_MAX)
			pa_twva_missed[pa_twva_missed_n++] = super;
		return;
	}
	if (tw == island) {
		pa_twva_log(super, island, tw, packed, head, 0);
		if (pa_twva_done_n < PA_TWVA_DONE_MAX)
			pa_twva_done[pa_twva_done_n++] = super;
		return;
	}
	nr = pa_twva_alias(island, tw) ? 5 : -2;
	pa_twva_log(super, island, tw, packed, head, nr);
	if (nr == 5 && pa_twva_done_n < PA_TWVA_DONE_MAX)
		pa_twva_done[pa_twva_done_n++] = super;
}

void darling_pa_twva_report(unsigned long super)
{
	unsigned long island;

	darling_pa_twva_consider(super);
	super &= ~(PA_META_SUPER - 1UL);
	if (pa_twva_listed(pa_twva_done, pa_twva_done_n, super))
		return;
	island = super + PA_META_PAGE;
	pa_twva_log(super, island, 0, 0, 0, -1);
}

static void darling_pa_scan_pool_fds(void)
{
	int fd;
	unsigned long sz;

	for (fd = 3; fd < 256; fd++) {
		sz = darling_pa_fd_size(fd);
		darling_pa_record_pool_fd(fd, sz);
	}
}

void darling_pa_note_shadow_map(unsigned long addr, unsigned long len, int fd, long pos)
{
	unsigned long sz, super, off, island;
	int wi, keep, pid;

	(void)dtape_pa_meta18_map_v1;
	if (fd < 0 || len == 0)
		return;
	sz = darling_pa_fd_size(fd);
	darling_pa_record_pool_fd(fd, sz);
	pid = (int)LINUX_SYSCALL0(__NR_getpid);
	wi = pa_watch_idx_for_pid(pid);

	/* Pool shadow file: SuperPage index is file_offset/4K, not VA 0x2000000. */
	if (sz >= PA_POOL_SHADOW_MIN && len == PA_META_PAGE && pos >= 0 &&
	    ((unsigned long)pos & (PA_META_PAGE - 1UL)) == 0) {
		off = (unsigned long)pos;
		if (wi >= 0 && pa_watch_res_lo[wi] && off + PA_META_PAGE <= sz) {
			super = pa_watch_res_lo[wi] +
			    (off / PA_META_PAGE) * PA_META_SUPER;
			if (super < pa_watch_res_hi[wi] &&
			    !darling_pa_mapmeta_already(super)) {
				island = super + PA_META_PAGE;
				if (darling_pa_mmap_shared(island, fd, off)) {
					darling_pa_mapmeta_log(super, island, fd, off, 1);
					darling_pa_mapmeta_mark(super);
				}
			}
		}
		return;
	}

	if (len == PA_META_PAGE && sz == PA_META_PAGE &&
	    darling_in_pa_probe(addr) &&
	    (addr & (PA_META_SUPER - 1UL)) == PA_META_PAGE) {
		super = addr & ~(PA_META_SUPER - 1UL);
		island = super + PA_META_PAGE;
		off = 0; /* 4K named-entry/memfd is the page; not off=0x2000000 */
		keep = (int)LINUX_SYSCALL(__NR_dup, fd);
		if (keep >= 0)
			darling_pa_record_page4k(super, keep, off);
		else
			darling_pa_record_page4k(super, fd, off);
		if (addr == island) {
			darling_pa_mapmeta_log(super, island, fd, off, 1);
			darling_pa_mapmeta_mark(super);
			return;
		}
		if (!darling_pa_mapmeta_already(super) &&
		    darling_pa_mmap_shared(island, fd, off)) {
			darling_pa_mapmeta_log(super, island, fd, off, 1);
			darling_pa_mapmeta_mark(super);
		}
	}
}

static void darling_pa_mapmeta(unsigned long super)
{
	unsigned long island, off, sz, prot;
	void *p;
	int i, fd, nr;

	(void)dtape_pa_meta18_commit_v1;
	(void)dtape_pa_meta18_map_v1;
	if (!darling_is_pa_helper() || !darling_in_pa_probe(super))
		return;
	super &= ~(PA_META_SUPER - 1UL);
	island = super + PA_META_PAGE;
	/* Island syscall: dedicated shadow at wrap VA, not steal 0x104. */
	darling_pa_root98_shared(island);
	if (darling_pa_mapmeta_already(super))
		return;

	/* Named-entry / memfd already tied to this SuperPage: off=0, not 0x2000000. */
	for (i = 0; i < pa_page4k_n; i++) {
		if (pa_page4k_super[i] != super)
			continue;
		fd = pa_page4k_fd[i];
		off = pa_page4k_off[i];
		if (darling_pa_mmap_shared(island, fd, off)) {
			darling_pa_mapmeta_log(super, island, fd, off, 1);
			darling_pa_mapmeta_mark(super);
			return;
		}
	}

	darling_pa_scan_pool_fds();
	for (i = 0; i < pa_pool_n; i++) {
		fd = pa_pool_fd[i];
		sz = pa_pool_sz[i];
		off = darling_pa_file_off(super, sz);
		if (off == (unsigned long)-1 || off + PA_META_PAGE > sz)
			continue;
		if (darling_pa_mmap_shared(island, fd, off)) {
			darling_pa_mapmeta_log(super, island, fd, off, 1);
			darling_pa_mapmeta_mark(super);
			return;
		}
	}

	/* pool_fd==-1 or SHARED failed: in-place Initialize. Do not skip. */
	(void)dtape_pa_meta18_hole_commit_v1;
	nr = 2;
	prot = darling_maps_prot(island);
	if (prot & LINUX_PROT_WRITE)
		;
	else if (prot == 0) {
		if (darling_mprotect_inplace((void *)island, PA_META_PAGE,
		    LINUX_PROT_READ | LINUX_PROT_WRITE) != 0)
			nr = -1;
	} else {
		/*
		 * Hole (not in maps → 0xff): Linux MAP_FIXED SHARED unmapped
		 * the island then failed. mprotect cannot fill a gap.
		 * Darwin first OVERWRITE of inaccessible metadata.
		 */
		p = linux_mmap_raw((void *)island, PA_META_PAGE,
		    LINUX_PROT_READ | LINUX_PROT_WRITE,
		    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
		    -1, 0);
		if (linux_mmap_failed(p) || p != (void *)island)
			nr = -1;
	}
	darling_pa_mapmeta_log(super, island, -1, 0, nr);
	if (nr == 2)
		darling_pa_mapmeta_mark(super);
}

static void darling_pa_meta18_rw(unsigned long addr, unsigned long len)
{
	unsigned long super, last;

	if (!darling_is_pa_helper() || !darling_in_pa_probe(addr) ||
	    len == 0 || len > 0x200000UL)
		return;
	last = addr + len - 1;
	if (last < addr)
		return;
	super = addr & ~(PA_META_SUPER - 1UL);
	while (super <= last) {
		darling_pa_mapmeta(super);
		if (super + PA_META_SUPER <= super)
			break;
		super += PA_META_SUPER;
	}
}

void darling_zero_if_not_live(void *addr, unsigned long len)
{
	unsigned long prot;
	char line[256];
	int n, fd;

	(void)dtape_first_commit_zeros_v1;
	if ((unsigned long)addr < PA_PROBE_BASE || len == 0)
		return;
	darling_pa_meta18_rw((unsigned long)addr, len);
	prot = darling_maps_prot((unsigned long)addr);
	if (prot == 0) {
		n = __simple_snprintf(line, sizeof(line),
		    "ZEROIF pid=%d addr=0x%lx len=0x%lx prot=0\n",
		    (int)LINUX_SYSCALL0(__NR_getpid),
		    (unsigned long)addr, len);
		if (n > 0) {
			if (n > (int)sizeof(line) - 1)
				n = (int)sizeof(line) - 1;
			fd = LINUX_SYSCALL(__NR_open, "/tmp/sigtrap-rip.log",
			    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
			if (fd >= 0) {
				LINUX_SYSCALL3(__NR_write, fd, line, n);
				LINUX_SYSCALL1(__NR_close, fd);
			}
		}
		darling_discard_anonymous(addr, len);
	}
}

void darling_gpu_slot_log(const char *op, unsigned long addr, unsigned long size,
	unsigned long flags, unsigned long result)
{
	char line[384];
	int n, fd, mc;
	unsigned long word;

	(void)dtape_gpu_slot_vm_log_v1;
	pa_watch_note(op, addr, size, flags, result);
	if (!darling_slot_overlap(addr, size, flags))
		return;
	word = pa_watch_word(&mc);
	n = __simple_snprintf(line, sizeof(line),
	    "gpu_slot op=%s pid=%d tid=%d addr=0x%lx len=0x%lx flags=0x%lx result=0x%lx word=0x%lx mc=%d\n",
	    op ? op : "?",
	    (int)LINUX_SYSCALL0(__NR_getpid),
	    (int)LINUX_SYSCALL0(__NR_gettid),
	    addr, size, flags, result, word, mc);
	if (n < 0)
		return;
	if (n > (int)sizeof(line) - 1)
		n = (int)sizeof(line) - 1;
	fd = LINUX_SYSCALL(__NR_open, "/tmp/gpu-slot-vm.log",
	    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
	if (fd < 0)
		return;
	LINUX_SYSCALL3(__NR_write, fd, line, n);
	LINUX_SYSCALL1(__NR_close, fd);
}

/*
 * Duct-tape over-map trim / named-entry unmap arrives as s2c_munmap.
 * Darwin vm_deallocate must not destroy adjacent live committed pages the
 * caller still owns. Track ranges s2c_mmap created and unmap only the
 * intersection (the intended hole). Untracked overlap is a live remainder.
 */
#define S2C_OWN_MAX 128
static struct {
	unsigned long lo;
	unsigned long hi;
} s2c_own[S2C_OWN_MAX];
static int s2c_own_n;

void darling_s2c_map_note(unsigned long addr, unsigned long size)
{
	unsigned long end;
	int i, slot;

	if (addr == 0 || size == 0)
		return;
	end = addr + size;
	if (end <= addr)
		return;
	(void)dtape_s2c_munmap_overtrim_split_v1;
	for (i = 0; i < s2c_own_n; i++) {
		if (s2c_own[i].hi < addr || s2c_own[i].lo > end)
			continue;
		if (addr < s2c_own[i].lo)
			s2c_own[i].lo = addr;
		if (end > s2c_own[i].hi)
			s2c_own[i].hi = end;
		return;
	}
	slot = s2c_own_n;
	if (slot < 0 || slot >= S2C_OWN_MAX)
		return;
	s2c_own[slot].lo = addr;
	s2c_own[slot].hi = end;
	s2c_own_n = slot + 1;
}

int darling_s2c_munmap(unsigned long addr, unsigned long size)
{
	unsigned long req_lo;
	unsigned long req_hi;
	unsigned long kept;
	int ret = 0;
	int i;
	int did = 0;

	if (size == 0)
		return 0;
	req_lo = addr;
	req_hi = addr + size;
	if (req_hi <= req_lo)
		return -LINUX_EINVAL;

	(void)dtape_s2c_munmap_overtrim_split_v1;
	kept = size;
	i = 0;
	while (i < s2c_own_n) {
		unsigned long lo = s2c_own[i].lo;
		unsigned long hi = s2c_own[i].hi;
		unsigned long ilo;
		unsigned long ihi;
		int nr;

		if (hi <= req_lo || lo >= req_hi) {
			i++;
			continue;
		}
		ilo = lo > req_lo ? lo : req_lo;
		ihi = hi < req_hi ? hi : req_hi;
		if (ihi > ilo) {
			nr = (int)LINUX_SYSCALL2(__NR_munmap, ilo, ihi - ilo);
			darling_gpu_slot_log("s2c_munmap", ilo, ihi - ilo, 0,
			    (unsigned long)(unsigned int)nr);
			if (nr < 0 && ret == 0)
				ret = nr;
			else if (nr == 0) {
				did = 1;
				if (kept >= (ihi - ilo))
					kept -= (ihi - ilo);
				else
					kept = 0;
			}
		}
		if (ilo <= lo && ihi >= hi) {
			s2c_own[i] = s2c_own[s2c_own_n - 1];
			s2c_own_n--;
			continue;
		}
		if (ilo <= lo) {
			s2c_own[i].lo = ihi;
			i++;
			continue;
		}
		if (ihi >= hi) {
			s2c_own[i].hi = ilo;
			i++;
			continue;
		}
		s2c_own[i].hi = ilo;
		if (s2c_own_n < S2C_OWN_MAX) {
			s2c_own[s2c_own_n].lo = ihi;
			s2c_own[s2c_own_n].hi = hi;
			s2c_own_n++;
		}
		i++;
	}

	if (kept > 0)
		darling_gpu_slot_log("s2c_munmap_keep", req_lo, kept, (unsigned long)did, 0);
	return ret;
}

int darling_gpu_fixed_pre(unsigned long addr, unsigned long size,
	int *cage_n, int *contains, int *mapped, int *resident)
{
	int gpu = darling_is_first_gpu();
	int probe = darling_in_pa_probe(addr);
	int nlocal;

	nlocal = pa_cage_n;
	if (nlocal < 0)
		nlocal = 0;
	if (nlocal > PA_CAGE_TRACK_MAX)
		nlocal = PA_CAGE_TRACK_MAX;
	/* Helpers that never note an 8/16GiB cage: still trace probe MAP_FIXED. */
	if (!gpu && !(probe && nlocal == 0))
		return 0;
	if (cage_n)
		*cage_n = nlocal;
	if (contains)
		*contains = darling_pa_cage_contains(addr, size);
	if (mapped)
		*mapped = darling_pa_range_mapped(addr, size);
	if (resident)
		*resident = darling_pa_range_resident(addr, size);
	return gpu ? 1 : 2;
}

void darling_gpu_fixed_post(const char *via, unsigned long addr, unsigned long size, int prot,
	int cage_n, int contains, int mapped, int resident, void *result, int kept)
{
	char line[384];
	int n, fd;
	int gpu = darling_is_first_gpu();
	int nlocal;

	nlocal = pa_cage_n;
	if (nlocal < 0)
		nlocal = 0;
	if (!gpu && !(darling_in_pa_probe(addr) && nlocal == 0))
		return;
	(void)dtape_gpu_map_fixed_log_v1;
	n = __simple_snprintf(line, sizeof(line),
	    "gpu_map_fixed via=%s pid=%d gpu=%d addr=0x%lx len=0x%lx prot=0x%x cage_n=%d contains=%d mapped=%d resident=%d kept=%d result=0x%lx\n",
	    via ? via : "?",
	    (int)LINUX_SYSCALL0(__NR_getpid),
	    gpu, addr, size, prot, cage_n, contains, mapped, resident, kept,
	    (unsigned long)result);
	if (n < 0)
		return;
	if (n > (int)sizeof(line) - 1)
		n = (int)sizeof(line) - 1;
	if (gpu)
		LINUX_SYSCALL3(__NR_write, 2, line, n);
	fd = LINUX_SYSCALL(__NR_open, "/tmp/gpu-mmap-fixed.log",
	    LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND, 0644);
	if (fd < 0)
		return;
	LINUX_SYSCALL3(__NR_write, fd, line, n);
	LINUX_SYSCALL1(__NR_close, fd);
}

static int pa_is_cage_len(unsigned long len)
{
	unsigned long eight = PA_PTR_TAG_ALIGN / 2;
	unsigned long sixteen = PA_PTR_TAG_ALIGN;

	if (len + PA_CAGE_SLOP >= eight && len <= eight + PA_CAGE_SLOP)
		return 1;
	if (len + PA_CAGE_SLOP >= sixteen && len <= sixteen + PA_CAGE_SLOP)
		return 1;
	return 0;
}

/*
 * Largest power-of-two alignment ≤ min(len, 16GiB) that divides len.
 * 2MiB superpages stay 2MiB; 8GiB/16GiB PA pools stay inside one tag bucket.
 * Cage-sized reservations skip the 2MiB-multiple requirement.
 */
static unsigned long pa_anon_align(unsigned long len)
{
	unsigned long a;

	if (pa_is_cage_len(len))
		return PA_PTR_TAG_ALIGN;
	/* 32GiB over-map is not a cage. Tag-probe + full client munmap
	 * was the traced wipe; Darwin mmap without MAP_ALIGNED(34) does
	 * not 16GiB-align a range larger than one tag bucket. */
	if (len > PA_PTR_TAG_ALIGN)
		return 0;
	if (len < DARWIN_SUPERPAGE_SIZE ||
	    (len & (DARWIN_SUPERPAGE_SIZE - 1UL)) != 0)
		return 0;
	a = DARWIN_SUPERPAGE_SIZE;
	while ((a << 1) <= len && (a << 1) <= PA_PTR_TAG_ALIGN && (len & a) == 0)
		a <<= 1;
	return a;
}

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

static int pa_same_tag_bucket(unsigned long addr, unsigned long size)
{
	if (size == 0)
		return 1;
	if (addr + size < addr || addr + size > LINUX_USER_END)
		return 0;
	return (addr & ~(PA_PTR_TAG_ALIGN - 1UL)) ==
	    ((addr + size - 1UL) & ~(PA_PTR_TAG_ALIGN - 1UL));
}

static int pa_keep_aligned(unsigned long addr, unsigned long size, unsigned long align)
{
	if ((addr & (align - 1UL)) != 0)
		return 0;
	if (align < PA_PTR_TAG_ALIGN || size > PA_PTR_TAG_ALIGN)
		return 1;
	return pa_same_tag_bucket(addr, size);
}

/*
 * Probe 16GiB-aligned holes from 1TiB first. Starting from a high unaligned
 * 0x7f… mmap walked into the last 16GiB of userspace (stack) so the first
 * GPU/network helpers kept a pool that straddled kPtrTagMask and ImmediateCrashed.
 */
static void *mmap_tag_probe(unsigned long len, int linux_prot, int linux_flags, int fd, long pos, unsigned long align)
{
	unsigned long bases[3];
	unsigned long h;
	void *mapped;
	long err;
	int b, n, nr;

	linux_flags &= ~LINUX_MAP_FIXED;
	bases[0] = PA_PROBE_BASE;
	bases[1] = align;
	bases[2] = PA_PROBE_BASE + ((unsigned long)PA_PROBE_SLOTS * align);

	(void)dtape_mmap_cage_slide_v1;
	for (b = 0; b < 3; b++) {
		h = bases[b] & ~(align - 1UL);
		if (h < align)
			h = align;
		for (n = 0; n < PA_PROBE_SLOTS; n++, h += align) {
			if (h < align || len > LINUX_USER_END - h)
				break;
			if (align >= PA_PTR_TAG_ALIGN && len <= PA_PTR_TAG_ALIGN &&
			    !pa_same_tag_bucket(h, len))
				continue;
			if (darling_pa_cage_occupies_shadow(h, len))
				continue;
			/*
			 * Darwin vm_map ANYWHERE: occupied hint slides to the
			 * next aligned hole. Linux NOREPLACE at 1TiB EEXIST
			 * (1MiB+8MiB islands) must not MAP_FIXED-unmap them.
			 */
			mapped = linux_mmap_raw((void*)h, len, linux_prot,
			    linux_flags | LINUX_MAP_FIXED_NOREPLACE, fd, pos);
			if (linux_mmap_failed(mapped) && pa_is_cage_len(len) &&
			    linux_prot != 0) {
				err = (long)mapped;
				if (err == -LINUX_ENOMEM) {
					mapped = linux_mmap_raw((void*)h, len, 0,
					    linux_flags | LINUX_MAP_FIXED_NOREPLACE,
					    fd, pos);
					if (!linux_mmap_failed(mapped) &&
					    mapped == (void*)h) {
						nr = darling_mprotect_inplace(
						    mapped, len, linux_prot);
						if (nr != 0) {
							linux_munmap_raw(mapped, len);
							mapped = (void*)(long)-LINUX_ENOMEM;
						}
					}
				}
			}
			if (!linux_mmap_failed(mapped) && mapped == (void*)h) {
				darling_pa_cage_note((unsigned long)mapped, len);
				return mapped;
			}
		}
	}
	return (void*)(long)-LINUX_ENOMEM;
}

static void *linux_mmap_syscall(void *addr, unsigned long size, int prot, int linux_flags, int fd, long pos)
{
#ifdef __NR_mmap2
	return (void*) LINUX_SYSCALL6(__NR_mmap2, addr, size, prot, linux_flags, fd, pos / 4096);
#else
	return (void*) LINUX_SYSCALL6(__NR_mmap, addr, size, prot, linux_flags, fd, pos);
#endif
}

static void *linux_mmap_raw(void *addr, unsigned long size, int prot, int linux_flags, int fd, long pos)
{
	void *mapped;

	if ((linux_flags & (LINUX_MAP_FIXED | LINUX_MAP_FIXED_NOREPLACE)) &&
	    darling_pa_cage_occupies_shadow((unsigned long)addr, size))
		return (void *)(long)-LINUX_ENOMEM;

	mapped = linux_mmap_syscall(addr, size, prot, linux_flags, fd, pos);
	if (!linux_mmap_failed(mapped) &&
	    (prot & (LINUX_PROT_READ | LINUX_PROT_WRITE)))
		pa_twva_note_rw4k((unsigned long)mapped, size);
	darling_gpu_slot_log("mmap", (unsigned long)addr, size,
	    (unsigned long)linux_flags, (unsigned long)mapped);
	if (size == PA_RES_LEN)
		darling_log_mmap_prot((unsigned long)addr, size,
		    (unsigned long)(unsigned int)prot, (unsigned long)mapped);
	if (!linux_mmap_failed(mapped)) {
		if (prot == 0)
			darling_page_state_note((unsigned long)mapped, size,
			    DARLING_PS_RESERVED);
		else if (prot & (LINUX_PROT_READ | LINUX_PROT_WRITE))
			darling_page_state_note((unsigned long)mapped, size,
			    DARLING_PS_FRESH);
	}
	if (!linux_mmap_failed(mapped) && mapped != addr)
		darling_gpu_slot_log("mmap", (unsigned long)mapped, size,
		    (unsigned long)linux_flags, (unsigned long)mapped);
	return mapped;
}

/*
 * XNU mmap(MAP_FIXED) over an existing anonymous reservation changes
 * protection of that range. Linux MAP_FIXED unmaps first, so a superpage
 * commit after InitializeFreelist replaces payload with fresh zeros while
 * slot-span occupancy (outside the cage) still says slots exist.
 * Try FIXED_NOREPLACE; if the VA is already mapped, mprotect in place.
 */
static void *linux_mmap_commit_keep(void *addr, unsigned long size, int prot, int linux_flags, int fd, long pos)
{
	void *mapped;
	int nr;
	int probe_flags;
	int log_gpu, cage_n = 0, contains = 0, mapped_pre = 0, resident = 0, kept = 0;

	if (darling_pa_cage_occupies_shadow((unsigned long)addr, size))
		return (void *)(long)-LINUX_ENOMEM;

	if (!(linux_flags & LINUX_MAP_FIXED) || !(linux_flags & LINUX_MAP_ANONYMOUS) || addr == 0)
		return linux_mmap_raw(addr, size, prot, linux_flags, fd, pos);

	if (darling_is_pa_helper() && darling_in_pa_probe((unsigned long)addr) &&
	    size <= 2UL * PA_META_PAGE)
		darling_pa_root98_shared((unsigned long)addr);

	log_gpu = darling_gpu_fixed_pre((unsigned long)addr, size,
	    &cage_n, &contains, &mapped_pre, &resident);
	/*
	 * Helpers only: Darwin NONE→RW / OVERWRITE on already-mapped anon
	 * is mprotect in place. Linux MAP_FIXED unmaps first (PA wipe).
	 * Cage-contains used to keep the browser's 16GiB too, and main
	 * then sat in vm_map (16KiB) so NativeWidget/network never ran.
	 * Browser/objc heap still replaces. Helpers do not need a cage note.
	 * Do not require mincore: early 32GiB/16GiB PROT_NONE at 0x108
	 * is already mapped, and mincore-false sent MAP_FIXED before the
	 * 10MiB keep (PA ImmediateCrash, rsi=kPtrTagMask).
	 */
	if (!darling_is_pa_helper() ||
	    darling_in_malloc_heap((unsigned long)addr, size)) {
		mapped = linux_mmap_raw(addr, size, prot, linux_flags, fd, pos);
		if (log_gpu)
			darling_gpu_fixed_post("mmap", (unsigned long)addr, size, prot,
			    cage_n, contains, mapped_pre, resident, mapped, 0);
		return mapped;
	}

	(void)dtape_mmap_commit_keep_v1;
	(void)dtape_mmap_commit_keep_v3;
	kept = 1;
	/* Original MAP_FIXED flags so sub-2MiB 0x130 commits are visible. */
	darling_gpu_slot_log("mmap", (unsigned long)addr, size,
	    (unsigned long)linux_flags, 1UL);
	probe_flags = (linux_flags & ~LINUX_MAP_FIXED) | LINUX_MAP_FIXED_NOREPLACE;
	mapped = linux_mmap_raw(addr, size, prot, probe_flags, fd, pos);
	if (!linux_mmap_failed(mapped) && mapped == addr) {
		if (prot & (LINUX_PROT_READ | LINUX_PROT_WRITE))
			darling_pa_after_commit((unsigned long)addr, size);
		if (log_gpu)
			darling_gpu_fixed_post("mmap", (unsigned long)addr, size, prot,
			    cage_n, contains, mapped_pre, resident, mapped, kept);
		return mapped;
	}

	if (prot & (LINUX_PROT_READ | LINUX_PROT_WRITE))
		darling_zero_if_not_live(addr, size);
	nr = darling_mprotect_inplace(addr, size, prot);
	if (nr == 0) {
		if (prot == 0)
			darling_page_state_note((unsigned long)addr, size,
			    DARLING_PS_RESERVED);
		else if (prot & (LINUX_PROT_READ | LINUX_PROT_WRITE)) {
			darling_page_state_note((unsigned long)addr, size,
			    DARLING_PS_FRESH);
			darling_pa_after_commit((unsigned long)addr, size);
		}
		if (log_gpu)
			darling_gpu_fixed_post("mmap", (unsigned long)addr, size, prot,
			    cage_n, contains, mapped_pre, resident, addr, kept);
		return addr;
	}

	/* Do not MAP_FIXED-fallback. That unmaps live payload. */
	if (!linux_mmap_failed(mapped)) {
		if (log_gpu)
			darling_gpu_fixed_post("mmap", (unsigned long)addr, size, prot,
			    cage_n, contains, mapped_pre, resident, mapped, kept);
		return mapped;
	}
	if (log_gpu)
		darling_gpu_fixed_post("mmap", (unsigned long)addr, size, prot,
		    cage_n, contains, mapped_pre, resident, (void*)(long)nr, kept);
	return (void*)(long)nr;
}

static int linux_munmap_raw(void *addr, unsigned long size)
{
	int ret;

	ret = (int)LINUX_SYSCALL2(__NR_munmap, addr, size);
	darling_gpu_slot_log("munmap", (unsigned long)addr, size, 0, (unsigned long)(unsigned int)ret);
	return ret;
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

	/* Cage-sized: slide to a free 16GiB slot. Do not MAP_FIXED over 1TiB islands. */
	if (align >= (1UL << 30)) {
		(void)dtape_mmap_cage_slide_v1;
		/*
		 * Helper already holds the reservation at the hint (32GiB at
		 * 0x108, or whatever it mapped). Keep there before tag-probe
		 * lands a second 16GiB at 0x104. Only if the hint is already
		 * mapped: treating a free junk hint as MAP_FIXED placed a
		 * 16GiB cage off-bucket (kPtrTagMask). Browser still probes.
		 */
		if (darling_is_pa_helper() && hint != 0 &&
		    !darling_in_malloc_heap((unsigned long)hint, len) &&
		    darling_pa_range_mapped((unsigned long)hint, DARLING_PAGE_SIZE)) {
			mapped = linux_mmap_commit_keep(hint, len, linux_prot,
			    linux_flags | LINUX_MAP_FIXED, fd, pos);
			if (!linux_mmap_failed(mapped) && mapped == hint)
				return mapped;
		}
		mapped = mmap_tag_probe(len, linux_prot, linux_flags, fd, pos, align);
		if (!linux_mmap_failed(mapped))
			return mapped;
		return (void*)(long)-LINUX_ENOMEM;
	}

	iaddr = linux_mmap_raw(hint, len, linux_prot, linux_flags, fd, pos);
	if (linux_mmap_failed(iaddr))
		return iaddr;
	if (pa_keep_aligned((unsigned long)iaddr, len, align))
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

	if (q < (unsigned long)iaddr || q + len < q || q + len > LINUX_USER_END ||
	    q >= PA_SAFE_OVERMAP_END ||
	    (align >= PA_PTR_TAG_ALIGN && len <= PA_PTR_TAG_ALIGN &&
	     !pa_same_tag_bucket(q, len))) {
		linux_munmap_raw(iaddr, over);
		mapped = mmap_tag_probe(len, linux_prot, linux_flags, fd, pos, align);
		if (!linux_mmap_failed(mapped))
			return mapped;
		return (void*)(long)-LINUX_ENOMEM;
	}

	mapped = linux_mmap_commit_keep((void*)q, len, linux_prot,
	    linux_flags | LINUX_MAP_FIXED, fd, pos);
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
	if (len == PA_RES_LEN)
		darling_gpu_slot_log("mmap_dprot", (unsigned long)start, len,
		    (unsigned long)(unsigned int)prot,
		    (unsigned long)(unsigned int)linux_prot);

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
	if ((linux_flags & LINUX_MAP_ANONYMOUS) && !(flags & MAP_FIXED)) {
		unsigned long pa = pa_anon_align(len);
		if (pa > align) {
			(void)dtape_mmap_superpage_align_v1;
			(void)dtape_mmap_pool_stride_align_v1;
			(void)dtape_mmap_pool_stride_align_v2;
			(void)dtape_mmap_pool_stride_align_v3;
			(void)dtape_mmap_pool_stride_align_v4;
			(void)dtape_mmap_commit_keep_v1;
			(void)dtape_mmap_commit_keep_v2;
			(void)dtape_mmap_commit_keep_v3;
			(void)dtape_gpu_map_fixed_log_v1;
			(void)dtape_s2c_mmap_commit_keep_v1;
			align = pa;
		}
	}
	if (align != 0 && !(flags & MAP_FIXED))
		ret = mmap_aligned_contiguous(start, len, linux_prot, linux_flags, linux_fd, pos, align);
	else if ((flags & MAP_FIXED) && (linux_flags & LINUX_MAP_ANONYMOUS))
		ret = linux_mmap_commit_keep(start, len, linux_prot, linux_flags, linux_fd, pos);
	else
		ret = linux_mmap_raw(start, len, linux_prot, linux_flags, linux_fd, pos);

	if (linux_mmap_failed(ret))
		ret = (void*)(long) errno_linux_to_bsd((int)(long) ret);
	else {
		darling_pa_cage_note((unsigned long)ret, len);
		if ((linux_flags & LINUX_MAP_SHARED) && linux_fd >= 0)
			darling_pa_note_shadow_map((unsigned long)ret, len,
			    linux_fd, pos);
	}

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

int darling_mprotect_inplace(void *addr, unsigned long len, int linux_prot)
{
	(void)dtape_mprotect_inplace_v1;
	/*
	 * Darwin vm_protect NONE→RW recommit keeps the same pages.
	 * munmap+mmap here drops PartitionAlloc encoded-next while
	 * occupancy still says the span is live.
	 */
	return (int)LINUX_SYSCALL3(__NR_mprotect, addr, len, linux_prot);
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

	if (linux_prot & (LINUX_PROT_READ | LINUX_PROT_WRITE))
		darling_zero_if_not_live(addr, len);
	ret = darling_mprotect_inplace(addr, len, linux_prot);
	if (ret == 0 && (linux_prot & (LINUX_PROT_READ | LINUX_PROT_WRITE)))
		darling_pa_after_commit((unsigned long)addr, len);
	if (ret == 0) {
		if (linux_prot == 0)
			darling_page_state_note((unsigned long)addr, len,
			    DARLING_PS_RESERVED);
		else if (linux_prot & (LINUX_PROT_READ | LINUX_PROT_WRITE))
			darling_page_state_note((unsigned long)addr, len,
			    DARLING_PS_FRESH);
	}
	darling_gpu_slot_log("mprotect", (unsigned long)addr, len,
	    (unsigned long)linux_prot, (unsigned long)(unsigned int)ret);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}

long sys_mincore(void* addr, unsigned long len, unsigned char* vec)
{
	int ret, kind, i, npages, linux0, dar0;
	unsigned long start, page;
	unsigned char v;

	(void)dtape_mincore_darwin_fresh_v1;
	ret = LINUX_SYSCALL3(__NR_mincore, addr, len, vec);
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	if (len == 0 || vec == 0)
		return 0;
	start = (unsigned long)addr;
	npages = (int)((len + DARLING_PAGE_SIZE - 1UL) / DARLING_PAGE_SIZE);
	if (npages < 1)
		return 0;
	linux0 = vec[0];
	kind = darling_page_state_at(start);
	if (npages > 8192) {
		if (kind == DARLING_PS_FRESH || kind == DARLING_PS_REUSABLE ||
		    kind == DARLING_PS_RESERVED) {
			for (i = 0; i < npages; i++)
				vec[i] = DARWIN_MINCORE_ANONYMOUS;
		} else {
			for (i = 0; i < npages; i++) {
				v = vec[i];
				vec[i] = DARWIN_MINCORE_ANONYMOUS |
				    ((v & 1) ? DARWIN_MINCORE_INCORE : 0);
			}
		}
	} else {
		for (i = 0; i < npages; i++) {
			page = start + (unsigned long)i * DARLING_PAGE_SIZE;
			kind = darling_page_state_at(page);
			v = vec[i];
			if (kind == DARLING_PS_FRESH || kind == DARLING_PS_REUSABLE ||
			    kind == DARLING_PS_RESERVED)
				vec[i] = DARWIN_MINCORE_ANONYMOUS;
			else
				vec[i] = DARWIN_MINCORE_ANONYMOUS |
				    ((v & 1) ? DARWIN_MINCORE_INCORE : 0);
		}
	}
	dar0 = vec[0];
	if (start >= PA_PROBE_BASE && len <= PA_SP_LEN)
		darling_gpu_slot_log("mincore", start, len,
		    ((unsigned long)(unsigned)linux0 << 16) |
		    ((unsigned long)(unsigned)dar0 << 8) |
		    (unsigned long)(unsigned)kind,
		    (unsigned long)(unsigned)npages);
	return 0;
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
