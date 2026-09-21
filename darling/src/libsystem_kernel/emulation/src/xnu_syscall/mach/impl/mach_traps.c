#define ioctl __real_ioctl
#include <mach/mach_traps.h>
#include <mach/vm_statistics.h>
#include <mach/kern_return.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <mach/mach_init.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/xnu_syscall/mach/impl/mach_traps.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/mman/duct_mman.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/mman/mman.h>

#include <darlingserver/rpc.h>

/* Self-task VM: raw Linux mmap/munmap, never the process allocator. */
static int linux_mmap_failed(void *p)
{
	return (unsigned long)p > (unsigned long)-4096UL;
}

static int self_task_mprotect(void *addr, unsigned long size, int prot);
__attribute__((used)) static const char dtape_mmap_commit_keep_v1[] = "mmap_commit_keep_v1";
__attribute__((used)) static const char dtape_mmap_commit_keep_v3[] = "mmap_commit_keep_v3";
__attribute__((used)) static const char dtape_gpu_map_fixed_log_v1[] = "gpu_map_fixed_log_v1";

static void *self_task_mmap_raw(void *addr, unsigned long size, int prot, int linux_flags)
{
	void *mapped;

#ifdef __NR_mmap2
	mapped = (void *)LINUX_SYSCALL(__NR_mmap2, addr, size, prot, linux_flags, -1, 0);
#else
	mapped = (void *)LINUX_SYSCALL(__NR_mmap, addr, size, prot, linux_flags, -1, 0);
#endif
	darling_gpu_slot_log("vm_allocate", (unsigned long)addr, size,
	    (unsigned long)linux_flags, (unsigned long)mapped);
	if (size == 0x800000000UL)
		darling_log_mmap_prot((unsigned long)addr, size,
		    (unsigned long)(unsigned int)prot, (unsigned long)mapped);
	return mapped;
}

/*
 * VM_FLAGS_OVERWRITE on an existing anonymous reservation is a prot change
 * on XNU. Linux MAP_FIXED unmaps first and drops encoded-next payload.
 */
static void *self_task_mmap(void *addr, unsigned long size, int prot, int linux_flags)
{
	void *mapped;
	int nr;
	int probe_flags;
	int log_gpu, cage_n = 0, contains = 0, mapped_pre = 0, resident = 0, kept = 0;

	if ((linux_flags & (LINUX_MAP_FIXED | LINUX_MAP_FIXED_NOREPLACE)) &&
	    darling_pa_cage_occupies_shadow((unsigned long)addr, size))
		return (void *)(long)-LINUX_ENOMEM;

	if (!(linux_flags & LINUX_MAP_FIXED) || addr == 0)
		return self_task_mmap_raw(addr, size, prot, linux_flags);

	log_gpu = darling_gpu_fixed_pre((unsigned long)addr, size,
	    &cage_n, &contains, &mapped_pre, &resident);
	/*
	 * Darwin VM_FLAGS_OVERWRITE on a live anonymous mapping is a prot
	 * change. Linux MAP_FIXED unmaps first. BSD mmap MAP_FIXED still
	 * replaces (objc heap). This trap must not require an 8GiB cage.
	 * Helpers in the PA probe range keep without mincore (early 0x108
	 * PROT_NONE). Low-VA helper FIXED (0x1000) still replaces when
	 * unmapped. Non-helpers keep only if already mapped (objc 0x7f).
	 */
	if (!(darling_is_pa_helper() &&
	      !darling_in_malloc_heap((unsigned long)addr, size)) &&
	    !darling_pa_range_mapped((unsigned long)addr, size)) {
		mapped = self_task_mmap_raw(addr, size, prot, linux_flags);
		darling_gpu_slot_log("vm_map", (unsigned long)addr, size,
		    (unsigned long)linux_flags, (unsigned long)mapped);
		if (log_gpu)
			darling_gpu_fixed_post("vm_map", (unsigned long)addr, size, prot,
			    cage_n, contains, mapped_pre, resident, mapped, 0);
		return mapped;
	}

	(void)dtape_mmap_commit_keep_v1;
	(void)dtape_mmap_commit_keep_v3;
	(void)dtape_gpu_map_fixed_log_v1;
	kept = 1;
	probe_flags = (linux_flags & ~LINUX_MAP_FIXED) | LINUX_MAP_FIXED_NOREPLACE;
	mapped = self_task_mmap_raw(addr, size, prot, probe_flags);
	if (!linux_mmap_failed(mapped) && mapped == addr) {
		darling_gpu_slot_log("vm_map", (unsigned long)addr, size,
		    (unsigned long)linux_flags, (unsigned long)mapped);
		if (log_gpu)
			darling_gpu_fixed_post("vm_map", (unsigned long)addr, size, prot,
			    cage_n, contains, mapped_pre, resident, mapped, kept);
		return mapped;
	}

	nr = self_task_mprotect(addr, size, prot);
	if (nr == 0) {
		darling_gpu_slot_log("vm_map", (unsigned long)addr, size,
		    (unsigned long)linux_flags, (unsigned long)addr);
		if (log_gpu)
			darling_gpu_fixed_post("vm_map", (unsigned long)addr, size, prot,
			    cage_n, contains, mapped_pre, resident, addr, kept);
		return addr;
	}

	/* Do not MAP_FIXED-fallback. That unmaps live payload. */
	if (!linux_mmap_failed(mapped)) {
		darling_gpu_slot_log("vm_map", (unsigned long)addr, size,
		    (unsigned long)linux_flags, (unsigned long)mapped);
		if (log_gpu)
			darling_gpu_fixed_post("vm_map", (unsigned long)addr, size, prot,
			    cage_n, contains, mapped_pre, resident, mapped, kept);
		return mapped;
	}
	darling_gpu_slot_log("vm_map", (unsigned long)addr, size,
	    (unsigned long)linux_flags, (unsigned long)(long)nr);
	if (log_gpu)
		darling_gpu_fixed_post("vm_map", (unsigned long)addr, size, prot,
		    cage_n, contains, mapped_pre, resident, (void*)(long)nr, kept);
	return (void*)(long)nr;
}

static int self_task_munmap(void *addr, unsigned long size)
{
	int ret;

	ret = (int)LINUX_SYSCALL(__NR_munmap, addr, size);
	darling_gpu_slot_log("munmap", (unsigned long)addr, size, 0,
	    (unsigned long)(unsigned int)ret);
	return ret;
}

static int self_task_mprotect(void *addr, unsigned long size, int prot)
{
	int ret;

	if (prot != 0)
		darling_zero_if_not_live(addr, size);
	ret = darling_mprotect_inplace(addr, size, prot);
	if (ret == 0 && prot != 0)
		darling_pa_after_commit((unsigned long)addr, size);
	if (ret == 0) {
		if (prot == 0)
			darling_page_state_note((unsigned long)addr, size,
			    DARLING_PS_RESERVED);
		else
			darling_page_state_note((unsigned long)addr, size,
			    DARLING_PS_FRESH);
	}
	darling_gpu_slot_log("vm_protect", (unsigned long)addr, size,
	    (unsigned long)prot, (unsigned long)(unsigned int)ret);
	return ret;
}

/* Darwin user page size; match duct-tape mach_vm_protect rounding. */
#define DARLING_PAGE_SIZE 4096ULL
#define darling_trunc_page(x) ((x) & ~(DARLING_PAGE_SIZE - 1ULL))
#define darling_round_page(x) darling_trunc_page((x) + (DARLING_PAGE_SIZE - 1ULL))
#define DARWIN_SUPERPAGE_SIZE  (2ULL * 1024ULL * 1024ULL)
#define PA_PTR_TAG_ALIGN       (1ULL << 34)
#define PA_CAGE_SLOP           (4ULL * DARWIN_SUPERPAGE_SIZE)
#define LINUX_USER_END         (1ULL << 47)
#define PA_PROBE_BASE          (1ULL << 40)
#define PA_PROBE_SLOTS         96
#define PA_SAFE_OVERMAP_END    (0x700000000000ULL)

__attribute__((used)) static const char dtape_vm_map_pool_stride_v1[] = "vm_map_pool_stride_v1";
__attribute__((used)) static const char dtape_vm_map_pool_stride_v2[] = "vm_map_pool_stride_v2";
__attribute__((used)) static const char dtape_vm_map_pool_stride_v3[] = "vm_map_pool_stride_v3";
__attribute__((used)) static const char dtape_vm_map_pool_stride_v4[] = "vm_map_pool_stride_v4";

static int pa_is_cage_len_u(uintptr_t len)
{
	uintptr_t eight = PA_PTR_TAG_ALIGN / 2;
	uintptr_t sixteen = PA_PTR_TAG_ALIGN;

	if (len + PA_CAGE_SLOP >= eight && len <= eight + PA_CAGE_SLOP)
		return 1;
	if (len + PA_CAGE_SLOP >= sixteen && len <= sixteen + PA_CAGE_SLOP)
		return 1;
	return 0;
}

static uintptr_t pa_anon_align_u(uintptr_t len)
{
	uintptr_t a;

	if (pa_is_cage_len_u(len))
		return PA_PTR_TAG_ALIGN;
	/* 32GiB over-map is not a cage. Same rule as pa_anon_align. */
	if (len > PA_PTR_TAG_ALIGN)
		return 0;
	if (len < DARWIN_SUPERPAGE_SIZE || (len & (DARWIN_SUPERPAGE_SIZE - 1ULL)) != 0)
		return 0;
	a = DARWIN_SUPERPAGE_SIZE;
	while ((a << 1) <= len && (a << 1) <= PA_PTR_TAG_ALIGN && (len & a) == 0)
		a <<= 1;
	return a;
}

static int pa_same_tag_bucket_u(uintptr_t addr, uintptr_t size)
{
	if (size == 0)
		return 1;
	if (addr + size < addr || addr + size > LINUX_USER_END)
		return 0;
	return (addr & ~(PA_PTR_TAG_ALIGN - 1ULL)) ==
	    ((addr + size - 1ULL) & ~(PA_PTR_TAG_ALIGN - 1ULL));
}

static int pa_keep_aligned_u(uintptr_t addr, uintptr_t size, uintptr_t align)
{
	if ((addr & (align - 1ULL)) != 0)
		return 0;
	if (align < PA_PTR_TAG_ALIGN || size > PA_PTR_TAG_ALIGN)
		return 1;
	return pa_same_tag_bucket_u(addr, size);
}

static void *self_task_mmap_tag_probe(unsigned long size, int prot, int linux_flags, unsigned long align, unsigned long hint)
{
	unsigned long bases[3];
	unsigned long h;
	void *mapped;
	int b, n;

	if (darling_is_pa_helper() && hint != 0 &&
	    darling_pa_range_mapped(hint, DARLING_PAGE_SIZE)) {
		mapped = self_task_mmap((void*)hint, size, prot,
		    linux_flags | LINUX_MAP_FIXED);
		if (!linux_mmap_failed(mapped) && mapped == (void*)hint)
			return mapped;
	}

	linux_flags &= ~LINUX_MAP_FIXED;
	bases[0] = PA_PROBE_BASE;
	bases[1] = align;
	bases[2] = PA_PROBE_BASE + ((unsigned long)PA_PROBE_SLOTS * align);

	for (b = 0; b < 3; b++) {
		h = bases[b] & ~(align - 1UL);
		if (h < align)
			h = align;
		for (n = 0; n < PA_PROBE_SLOTS; n++, h += align) {
			if (h < align || size > LINUX_USER_END - h)
				break;
			if (align >= PA_PTR_TAG_ALIGN && size <= PA_PTR_TAG_ALIGN &&
			    !pa_same_tag_bucket_u(h, size))
				continue;
			if (darling_pa_cage_occupies_shadow(h, size))
				continue;
			mapped = self_task_mmap((void*)h, size, prot,
			    linux_flags | LINUX_MAP_FIXED_NOREPLACE);
			if (!linux_mmap_failed(mapped) && mapped == (void*)h) {
				darling_pa_cage_note((unsigned long)mapped, size);
				return mapped;
			}
		}
	}
	return (void*)(long)-LINUX_ENOMEM;
}

__attribute__((used)) static const char dtape_named_entry_keep_page_v1[] =
    "named_entry_keep_page_v1";

#define UNIMPLEMENTED_TRAP() { char msg[] = "Called unimplemented Mach trap: "; write(2, msg, sizeof(msg)-1); write(2, __FUNCTION__, sizeof(__FUNCTION__)-1); write(2, "\n", 1); }

mach_port_name_t mach_reply_port_impl(void)
{
	unsigned int port_name;
	if (dserver_rpc_mach_reply_port(&port_name) != 0) {
		port_name = MACH_PORT_NULL;
	}
	return port_name;
}

mach_port_name_t thread_self_trap_impl(void)
{
	unsigned int port_name;
	if (dserver_rpc_thread_self_trap(&port_name) != 0) {
		port_name = MACH_PORT_NULL;
	}
	return port_name;
}

mach_port_name_t host_self_trap_impl(void)
{
	unsigned int port_name;
	if (dserver_rpc_host_self_trap(&port_name) != 0) {
		port_name = MACH_PORT_NULL;
	}
	return port_name;
}

mach_msg_return_t mach_msg_trap_impl(
				mach_msg_header_t *msg,
				mach_msg_option_t option,
				mach_msg_size_t send_size,
				mach_msg_size_t rcv_size,
				mach_port_name_t rcv_name,
				mach_msg_timeout_t timeout,
				mach_port_name_t notify)
{
	return mach_msg_overwrite_trap_impl(msg,
			option, send_size, rcv_size,
			rcv_name, timeout, notify,
			msg, 0);
}

mach_msg_return_t mach_msg_overwrite_trap_impl(
				mach_msg_header_t *msg,
				mach_msg_option_t option,
				mach_msg_size_t send_size,
				mach_msg_size_t rcv_size,
				mach_port_name_t rcv_name,
				mach_msg_timeout_t timeout,
				mach_port_name_t notify,
				mach_msg_header_t *rcv_msg,
				mach_msg_size_t rcv_limit)
{
	int code;

retry:
	code = dserver_rpc_mach_msg_overwrite(msg, option, send_size, rcv_size, rcv_name, timeout, notify, rcv_msg);

	if (code < 0) {
		if (code == -LINUX_EINTR) {
			// when the RPC call returns EINTR, it means we didn't manage to send the RPC message to the server;
			// when the RPC receive operation receives EINTR, it retries the call, meaning we should never see EINTR from an RPC receive.
			// therefore, if we wanted to both send and receive a message, this means the send (which is performed first) was interrupted.
			//
			// we also need to check if the caller wants to know about interrupts. if they want send interrupts, we tell them.
			// if they want receive interrupts, we tell them. otherwise, we retry the call.
			if ((option & MACH_SEND_MSG) != 0 && (option & MACH_SEND_INTERRUPT) != 0) {
				return MACH_SEND_INTERRUPTED;
			} else if ((option & MACH_RCV_MSG) != 0 && (option & MACH_RCV_INTERRUPT) != 0) {
				return MACH_RCV_INTERRUPTED;
			} else {
				goto retry;
			}
		}
		__simple_printf("mach_msg_overwrite failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t semaphore_signal_trap_impl(
				mach_port_name_t signal_name)
{
	int code = dserver_rpc_semaphore_signal(signal_name);

	if (code < 0) {
		__simple_printf("semaphore_signal failed (internally): %d\n", code);
		return KERN_FAILURE;
	}

	return code;
}
					      
kern_return_t semaphore_signal_all_trap_impl(
				mach_port_name_t signal_name)
{
	int code = dserver_rpc_semaphore_signal_all(signal_name);

	if (code < 0) {
		__simple_printf("semaphore_signal_all failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t semaphore_signal_thread_trap_impl(
				mach_port_name_t signal_name,
				mach_port_name_t thread_name)
{
	UNIMPLEMENTED_TRAP();
	return KERN_FAILURE;
}

kern_return_t semaphore_wait_trap_impl(
				mach_port_name_t wait_name)
{
	int code = dserver_rpc_semaphore_wait(wait_name);

	if (code < 0) {
		if (code == -LINUX_EINTR) {
			return KERN_ABORTED;
		}
		__simple_printf("semaphore_wait failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t semaphore_wait_signal_trap_impl(
				mach_port_name_t wait_name,
				mach_port_name_t signal_name)
{
	int code = dserver_rpc_semaphore_wait_signal(wait_name, signal_name);

	if (code < 0) {
		if (code == -LINUX_EINTR) {
			return KERN_ABORTED;
		}
		__simple_printf("semaphore_wait_signal failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t semaphore_timedwait_trap_impl(
				mach_port_name_t wait_name,
				unsigned int sec,
				clock_res_t nsec)
{
	int code = dserver_rpc_semaphore_timedwait(wait_name, sec, nsec);

	if (code < 0) {
		if (code == -LINUX_EINTR) {
			return KERN_ABORTED;
		}
		__simple_printf("semaphore_timedwait failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t semaphore_timedwait_signal_trap_impl(
				mach_port_name_t wait_name,
				mach_port_name_t signal_name,
				unsigned int sec,
				clock_res_t nsec)
{
	int code = dserver_rpc_semaphore_timedwait_signal(wait_name, signal_name, sec, nsec);

	if (code < 0) {
		if (code == -LINUX_EINTR) {
			return KERN_ABORTED;
		}
		__simple_printf("semaphore_timedwait_signal failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t clock_sleep_trap_impl(
				mach_port_name_t clock_name,
				sleep_type_t sleep_type,
				int sleep_sec,
				int sleep_nsec,
				mach_timespec_t	*wakeup_time)
{
	UNIMPLEMENTED_TRAP();
	return KERN_FAILURE;
}

kern_return_t _kernelrpc_mach_vm_allocate_trap_impl(
				mach_port_name_t target,
				mach_vm_offset_t *addr,
				mach_vm_size_t size,
				int flags)
{
	if (target != 0 && target != mach_task_self())
	{
		int code = dserver_rpc_mach_vm_allocate(target, addr, size, flags);

		if (code < 0) {
			__simple_printf("mach_vm_allocate failed (internally): %d\n", code);
			__simple_abort();
		}

		return code;
	}
	else
	{
		return _kernelrpc_mach_vm_map_trap_impl(target, addr,
				size, 0, flags, VM_PROT_READ | VM_PROT_WRITE);
	}
}

__attribute__((used)) static const char dtape_named_entry_reuse_va_v1[] = "named_entry_reuse_va_v1";

kern_return_t _kernelrpc_mach_vm_deallocate_trap_impl(
				mach_port_name_t target,
				mach_vm_address_t address,
				mach_vm_size_t size
)
{
	int ret;

	if (target != 0 && target != mach_task_self())
	{
		int code = dserver_rpc_mach_vm_deallocate(target, address, size);

		if (code < 0) {
			__simple_printf("mach_vm_deallocate failed (internally): %d\n", code);
			__simple_abort();
		}

		return code;
	}
	else
	{
		mach_vm_address_t start;
		mach_vm_address_t end;

		// XNU returns KERN_INVALID_ARGUMENT for address overflow, 
		// and allows NULL address if size is 0.
		if (address + size < address)
		{
			return KERN_INVALID_ARGUMENT;
		}

		if (size == (mach_vm_offset_t)0)
		{
			return KERN_SUCCESS;
		}

		/*
		 * Self-task dealloc is a raw Linux munmap. It never reaches
		 * dserver vm_map_remove, so the ≥128KB named-entry pin there
		 * never ran. Chrome Map()s NodeLinkMemory at 0x7f0000001000
		 * then the first Mapping destructor punches it before the
		 * second map. AdoptFragment at 0x4c0 then hits a hollow page.
		 * Keep ≥128KB maps in that window. 4K punches stay independent.
		 * Do not RPC this (S2C munmap deadlocks the waiting thread).
		 */
		start = darling_trunc_page(address);
		end = darling_round_page(address + size);
		if (end > start &&
		    end > 0x7f0000000000ULL && start < 0x7f8000000000ULL &&
		    (end - start) >= 131072ULL)
		{
			(void)dtape_named_entry_reuse_va_v1;
			(void)dtape_named_entry_keep_page_v1;
			__simple_printf("named_entry_reuse_va_v1 keep_va=0x%lx size=%lu dealloc=0x%lx-0x%lx\n",
			    (unsigned long)start, (unsigned long)(end - start),
			    (unsigned long)start, (unsigned long)end);
			return KERN_SUCCESS;
		}

		ret = self_task_munmap((void*)address, size);

		if (ret < 0)
			return KERN_FAILURE;

		return KERN_SUCCESS;
	}
}

kern_return_t _kernelrpc_mach_vm_protect_trap_impl(
				mach_port_name_t target,
				mach_vm_address_t address,
				mach_vm_size_t size,
				boolean_t set_maximum,
				vm_prot_t new_protection
)
{
	int prot = 0;
	int ret;
	mach_vm_address_t start;
	mach_vm_address_t end;

	if (target != 0 && target != mach_task_self())
		return MACH_SEND_INVALID_DEST;

	if (address + size < address)
		return KERN_INVALID_ARGUMENT;

	if (size == (mach_vm_size_t)0)
		return KERN_SUCCESS;

	if (new_protection & VM_PROT_READ)
		prot |= LINUX_PROT_READ;
	if (new_protection & VM_PROT_WRITE)
		prot |= LINUX_PROT_WRITE;
	if (new_protection & VM_PROT_EXECUTE)
		prot |= LINUX_PROT_EXEC;

	/* Same rounding as duct-tape mach_vm_protect / XNU vm_map_protect.
	 * Unaligned malloc_zone_t still needs trunc/round. */
	start = darling_trunc_page(address);
	end = darling_round_page(address + size);
	size = end - start;

	ret = self_task_mprotect((void*)start, (unsigned long)size, prot);
	if (ret < 0)
		return KERN_FAILURE;

	return KERN_SUCCESS;
}

kern_return_t _kernelrpc_mach_vm_map_trap_impl(
				mach_port_name_t target,
				mach_vm_offset_t *address,
				mach_vm_size_t size,
				mach_vm_offset_t mask,
				int flags,
				vm_prot_t cur_protection
)
{
	// We cannot allocate memory in other processes
	if (target != 0 && target != mach_task_self())
		return KERN_FAILURE;

	void* addr;
	int prot = 0;
	int linux_flags = LINUX_MAP_ANONYMOUS | LINUX_MAP_PRIVATE;

	if (cur_protection & VM_PROT_READ)
		prot |= LINUX_PROT_READ;
	if (cur_protection & VM_PROT_WRITE)
		prot |= LINUX_PROT_WRITE;
	if (cur_protection & VM_PROT_EXECUTE)
		prot |= LINUX_PROT_EXEC;

	if (!(flags & VM_FLAGS_ANYWHERE)) {
		if (flags & VM_FLAGS_OVERWRITE)
			linux_flags |= LINUX_MAP_FIXED;
		else
			linux_flags |= LINUX_MAP_FIXED_NOREPLACE;
	}
	if ((flags >> 24) == VM_MEMORY_REALLOC)
		addr = (void*)LINUX_SYSCALL(__NR_mremap, ((char*)*address) - 0x1000, 0x1000, 0x1000 + size, 0, NULL);
	else
		addr = self_task_mmap((void*)*address, size, prot, linux_flags);

	if (linux_mmap_failed(addr))
	{
		long err = (long)addr;

		if (err == -LINUX_EEXIST || err == -LINUX_ENOMEM)
			return KERN_NO_SPACE;
		return KERN_FAILURE;
	}

	/*
	 * Same layout as dtape_map_memfd_aligned: if the first try misses the
	 * mask, unmap it, over-map, MAP_FIXED|overwrite at aligned q for
	 * exactly `size` (one VMA), then drop prefix/suffix. Do not punch
	 * holes inside [q, q+size). FIXED maps keep the first try.
	 * PartitionAlloc 8/16GiB pools need stride ≥ kPtrTagMask even when
	 * the caller only passed a 2MiB mask (or mask==0 via mmap).
	 */
	if (flags & VM_FLAGS_ANYWHERE)
	{
		uintptr_t pa = pa_anon_align_u((uintptr_t)size);
		uintptr_t need = mask ? ((uintptr_t)mask + 1) : 0;
		if (pa > need)
			need = pa;
		if (need > 1 && !pa_keep_aligned_u((uintptr_t)addr, (uintptr_t)size, need))
		{
			uintptr_t boundary, q, diff, iaddr, over_size;
			void *mapped;
			int over_flags = linux_flags;

			(void)dtape_vm_map_pool_stride_v1;
			(void)dtape_vm_map_pool_stride_v2;
			(void)dtape_vm_map_pool_stride_v3;
			(void)dtape_vm_map_pool_stride_v4;
			self_task_munmap(addr, size);

			boundary = need;
			over_flags = linux_flags;
			over_flags &= ~LINUX_MAP_FIXED;

			if (need >= (1UL << 30)) {
				mapped = self_task_mmap_tag_probe((unsigned long)size, prot, over_flags, need,
				    (unsigned long)*address);
				if (!linux_mmap_failed(mapped)) {
					addr = mapped;
					goto pa_aligned_done;
				}
			}

			if (boundary == 0 || (size > ~(mach_vm_size_t)0 - boundary))
				return KERN_NO_SPACE;

			over_size = (uintptr_t)size + boundary;

			iaddr = (uintptr_t)self_task_mmap((void*)*address, over_size, prot, over_flags);
			if (linux_mmap_failed((void*)iaddr)) {
				mapped = self_task_mmap_tag_probe((unsigned long)size, prot, over_flags, need,
				    (unsigned long)*address);
				if (!linux_mmap_failed(mapped)) {
					addr = mapped;
					goto pa_aligned_done;
				}
				return KERN_FAILURE;
			}

			q = (iaddr + (boundary - 1)) / boundary * boundary;
			diff = q - iaddr;

			if (q < iaddr || q + (uintptr_t)size < q ||
			    q + (uintptr_t)size > LINUX_USER_END ||
			    q >= PA_SAFE_OVERMAP_END ||
			    (need >= PA_PTR_TAG_ALIGN && (uintptr_t)size <= PA_PTR_TAG_ALIGN &&
			     !pa_same_tag_bucket_u(q, (uintptr_t)size))) {
				self_task_munmap((void*)iaddr, over_size);
				mapped = self_task_mmap_tag_probe((unsigned long)size, prot, over_flags, need,
				    (unsigned long)*address);
				if (!linux_mmap_failed(mapped)) {
					addr = mapped;
					goto pa_aligned_done;
				}
				return KERN_NO_SPACE;
			}

			mapped = self_task_mmap((void*)q, size, prot, over_flags | LINUX_MAP_FIXED);
			if (linux_mmap_failed(mapped) || mapped != (void*)q)
			{
				self_task_munmap((void*)iaddr, over_size);
				return KERN_NO_SPACE;
			}

			if (diff > 0)
				self_task_munmap((void*)iaddr, diff);
			if (boundary - diff > 0)
				self_task_munmap((void*)(q + size), boundary - diff);

			addr = mapped;
		}
	}
pa_aligned_done:

	*address = (uintptr_t)addr;
	darling_pa_cage_note((unsigned long)addr, (unsigned long)size);
	return KERN_SUCCESS;
}

kern_return_t _kernelrpc_mach_port_allocate_trap_impl(
				mach_port_name_t target,
				mach_port_right_t right,
				mach_port_name_t *name
)
{
	int code = dserver_rpc_mach_port_allocate(target, right, name);

	if (code < 0) {
		__simple_printf("mach_port_allocate failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}


kern_return_t _kernelrpc_mach_port_destroy_trap_impl(
				mach_port_name_t target,
				mach_port_name_t name
)
{
	int code = dserver_rpc_mach_port_destruct(target, name, 0, 0);

	if (code < 0) {
		__simple_printf("mach_port_destroy failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_deallocate_trap_impl(
				mach_port_name_t target,
				mach_port_name_t name
)
{
	int code = dserver_rpc_mach_port_deallocate(target, name);

	if (code < 0) {
		__simple_printf("mach_port_deallocate failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_mod_refs_trap_impl(
				mach_port_name_t target,
				mach_port_name_t name,
				mach_port_right_t right,
				mach_port_delta_t delta
)
{
	int code = dserver_rpc_mach_port_mod_refs(target, name, right, delta);

	if (code < 0) {
		__simple_printf("mach_port_deallocate failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_move_member_trap_impl(
				mach_port_name_t target,
				mach_port_name_t member,
				mach_port_name_t after
)
{
	int code = dserver_rpc_mach_port_move_member(target, member, after);

	if (code < 0) {
		__simple_printf("mach_port_move_member failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_insert_right_trap_impl(
				mach_port_name_t target,
				mach_port_name_t name,
				mach_port_name_t poly,
				mach_msg_type_name_t polyPoly
)
{
	int code = dserver_rpc_mach_port_insert_right(target, name, poly, polyPoly);

	if (code < 0) {
		__simple_printf("mach_port_insert_right failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_insert_member_trap_impl(
				mach_port_name_t target,
				mach_port_name_t name,
				mach_port_name_t pset
)
{
	int code = dserver_rpc_mach_port_insert_member(target, name, pset);

	if (code < 0) {
		__simple_printf("mach_port_insert_member failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_extract_member_trap_impl(
				mach_port_name_t target,
				mach_port_name_t name,
				mach_port_name_t pset
)
{
	int code = dserver_rpc_mach_port_extract_member(target, name, pset);

	if (code < 0) {
		__simple_printf("mach_port_extract_member failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_construct_trap_impl(
				mach_port_name_t target,
				mach_port_options_t *options,
				uint64_t context,
				mach_port_name_t *name
)
{
	int code = dserver_rpc_mach_port_construct(target, options, context, name);

	if (code < 0) {
		__simple_printf("mach_port_construct failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_destruct_trap_impl(
				mach_port_name_t target,
				mach_port_name_t name,
				mach_port_delta_t srdelta,
				uint64_t guard
)
{
	int code = dserver_rpc_mach_port_destruct(target, name, srdelta, guard);

	if (code < 0) {
		__simple_printf("mach_port_destruct failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_guard_trap_impl(
				mach_port_name_t target,
				mach_port_name_t name,
				uint64_t guard,
				boolean_t strict
)
{
	int code = dserver_rpc_mach_port_guard(target, name, guard, strict);

	if (code < 0) {
		__simple_printf("mach_port_guard failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_unguard_trap_impl(
				mach_port_name_t target,
				mach_port_name_t name,
				uint64_t guard
)
{
	int code = dserver_rpc_mach_port_unguard(target, name, guard);

	if (code < 0) {
		__simple_printf("mach_port_unguard failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t thread_get_special_reply_port_impl(void)
{
	unsigned int port_name;
	if (dserver_rpc_thread_get_special_reply_port(&port_name) != 0) {
		port_name = MACH_PORT_NULL;
	}
	return port_name;
};

kern_return_t _kernelrpc_mach_port_request_notification_impl(
	ipc_space_t task,
	mach_port_name_t name,
	mach_msg_id_t msgid,
	mach_port_mscount_t sync,
	mach_port_name_t notify,
	mach_msg_type_name_t notifyPoly,
	mach_port_name_t* previous
)
{
	int code = dserver_rpc_mach_port_request_notification(task, name, msgid, sync, notify, notifyPoly, previous);

	if (code < 0) {
		__simple_printf("mach_port_request_notification failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
};

kern_return_t _kernelrpc_mach_port_get_attributes_impl(
	mach_port_name_t target,
	mach_port_name_t name,
	mach_port_flavor_t flavor,
	mach_port_info_t port_info_out,
	mach_msg_type_number_t* port_info_outCnt
)
{
	int code = dserver_rpc_mach_port_get_attributes(target, name, flavor, port_info_out, port_info_outCnt);

	if (code < 0) {
		__simple_printf("mach_port_get_attributes failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
};

kern_return_t _kernelrpc_mach_port_peek_impl(
	mach_port_name_t target,
	mach_port_name_t name,
	mach_msg_trailer_type_t trailer_type,
	mach_port_seqno_t* seqnop,
	mach_msg_size_t* msg_sizep,
	mach_msg_id_t* msg_idp,
	mach_msg_trailer_info_t trailer_infop,
	mach_msg_type_number_t* trailer_sizep
)
{
	int code = dserver_rpc_mach_port_peek(target, name, trailer_type,
	    seqnop, msg_sizep, msg_idp, trailer_infop, trailer_sizep);

	if (code < 0) {
		__simple_printf("mach_port_peek failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
};

kern_return_t _kernelrpc_mach_port_type_impl(
	ipc_space_t task,
	mach_port_name_t name,
	mach_port_type_t* ptype
)
{
	int code = dserver_rpc_mach_port_type(task, name, ptype);

	if (code < 0) {
		__simple_printf("mach_port_type failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
};

kern_return_t macx_swapon_impl(
				uint64_t filename,
				int flags,
				int size,
				int priority)
{
	UNIMPLEMENTED_TRAP();
	return KERN_FAILURE;
}

kern_return_t macx_swapoff_impl(
				uint64_t filename,
				int flags)
{
	UNIMPLEMENTED_TRAP();
	return KERN_FAILURE;
}

kern_return_t macx_triggers_impl(
				int hi_water,
				int low_water,
				int flags,
				mach_port_t alert_port)
{
	UNIMPLEMENTED_TRAP();
	return KERN_FAILURE;
}

kern_return_t macx_backing_store_suspend_impl(
				boolean_t suspend)
{
	UNIMPLEMENTED_TRAP();
	return KERN_FAILURE;
}

kern_return_t macx_backing_store_recovery_impl(
				int pid)
{
	UNIMPLEMENTED_TRAP();
	return KERN_FAILURE;
}

extern void __linux_sched_yield();
boolean_t swtch_pri_impl(int pri)
{
	__linux_sched_yield();
	return 0;
}

boolean_t swtch_impl(void)
{
	__linux_sched_yield();
	return 0;
}

extern int __linux_nanosleep(struct timespec* tv, struct timespec* rem);
kern_return_t syscall_thread_switch_impl(
				mach_port_name_t thread_name,
				int option,
				mach_msg_timeout_t option_time)
{
	struct timespec tv = {
		.tv_sec = 0,
		.tv_nsec = 1000000
	};
	// Sleep for 1ms
	__linux_nanosleep(&tv, &tv);

	// TODO: we could implement this with yield_to() in LKM
	return KERN_SUCCESS;
}

mach_port_name_t task_self_trap_impl(void)
{
	unsigned int port_name;
	if (dserver_rpc_task_self_trap(&port_name) != 0) {
		port_name = MACH_PORT_NULL;
	}
	return port_name;
}

/*
 *	Obsolete interfaces.
 */

kern_return_t task_for_pid_impl(
				mach_port_name_t target_tport,
				int pid,
				mach_port_name_t *t)
{
	int code = dserver_rpc_task_for_pid(target_tport, pid, t);

	if (code < 0) {
		__simple_printf("task_for_pid failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t task_name_for_pid_impl(
				mach_port_name_t target_tport,
				int pid,
				mach_port_name_t *tn)
{
	int code = dserver_rpc_task_name_for_pid(target_tport, pid, tn);

	if (code < 0) {
		__simple_printf("task_name_for_pid failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t pid_for_task_impl(
				mach_port_name_t t,
				int *x)
{
	int code = dserver_rpc_pid_for_task(t, x);

	if (code < 0) {
		__simple_printf("pid_for_task failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t mach_generate_activity_id_impl(mach_port_name_t task, int i, uint64_t* id)
{
	UNIMPLEMENTED_TRAP();
	return KERN_FAILURE;
}

mach_port_name_t mk_timer_create_impl(void)
{
	unsigned int port_name;
	if (dserver_rpc_mk_timer_create(&port_name) < 0) {
		port_name = MACH_PORT_NULL;
	}
	return port_name;
}

kern_return_t mk_timer_destroy_impl(mach_port_name_t name)
{
	int code = dserver_rpc_mk_timer_destroy(name);

	if (code < 0) {
		__simple_printf("mk_timer_destroy failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t mk_timer_arm_impl(mach_port_name_t name, uint64_t expire_time)
{
	int code = dserver_rpc_mk_timer_arm(name, expire_time);

	if (code < 0) {
		__simple_printf("mk_timer_arm failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t mk_timer_cancel_impl(mach_port_name_t name, uint64_t *result_time)
{
	int code = dserver_rpc_mk_timer_cancel(name, result_time);

	if (code < 0) {
		__simple_printf("mk_timer_cancel failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}
