//! memoryset 多进程、多线程包装。
use super::*;
use crate::sync::{KernelMutex, KernelMutexGuard};
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicUsize, Ordering};

/// Linux exposes `vm_committed_as` through a percpu counter instead of walking
/// every task and taking every `mmap_lock` on each `/proc/meminfo` read.  A
/// single relaxed counter is sufficient for this smaller kernel.
static VM_COMMITTED_BYTES: AtomicUsize = AtomicUsize::new(0);

struct MmState {
    memory_set: KernelMutex<MemorySet>,
    committed_bytes: AtomicUsize,
}

impl MmState {
    fn new(memory_set: MemorySet) -> Self {
        let committed_bytes = memory_set.committed_vm_bytes();
        VM_COMMITTED_BYTES.fetch_add(committed_bytes, Ordering::Relaxed);
        Self {
            memory_set: KernelMutex::new(memory_set),
            committed_bytes: AtomicUsize::new(committed_bytes),
        }
    }

    fn update_committed_bytes(&self, committed_bytes: usize) {
        let previous = self.committed_bytes.load(Ordering::Relaxed);
        if committed_bytes == previous {
            return;
        }
        self.committed_bytes
            .store(committed_bytes, Ordering::Relaxed);
        if committed_bytes >= previous {
            VM_COMMITTED_BYTES.fetch_add(committed_bytes - previous, Ordering::Relaxed);
        } else {
            VM_COMMITTED_BYTES.fetch_sub(previous - committed_bytes, Ordering::Relaxed);
        }
    }
}

impl Drop for MmState {
    fn drop(&mut self) {
        VM_COMMITTED_BYTES.fetch_sub(
            self.committed_bytes.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
    }
}

pub struct MmGuard<'a> {
    guard: KernelMutexGuard<'a, MemorySet>,
    state: &'a MmState,
}

impl Deref for MmGuard<'_> {
    type Target = MemorySet;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl DerefMut for MmGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl Drop for MmGuard<'_> {
    fn drop(&mut self) {
        self.state
            .update_committed_bytes(self.guard.committed_vm_bytes());
    }
}

#[derive(Clone)]
pub struct MmRef {
    /// Linux protects the VMA tree with `mm_struct::mmap_lock`, a sleeping
    /// rwsem.  MemorySet is still serialized exclusively for now, but it must
    /// likewise sleep under contention: mmap and file-backed fault paths may
    /// block on I/O while the address-space lock is held.
    inner: Arc<MmState>,
    /// Serialize only the rare slow retry path after repeated optimistic fault
    /// commit races. Normal faults never acquire this lock.
    pub(super) fault_retry_lock: Arc<crate::sync::KernelMutex<()>>,
    /// Stable page-table token cached outside the large mm lock. Trap return
    /// uses this on the hot path; page-table root replacement creates a new
    /// MmRef instead of mutating the token in place.
    token: usize,
    /// ASID ownership is tied to the address space lifetime, not to transient
    /// MemorySet locks. Cloned MmRef handles therefore share the same context.
    #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
    asid: Arc<AsidContext>,
}

impl MmRef {
    /// 将 MemorySet 包装为 MmRef（用于进程创建时）。
    pub fn new(memory_set: MemorySet) -> Self {
        let token = memory_set.token();
        #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
        let asid = Arc::clone(&memory_set.asid);
        Self {
            inner: Arc::new(MmState::new(memory_set)),
            fault_retry_lock: Arc::new(crate::sync::KernelMutex::new(())),
            token,
            #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
            asid,
        }
    }

    /// 获取 MemorySet 的互斥锁守卫。
    pub fn lock(&self) -> MmGuard<'_> {
        MmGuard {
            guard: self.inner.memory_set.lock(),
            state: self.inner.as_ref(),
        }
    }

    /// Current system-wide committed address-space bytes.
    pub fn global_committed_bytes() -> usize {
        VM_COMMITTED_BYTES.load(Ordering::Relaxed)
    }

    /// 返回页表根地址 token（用于切换地址空间）。
    pub fn token(&self) -> usize {
        self.token
    }

    #[cfg(target_arch = "loongarch64")]
    pub fn prepare_user_asid(&self) -> (usize, bool) {
        crate::arch::loongarch64::mm::prepare_user_asid(self.asid.as_ref())
    }

    #[cfg(target_arch = "loongarch64")]
    pub fn leave_user_asid(&self) {
        crate::arch::loongarch64::mm::leave_user_asid(self.asid.as_ref());
    }

    #[cfg(target_arch = "riscv64")]
    pub fn prepare_user_satp(&self) -> (usize, bool, bool) {
        crate::arch::riscv64::mm::prepare_user_satp(&self.asid, self.token)
    }

    #[cfg(target_arch = "loongarch64")]
    pub(super) fn flush_user_page(&self, va: usize) {
        crate::arch::loongarch64::mm::flush_user_page(&self.asid, va);
    }

    #[cfg(target_arch = "riscv64")]
    pub(super) fn flush_user_page(&self, va: usize) {
        crate::arch::riscv64::mm::flush_user_page(&self.asid, va);
    }

    #[cfg(target_arch = "riscv64")]
    pub fn leave_user_satp(&self) {
        crate::arch::riscv64::mm::leave_user_satp(self.asid.as_ref());
    }

    /// 为新线程分配 TrapContext 槽位，返回槽号。
    pub fn alloc_trap_context_slot(&self) -> usize {
        self.lock().alloc_trap_context_slot()
    }

    /// 预留指定 TrapContext 槽位（exec 复用已有槽号时使用）。
    pub fn reserve_trap_context_slot(&self, slot: usize) {
        self.lock().reserve_trap_context_slot(slot);
    }

    /// 释放 TrapContext 槽位（线程退出时调用）。
    pub fn dealloc_trap_context_slot(&self, slot: usize) {
        self.lock().dealloc_trap_context_slot(slot);
    }

    /// 检查是否存在对指定 memfd 的可写共享映射（F_SEAL_WRITE 检查）。
    pub fn has_writable_shared_memfd_mapping(&self, memfd_id: u64) -> bool {
        self.lock().has_writable_shared_memfd_mapping(memfd_id)
    }

    /// 返回需要将 fd write 数据镜像到用户内存的 (va, src_offset, len) 列表。
    pub fn file_vm_copy_targets(
        &self,
        dev: usize,
        ino: u32,
        write_off: usize,
        len: usize,
    ) -> Vec<(usize, usize, usize)> {
        self.lock().file_vm_copy_targets(dev, ino, write_off, len)
    }

    /// 文件大小变化后同步所有映射了该文件的 VMA（更新 sigbus_start 等）。
    pub fn update_file_vm_size(&self, dev: usize, ino: u32, file_size: usize) -> bool {
        self.lock().update_file_vm_size(dev, ino, file_size)
    }

    /// fd write 后将数据镜像到所有共享文件映射的驻留页。
    pub fn mirror_shared_file_write_to_resident_mmaps(
        &self,
        dev: usize,
        ino: u32,
        write_off: usize,
        data: &[u8],
    ) {
        self.lock()
            .mirror_shared_file_write_to_resident_mmaps(dev, ino, write_off, data);
    }

    /// 为栈区插入 Framed 映射（exec 时建立初始栈使用）。
    pub fn try_insert_stack_framed_range(
        &self,
        start: usize,
        end: usize,
        permission: MapPermission,
    ) -> bool {
        self.lock()
            .try_insert_stack_framed_range(start, end, permission)
    }

    /// 解除 [start_va, end_va) 内的用户 VMA 映射。
    pub fn unmap_user_vma_range(&self, start_va: VirtAddr, end_va: VirtAddr) {
        self.lock().unmap_user_vma_range(start_va, end_va);
    }

    /// 返回 fork/COW 内存压力诊断统计。
    pub fn cow_diag_stats(&self) -> (usize, usize, usize, usize, usize, usize) {
        self.lock().cow_diag_stats()
    }

    /// 插入一段 Framed 映射（立即分配物理帧）。
    pub fn try_insert_framed_area(
        &self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
    ) -> bool {
        self.lock()
            .try_insert_framed_area(start_va, end_va, permission)
    }

    /// 检查 addr 是否落在文件映射的 SIGBUS tail 区。
    #[cfg(target_arch = "riscv64")]
    pub fn fault_hits_mmap_sigbus_tail(&self, addr: usize) -> bool {
        self.lock().fault_hits_mmap_sigbus_tail(addr)
    }

    /// 查询 vpn 对应的页表项。
    pub fn translate(&self, vpn: VirtPageNum) -> Option<PageTableEntry> {
        self.lock().translate(vpn)
    }

    pub(crate) fn try_pin_user_buffer(
        &self,
        ptr: *const u8,
        len: usize,
        access: MapPermission,
    ) -> Result<UserBuffer, ()> {
        self.lock().try_pin_user_buffer(ptr, len, access)
    }

    /// 删除以 start_va 为起始地址的 MapArea。
    pub fn remove_area_with_start_vpn(&self, start_va: VirtAddr) {
        self.lock().remove_area_with_start_vpn(start_va);
    }

    /// 返回当前 SysV shm attach 列表的快照。
    pub fn sysv_shm_attaches_snapshot(&self) -> Vec<ShmAttach> {
        self.lock().sysv_shm_attaches_snapshot()
    }

    /// 替换 SysV shm attach 列表（MAP_FIXED 覆盖 shm 时更新）。
    pub fn replace_sysv_shm_attaches(&self, attaches: Vec<ShmAttach>) {
        self.lock().replace_sysv_shm_attaches(attaches);
    }

    /// 仅当本 MmRef 是最后一个持有者时，取出 SysV shm attach 列表供清理。
    /// 多个引用者（多线程）时返回 None，避免重复释放。
    pub fn take_sysv_shm_attaches_for_cleanup(&mut self) -> Option<Vec<ShmAttach>> {
        if Arc::strong_count(&self.inner) != 1 {
            return None;
        }
        Some(self.lock().take_sysv_shm_attaches())
    }

    /// fork：以 COW 方式克隆父进程地址空间，子进程与父进程共享物理页直到写操作。
    pub fn from_existed_user_cow(parent: &Self) -> Result<Self, ()> {
        let mut parent = parent.lock();
        MemorySet::from_existed_user_cow(&mut parent).map(Self::new)
    }

    /// fork（LoongArch）：深拷贝父进程地址空间（不使用 COW）。
    #[cfg(target_arch = "loongarch64")]
    pub fn from_existed_user_deep(parent: &Self) -> Self {
        let parent = parent.lock();
        Self::new(MemorySet::from_existed_user(&parent))
    }
}
