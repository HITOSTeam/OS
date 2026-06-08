use super::*;
use spin::MutexGuard;

#[derive(Clone)]
pub struct MmRef {
    inner: Arc<Mutex<MemorySet>>,
}

impl MmRef {
    pub fn new(memory_set: MemorySet) -> Self {
        Self {
            inner: Arc::new(Mutex::new(memory_set)),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, MemorySet> {
        self.inner.lock()
    }

    pub fn token(&self) -> usize {
        self.lock().token()
    }

    pub fn alloc_trap_context_slot(&self) -> usize {
        self.lock().alloc_trap_context_slot()
    }

    pub fn reserve_trap_context_slot(&self, slot: usize) {
        self.lock().reserve_trap_context_slot(slot);
    }

    pub fn dealloc_trap_context_slot(&self, slot: usize) {
        self.lock().dealloc_trap_context_slot(slot);
    }

    pub fn has_writable_shared_memfd_mapping(&self, memfd_id: u64) -> bool {
        self.lock().has_writable_shared_memfd_mapping(memfd_id)
    }

    pub fn file_vm_copy_targets(
        &self,
        dev: usize,
        ino: u32,
        write_off: usize,
        len: usize,
    ) -> Vec<(usize, usize, usize)> {
        self.lock().file_vm_copy_targets(dev, ino, write_off, len)
    }

    pub fn update_file_vm_size(&self, dev: usize, ino: u32, file_size: usize) -> bool {
        self.lock().update_file_vm_size(dev, ino, file_size)
    }

    pub fn try_insert_stack_framed_range(
        &self,
        start: usize,
        end: usize,
        permission: MapPermission,
    ) -> bool {
        self.lock()
            .try_insert_stack_framed_range(start, end, permission)
    }

    pub fn unmap_user_vma_range(&self, start_va: VirtAddr, end_va: VirtAddr) {
        self.lock().unmap_user_vma_range(start_va, end_va);
    }

    pub fn cow_diag_stats(&self) -> (usize, usize, usize, usize, usize, usize) {
        self.lock().cow_diag_stats()
    }

    pub fn try_insert_framed_area(
        &self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
    ) -> bool {
        self.lock()
            .try_insert_framed_area(start_va, end_va, permission)
    }

    pub fn resolve_cow_fault(&self, fault_va: usize) -> bool {
        self.lock().resolve_cow_fault(fault_va)
    }

    pub fn resolve_lazy_fault(&self, fault_va: usize, access: MapPermission) -> LazyFaultResult {
        self.lock().resolve_lazy_fault(fault_va, access)
    }

    #[cfg(target_arch = "riscv64")]
    pub fn fault_hits_mmap_sigbus_tail(&self, addr: usize) -> bool {
        self.lock().fault_hits_mmap_sigbus_tail(addr)
    }

    pub fn try_expand_growsdown(&self, fault_va: usize, access: MapPermission) -> LazyFaultResult {
        self.lock().try_expand_growsdown(fault_va, access)
    }

    pub fn translate(&self, vpn: VirtPageNum) -> Option<PageTableEntry> {
        self.lock().translate(vpn)
    }

    pub fn remove_area_with_start_vpn(&self, start_va: VirtAddr) {
        self.lock().remove_area_with_start_vpn(start_va);
    }

    pub fn sysv_shm_attaches_snapshot(&self) -> Vec<ShmAttach> {
        self.lock().sysv_shm_attaches_snapshot()
    }

    pub fn replace_sysv_shm_attaches(&self, attaches: Vec<ShmAttach>) {
        self.lock().replace_sysv_shm_attaches(attaches);
    }

    pub fn take_sysv_shm_attaches_for_cleanup(&mut self) -> Option<Vec<ShmAttach>> {
        if Arc::strong_count(&self.inner) != 1 {
            return None;
        }
        Some(self.lock().take_sysv_shm_attaches())
    }

    pub fn from_existed_user_cow(parent: &Self) -> Self {
        let mut parent = parent.lock();
        Self::new(MemorySet::from_existed_user_cow(&mut parent))
    }

    #[cfg(target_arch = "loongarch64")]
    pub fn from_existed_user_deep(parent: &Self) -> Self {
        let parent = parent.lock();
        Self::new(MemorySet::from_existed_user(&parent))
    }
}
