#[cfg(target_arch = "riscv64")]
mod virtio_mmio {
    use super::super::async_queue::{AsyncBlockDiagnostics, AsyncVirtIOBlock};
    use alloc::vec;
    use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

    use core::ptr::NonNull;
    use ext4_fs::BlockDevice;
    use lazy_static::lazy_static;
    use spin::Mutex;
    use virtio_drivers::{
        BufferDirection, Hal,
        device::blk::VirtIOBlk,
        transport::{
            DeviceType, Transport,
            mmio::{MmioTransport, VirtIOHeader},
        },
    };

    use crate::{
        mm::{FrameTracker, PhysAddr, frame_alloc_contiguous},
        println,
    };

    const VIRTIO_MMIO_BASE: usize = 0x1000_1000;
    const VIRTIO_MMIO_STRIDE: usize = 0x1000;
    const VIRTIO_MMIO_SLOTS: usize = 8;

    pub struct VirtIOBlock {
        queue: AsyncVirtIOBlock<VirtioHal, MmioTransport>,
        irq: usize,
    }

    lazy_static! {
        static ref DMA_FRAMES: Mutex<BTreeMap<usize, Vec<FrameTracker>>> =
            Mutex::new(BTreeMap::new());
    }

    impl BlockDevice for VirtIOBlock {
        fn io_relax(&self) {
            if crate::task::processor::current_task().is_some() {
                crate::task::processor::suspend_current_and_run_next();
            } else {
                core::hint::spin_loop();
            }
        }

        fn read_block(&self, block_id: usize, buf: &mut [u8]) {
            self.read_blocks(block_id, buf);
        }
        fn write_block(&self, block_id: usize, buf: &[u8]) {
            self.write_blocks(block_id, buf);
        }
        fn read_blocks(&self, block_id: usize, buf: &mut [u8]) {
            assert_eq!(buf.len() % ext4_fs::BLOCK_SZ, 0);
            let sectors_per_block = ext4_fs::BLOCK_SZ / 512;
            let base_sector = block_id * sectors_per_block;
            let start = crate::perf::block_read_begin();
            // The virtio driver dereferences physical/direct-map DMA buffers.
            // RISC-V user page tables share only selected kernel roots, so enter
            // the full kernel page table around the MMIO driver call.
            let _kernel_pt = crate::mm::KernelPageTableGuard::enter();
            self.queue
                .read_blocks(base_sector, buf)
                .expect("Error when reading VirtIOBlk");
            crate::perf::block_read_end(start, buf.len());
        }
        fn write_blocks(&self, block_id: usize, buf: &[u8]) {
            assert_eq!(buf.len() % ext4_fs::BLOCK_SZ, 0);
            let sectors_per_block = ext4_fs::BLOCK_SZ / 512;
            let base_sector = block_id * sectors_per_block;
            let start = crate::perf::block_write_begin();
            // See read path: the driver must run with the kernel direct map active.
            let _kernel_pt = crate::mm::KernelPageTableGuard::enter();
            self.queue
                .write_blocks(base_sector, buf)
                .expect("Error when writing VirtIOBlk");
            crate::perf::block_write_end(start, buf.len());
        }
    }

    impl VirtIOBlock {
        #[allow(unused)]
        pub fn new() -> Self {
            Self::try_new_with_base(VIRTIO_MMIO_BASE).expect("VirtIO block device not found")
        }

        pub fn probe_all() -> Vec<Self> {
            (0..VIRTIO_MMIO_SLOTS)
                .filter_map(|index| {
                    Self::try_new_with_base(VIRTIO_MMIO_BASE + index * VIRTIO_MMIO_STRIDE)
                })
                .collect()
        }

        /// try to initalize a block device form the given address
        pub fn try_new_with_base(base: usize) -> Option<Self> {
            let header = NonNull::new(base as *mut VirtIOHeader)?;
            // SAFETY: base is the MMIO address from device tree or known constant;
            // header is a valid non-null pointer to VirtIOHeader.
            let transport = unsafe { MmioTransport::new(header) }.ok()?;
            if transport.device_type() != DeviceType::Block {
                return None;
            }
            let blk = VirtIOBlk::<VirtioHal, _>::new(transport).ok()?;
            let irq = (base.checked_sub(VIRTIO_MMIO_BASE)? / VIRTIO_MMIO_STRIDE) + 1;
            crate::arch::enable_external_irq(irq);
            println!("VirtIOBlock initialized at {:#x}, irq {}.", base, irq);
            Some(Self {
                queue: AsyncVirtIOBlock::new(blk),
                irq,
            })
        }

        pub fn handle_irq(&self, irq: usize) -> bool {
            if irq != self.irq {
                return false;
            }
            // Linux device interrupt handlers always run with kernel mappings
            // active.  Keep that invariant at the driver boundary as well as
            // at the PLIC entry so future dispatch paths cannot touch VirtIO
            // MMIO or DMA buffers through a user page table.
            let _kernel_pt = crate::mm::KernelPageTableGuard::enter();
            self.queue.handle_interrupt()
        }

        pub fn poll(&self) {
            // Timer/watchdog fallback polling can run directly from a user
            // trap, where this kernel deliberately retains the user SATP.
            // Linux's block polling path still executes in kernel address
            // space, so switch before acknowledging MMIO or draining DMA.
            let _kernel_pt = crate::mm::KernelPageTableGuard::enter();
            self.queue.poll();
        }

        pub fn diagnostics(&self) -> AsyncBlockDiagnostics {
            self.queue.diagnostics()
        }
    }

    pub struct VirtioHal;

    unsafe impl Hal for VirtioHal {
        fn dma_alloc(pages: usize, _direction: BufferDirection) -> (usize, NonNull<u8>) {
            assert_ne!(pages, 0);
            let frames = frame_alloc_contiguous(pages).expect("VirtIO DMA: OOM");
            let paddr: PhysAddr = frames[0].ppn.into();
            let paddr = paddr.0;
            DMA_FRAMES.lock().insert(paddr, frames);
            (paddr, NonNull::new(paddr as *mut u8).unwrap())
        }

        unsafe fn dma_dealloc(paddr: usize, _vaddr: NonNull<u8>, _pages: usize) -> i32 {
            if DMA_FRAMES.lock().remove(&paddr).is_some() {
                0
            } else {
                -1
            }
        }

        unsafe fn mmio_phys_to_virt(paddr: usize, _size: usize) -> NonNull<u8> {
            NonNull::new(paddr as *mut u8).unwrap()
        }

        unsafe fn share(buffer: NonNull<[u8]>, direction: BufferDirection) -> usize {
            assert_ne!(buffer.len(), 0);
            let mut shared = vec![0u8; buffer.len()].into_boxed_slice();
            if let BufferDirection::DriverToDevice | BufferDirection::Both = direction {
                unsafe {
                    let src =
                        core::slice::from_raw_parts(buffer.as_ptr() as *const u8, buffer.len());
                    core::ptr::copy_nonoverlapping(src.as_ptr(), shared.as_mut_ptr(), buffer.len());
                }
            }
            Box::into_raw(shared) as *mut u8 as usize
        }

        unsafe fn unshare(paddr: usize, buffer: NonNull<[u8]>, direction: BufferDirection) {
            assert_ne!(buffer.len(), 0);
            if let BufferDirection::DeviceToDriver | BufferDirection::Both = direction {
                unsafe {
                    let src = core::slice::from_raw_parts(paddr as *const u8, buffer.len());
                    let dst =
                        core::slice::from_raw_parts_mut(buffer.as_ptr() as *mut u8, buffer.len());
                    dst.copy_from_slice(src);
                }
            }
            unsafe {
                let _shared = Box::from_raw(core::ptr::slice_from_raw_parts_mut(
                    paddr as *mut u8,
                    buffer.len(),
                ));
            }
        }
    }
}

#[cfg(target_arch = "loongarch64")]
mod virtio_pci {
    use super::super::async_queue::{AsyncBlockDiagnostics, AsyncVirtIOBlock};
    use crate::{
        config::{DEVICE_TREE_ADDR, PAGE_SIZE, phys_mem_end, phys_mem_start},
        mm::{
            FrameTracker, KERNEL_SPACE, MapPermission, PTEFlags, PhysAddr, VirtAddr,
            frame_alloc_contiguous,
        },
        println,
    };
    use alloc::vec;
    use alloc::{
        boxed::Box,
        collections::{BTreeMap, BTreeSet},
        vec::Vec,
    };
    use core::{
        ptr::NonNull,
        sync::atomic::{AtomicBool, Ordering},
    };
    use ext4_fs::BlockDevice;
    use fdt::{Fdt, node::FdtNode};
    use lazy_static::lazy_static;
    use spin::Mutex;
    use virtio_drivers::{
        BufferDirection, Hal,
        device::blk::VirtIOBlk,
        transport::{
            DeviceType,
            pci::{
                PciTransport,
                bus::{BarInfo, Cam, Command, DeviceFunction, MemoryBarType, PciRoot},
                virtio_device_type,
            },
        },
    };

    static PCI_ECAM_MAPPED: AtomicBool = AtomicBool::new(false);
    const FORCE_DMA_CACHEABLE: bool = true;

    pub struct VirtIOBlock {
        queue: AsyncVirtIOBlock<HalImpl, PciTransport>,
        irq: usize,
    }

    lazy_static! {
        static ref DMA_FRAMES: Mutex<BTreeMap<usize, Vec<FrameTracker>>> =
            Mutex::new(BTreeMap::new());
        static ref PCI_ALLOCATOR: Mutex<Option<PciMemory32Allocator>> = Mutex::new(None);
        static ref ALLOCATED_BARS: Mutex<BTreeSet<(u8, u8, u8)>> = Mutex::new(BTreeSet::new());
    }

    pub struct HalImpl;

    fn direct_dma_ok(vaddr: usize, len: usize) -> bool {
        if len == 0 {
            return false;
        }
        let end = match vaddr.checked_add(len) {
            Some(v) => v,
            None => return false,
        };
        vaddr >= phys_mem_start() && end <= phys_mem_end()
    }

    fn set_dma_page_flags(paddr: usize, pages: usize, io: bool) {
        if FORCE_DMA_CACHEABLE {
            return;
        }
        let perm = if io {
            MapPermission::R | MapPermission::W | MapPermission::IO
        } else {
            MapPermission::R | MapPermission::W
        };
        let flags = PTEFlags::from(perm);
        let mut kernel_space = KERNEL_SPACE.lock();
        for i in 0..pages {
            let vpn = VirtAddr::from(paddr + i * PAGE_SIZE).floor();
            let _ = kernel_space.set_pte_flags(vpn, flags);
        }
    }

    unsafe impl Hal for HalImpl {
        fn dma_alloc(pages: usize, _direction: BufferDirection) -> (usize, NonNull<u8>) {
            assert_ne!(pages, 0);
            let frames = frame_alloc_contiguous(pages).expect("VirtIO DMA: OOM");
            let paddr: PhysAddr = frames[0].ppn.into();
            let paddr = paddr.0;
            set_dma_page_flags(paddr, pages, true);
            DMA_FRAMES.lock().insert(paddr, frames);
            (paddr, NonNull::new(paddr as *mut u8).unwrap())
        }

        unsafe fn dma_dealloc(paddr: usize, _vaddr: NonNull<u8>, pages: usize) -> i32 {
            assert_ne!(pages, 0);
            if DMA_FRAMES.lock().remove(&paddr).is_some() {
                set_dma_page_flags(paddr, pages, false);
                0
            } else {
                -1
            }
        }

        unsafe fn mmio_phys_to_virt(paddr: usize, _size: usize) -> NonNull<u8> {
            NonNull::new(phys_to_virt(paddr) as *mut u8).unwrap()
        }

        unsafe fn share(buffer: NonNull<[u8]>, direction: BufferDirection) -> usize {
            assert_ne!(buffer.len(), 0);
            let vaddr = buffer.as_ptr() as *const u8 as usize;
            if direct_dma_ok(vaddr, buffer.len()) {
                return vaddr;
            }
            let mut shared = vec![0u8; buffer.len()].into_boxed_slice();
            if let BufferDirection::DriverToDevice | BufferDirection::Both = direction {
                // SAFETY: buffer is a valid non-null slice; shared has the same length;
                // both pointers are valid for copy_nonoverlapping.
                unsafe {
                    let src =
                        core::slice::from_raw_parts(buffer.as_ptr() as *const u8, buffer.len());
                    core::ptr::copy_nonoverlapping(src.as_ptr(), shared.as_mut_ptr(), buffer.len());
                }
            }
            Box::into_raw(shared) as *mut u8 as usize
        }

        unsafe fn unshare(paddr: usize, buffer: NonNull<[u8]>, direction: BufferDirection) {
            assert_ne!(buffer.len(), 0);
            assert_ne!(paddr, 0);
            let vaddr = buffer.as_ptr() as *const u8 as usize;
            if direct_dma_ok(vaddr, buffer.len()) {
                return;
            }
            if let BufferDirection::DeviceToDriver | BufferDirection::Both = direction {
                // SAFETY: `paddr` names the bounce buffer allocated by `share`,
                // and `buffer` is the original non-null slice of the same length.
                unsafe {
                    let src = core::slice::from_raw_parts(paddr as *const u8, buffer.len());
                    let dst =
                        core::slice::from_raw_parts_mut(buffer.as_ptr() as *mut u8, buffer.len());
                    dst.copy_from_slice(src);
                }
            }
            // SAFETY: `paddr` was produced by `Box::into_raw` in `share`, with
            // this exact slice length, and this is its single matching release.
            let _shared = unsafe {
                Box::from_raw(core::ptr::slice_from_raw_parts_mut(
                    paddr as *mut u8,
                    buffer.len(),
                ))
            };
        }
    }

    fn phys_to_virt(paddr: usize) -> usize {
        paddr
    }

    impl BlockDevice for VirtIOBlock {
        fn io_relax(&self) {
            if crate::task::processor::current_task().is_some() {
                crate::task::processor::suspend_current_and_run_next();
            } else {
                core::hint::spin_loop();
            }
        }

        fn read_block(&self, block_id: usize, buf: &mut [u8]) {
            self.read_blocks(block_id, buf);
        }
        fn write_block(&self, block_id: usize, buf: &[u8]) {
            self.write_blocks(block_id, buf);
        }
        fn read_blocks(&self, block_id: usize, buf: &mut [u8]) {
            assert_eq!(buf.len() % ext4_fs::BLOCK_SZ, 0);
            let sectors_per_block = ext4_fs::BLOCK_SZ / 512;
            let base_sector = block_id * sectors_per_block;
            let start = crate::perf::block_read_begin();
            self.queue
                .read_blocks(base_sector, buf)
                .expect("Error when reading VirtIOBlk");
            crate::perf::block_read_end(start, buf.len());
        }
        fn write_blocks(&self, block_id: usize, buf: &[u8]) {
            assert_eq!(buf.len() % ext4_fs::BLOCK_SZ, 0);
            let sectors_per_block = ext4_fs::BLOCK_SZ / 512;
            let base_sector = block_id * sectors_per_block;
            let start = crate::perf::block_write_begin();
            self.queue
                .write_blocks(base_sector, buf)
                .expect("Error when writing VirtIOBlk");
            crate::perf::block_write_end(start, buf.len());
        }
    }

    /// Allocates 32-bit memory addresses for PCI BARs.
    struct PciMemory32Allocator {
        start: u32,
        end: u32,
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    enum PciRangeType {
        ConfigurationSpace,
        IoSpace,
        Memory32,
        Memory64,
    }

    impl From<u8> for PciRangeType {
        fn from(value: u8) -> Self {
            match value {
                0 => Self::ConfigurationSpace,
                1 => Self::IoSpace,
                2 => Self::Memory32,
                3 => Self::Memory64,
                _ => panic!("invalid PCI range type {}", value),
            }
        }
    }

    impl PciMemory32Allocator {
        fn for_pci_ranges(pci_node: &FdtNode) -> Self {
            let ranges = pci_node
                .property("ranges")
                .expect("PCI node missing ranges property.");
            let mut memory_32_address = 0;
            let mut memory_32_size = 0;
            for i in 0..ranges.value.len() / 28 {
                let range = &ranges.value[i * 28..(i + 1) * 28];
                let prefetchable = range[0] & 0x80 != 0;
                let range_type = PciRangeType::from(range[0] & 0x3);
                let cpu_physical = u64::from_be_bytes(range[12..20].try_into().unwrap());
                let bus_address = u64::from_be_bytes(range[4..12].try_into().unwrap());
                let size = u64::from_be_bytes(range[20..28].try_into().unwrap());
                if !prefetchable
                    && matches!(range_type, PciRangeType::Memory32 | PciRangeType::Memory64)
                    && size > memory_32_size.into()
                    && bus_address + size < u32::MAX.into()
                {
                    memory_32_address = u32::try_from(cpu_physical).unwrap();
                    memory_32_size = u32::try_from(size).unwrap();
                }
            }
            if memory_32_size == 0 {
                panic!("no 32-bit PCI memory region found");
            }
            Self {
                start: memory_32_address,
                end: memory_32_address + memory_32_size,
            }
        }

        fn allocate_memory_32(&mut self, size: u32) -> u32 {
            debug_assert!(size.is_power_of_two());
            let allocated_address = align_up(self.start, size);
            debug_assert!(allocated_address + size <= self.end);
            self.start = allocated_address + size;
            allocated_address
        }
    }

    const fn align_up(value: u32, alignment: u32) -> u32 {
        ((value - 1) | (alignment - 1)) + 1
    }

    fn allocate_bars(
        root: &mut PciRoot,
        device_function: DeviceFunction,
        allocator: &mut PciMemory32Allocator,
    ) {
        let mut bar_index = 0u8;
        while bar_index < 6 {
            let info = match root.bar_info(device_function, bar_index) {
                Ok(info) => info,
                Err(_) => {
                    bar_index += 1;
                    continue;
                }
            };
            if let BarInfo::Memory {
                address_type, size, ..
            } = info.clone()
            {
                if size == 0 {
                    bar_index += 1;
                    continue;
                }
                match address_type {
                    MemoryBarType::Width32 => {
                        let address = allocator.allocate_memory_32(size);
                        root.set_bar_32(device_function, bar_index, address);
                    }
                    MemoryBarType::Width64 => {
                        let address = allocator.allocate_memory_32(size);
                        root.set_bar_64(device_function, bar_index, address.into());
                    }
                    _ => panic!("unsupported memory BAR address type {:?}", address_type),
                }
            }
            bar_index += if info.takes_two_entries() { 2 } else { 1 };
        }

        root.set_command(
            device_function,
            Command::IO_SPACE | Command::MEMORY_SPACE | Command::BUS_MASTER,
        );
    }

    fn map_identical_range(start: usize, size: usize) {
        if size == 0 {
            return;
        }
        let end = start.saturating_add(size);
        let mut kernel_space = KERNEL_SPACE.lock();
        kernel_space.map_identical_range_skip_mapped(
            start,
            end,
            MapPermission::R | MapPermission::W | MapPermission::IO,
        );
    }

    fn log_pci_range(label: &str, start: usize, size: usize) {
        let end = start.saturating_add(size);
        let mem_start = phys_mem_start();
        let mem_end = phys_mem_end();
        println!(
            "[virtio_pci] {} [{:#x}, {:#x}) size={:#x}",
            label, start, end, size
        );
        if start < mem_end && end > mem_start {
            println!(
                "[virtio_pci][warn] {} overlaps RAM [{:#x}, {:#x})",
                label, mem_start, mem_end
            );
        }
    }

    fn map_device_bars(root: &mut PciRoot, device_function: DeviceFunction) {
        let mut bar_index = 0u8;
        while bar_index < 6 {
            let info = match root.bar_info(device_function, bar_index) {
                Ok(info) => info,
                Err(_) => {
                    bar_index += 1;
                    continue;
                }
            };
            if let Some((addr, size)) = info.memory_address_size() {
                log_pci_range("PCI BAR", addr as usize, size as usize);
                map_identical_range(addr as usize, size as usize);
            }
            bar_index += if info.takes_two_entries() { 2 } else { 1 };
        }
    }

    fn ensure_pci_allocator(pci_node: &FdtNode) {
        let mut allocator = PCI_ALLOCATOR.lock();
        if allocator.is_none() {
            *allocator = Some(PciMemory32Allocator::for_pci_ranges(pci_node));
        }
    }

    fn ensure_pci_ecam_mapped(pci_node: &FdtNode) {
        if PCI_ECAM_MAPPED.load(Ordering::SeqCst) {
            return;
        }
        let mut mapped = false;
        if let Some(reg) = pci_node.reg() {
            for region in reg {
                if let Some(size) = region.size {
                    log_pci_range("PCI ECAM", region.starting_address as usize, size);
                    map_identical_range(region.starting_address as usize, size);
                    mapped = true;
                }
            }
        }
        if mapped {
            PCI_ECAM_MAPPED.store(true, Ordering::SeqCst);
        }
    }

    fn virtio_blk_pci(transport: PciTransport, irq: usize) -> VirtIOBlock {
        let blk = VirtIOBlk::<HalImpl, PciTransport>::new(transport)
            .expect("failed to create virtio block driver");
        crate::arch::enable_external_irq(irq);
        VirtIOBlock {
            queue: AsyncVirtIOBlock::new(blk),
            irq,
        }
    }

    impl VirtIOBlock {
        pub fn new() -> Self {
            Self::try_new_with_index(0).expect("VirtIO block device not found")
        }

        pub fn probe_all() -> Vec<Self> {
            let mut devices = Vec::new();
            for index in 0..26 {
                let Some(device) = Self::try_new_with_index(index) else {
                    break;
                };
                devices.push(device);
            }
            devices
        }

        fn try_new_with_index(index: usize) -> Option<Self> {
            // SAFETY: DEVICE_TREE_ADDR is the FDT address passed by bootloader; valid during init.
            let fdt = unsafe { Fdt::from_ptr(DEVICE_TREE_ADDR as *const u8).ok()? };
            let pci_node = fdt.find_compatible(&["pci-host-ecam-generic"])?;
            ensure_pci_ecam_mapped(&pci_node);
            ensure_pci_allocator(&pci_node);
            let reg = pci_node.reg()?;
            for region in reg {
                // SAFETY: region.starting_address is the ECAM base from FDT; mapped by ensure_pci_ecam_mapped.
                let mut pci_root =
                    unsafe { PciRoot::new(region.starting_address as *mut u8, Cam::Ecam) };
                let mut blk_index = 0usize;
                for (device_function, info) in pci_root.enumerate_bus(0) {
                    let Some(virtio_type) = virtio_device_type(&info) else {
                        continue;
                    };
                    if virtio_type != DeviceType::Block {
                        continue;
                    }
                    let device_key = (
                        device_function.bus,
                        device_function.device,
                        device_function.function,
                    );
                    let need_alloc = {
                        let mut allocated = ALLOCATED_BARS.lock();
                        if allocated.contains(&device_key) {
                            false
                        } else {
                            allocated.insert(device_key);
                            true
                        }
                    };
                    if need_alloc {
                        let mut allocator = PCI_ALLOCATOR.lock();
                        let allocator = allocator.as_mut().expect("PCI allocator not initialized");
                        allocate_bars(&mut pci_root, device_function, allocator);
                    }
                    map_device_bars(&mut pci_root, device_function);
                    if blk_index == index {
                        let pin = pci_root.interrupt_pin(device_function);
                        if !(1..=4).contains(&pin) {
                            println!(
                                "[virtio_pci] invalid INTx pin {} for {}, skipping",
                                pin, device_function
                            );
                            return None;
                        }
                        // QEMU's LoongArch virt host bridge follows the PCI
                        // INTx swizzle encoded by its FDT interrupt-map:
                        // input = 16 + (device + pin - 1) mod 4.
                        let irq =
                            16 + (usize::from(device_function.device) + usize::from(pin) - 1) % 4;
                        let transport =
                            PciTransport::new::<HalImpl>(&mut pci_root, device_function).ok()?;
                        println!(
                            "[virtio_pci] block {} pin {} routed to irq {}",
                            device_function, pin, irq
                        );
                        return Some(virtio_blk_pci(transport, irq));
                    }
                    blk_index += 1;
                }
            }
            None
        }

        pub fn handle_irq(&self, irq: usize) -> bool {
            irq == self.irq && self.queue.handle_interrupt()
        }

        pub fn poll(&self) {
            self.queue.poll();
        }

        pub fn diagnostics(&self) -> AsyncBlockDiagnostics {
            self.queue.diagnostics()
        }
    }
}

#[cfg(target_arch = "riscv64")]
pub use virtio_mmio::VirtIOBlock;
#[cfg(target_arch = "loongarch64")]
pub use virtio_pci::VirtIOBlock;
