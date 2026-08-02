#[cfg(target_arch = "riscv64")]
mod virtio_mmio {
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

    const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;
    const VIRTIO_MMIO_LEGACY_VERSION: u32 = 1;
    const VIRTIO_MMIO_MODERN_VERSION: u32 = 2;
    const VIRTIO_DEVICE_ID_BLOCK: u32 = 2;
    pub struct VirtIOBlock(Mutex<VirtIOBlk<VirtioHal, MmioTransport>>);

    lazy_static! {
        static ref DMA_FRAMES: Mutex<BTreeMap<usize, Vec<FrameTracker>>> =
            Mutex::new(BTreeMap::new());
    }

    impl BlockDevice for VirtIOBlock {
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
            self.0
                .lock()
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
            self.0
                .lock()
                .write_blocks(base_sector, buf)
                .expect("Error when writing VirtIOBlk");
            crate::perf::block_write_end(start, buf.len());
        }
    }

    impl VirtIOBlock {
        #[allow(unused)]
        pub fn new() -> Self {
            Self::try_new_with_index(0).expect("VirtIO block device not found")
        }

        #[allow(unused)]
        pub fn try_new_second() -> Option<Self> {
            Self::try_new_with_index(1)
        }

        /// 按块设备序号从已发布的 DTB virtio-mmio 资源中选址。
        fn try_new_with_index(index: usize) -> Option<Self> {
            Self::block_device_base_from_dtb(index).and_then(Self::try_new_with_base)
        }

        /// 返回 DTB 中第 `index` 个经寄存器验证的 virtio-mmio 块设备基址。
        fn block_device_base_from_dtb(index: usize) -> Option<usize> {
            let mut bases = Vec::new();
            crate::arch::DTB_data::for_each_virtio_mmio_device(|base, _| {
                if Self::is_block_device(base) {
                    bases.push(base);
                }
            });
            bases.sort_unstable();
            bases.get(index).copied()
        }

        /// 通过 virtio-mmio 头部的 magic、version 和 device id 验证块设备。
        fn is_block_device(base: usize) -> bool {
            let regs = base as *const u32;
            unsafe {
                let magic = core::ptr::read_volatile(regs.add(0));
                let version = core::ptr::read_volatile(regs.add(1));
                let device_id = core::ptr::read_volatile(regs.add(2));
                magic == VIRTIO_MMIO_MAGIC
                    && matches!(
                        version,
                        VIRTIO_MMIO_LEGACY_VERSION | VIRTIO_MMIO_MODERN_VERSION
                    )
                    && device_id == VIRTIO_DEVICE_ID_BLOCK
            }
        }

        pub fn try_new_with_base(base: usize) -> Option<Self> {
            let header = NonNull::new(base as *mut VirtIOHeader)?;
            // 安全性：base 来自已发布的 DTB virtio-mmio 节点，且 header 非空。
            let transport = unsafe { MmioTransport::new(header) }.ok()?;
            if transport.device_type() != DeviceType::Block {
                return None;
            }
            let blk = VirtIOBlk::<VirtioHal, _>::new(transport).ok()?;
            println!("VirtIOBlock initialized at {:#x}.", base);
            Some(Self(Mutex::new(blk)))
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
    use crate::{
        arch::DTB_data::{self, PciHostInfo},
        config::{PAGE_SIZE, phys_range_in_ram},
        mm::{
            FrameTracker, KERNEL_SPACE, MapPermission, PTEFlags, PhysAddr, VirtAddr,
            frame_alloc_contiguous,
        },
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

    pub struct VirtIOBlock(Mutex<VirtIOBlk<HalImpl, PciTransport>>);

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
        phys_range_in_ram(vaddr, len)
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
            // SAFETY: paddr 来自 share 中同长度的 Box<[u8]>；buffer 在调用期间
            // 保持有效且与该临时缓冲区不重叠，最后用原始切片指针恢复所有权。
            unsafe {
                if let BufferDirection::DeviceToDriver | BufferDirection::Both = direction {
                    let src = core::slice::from_raw_parts(paddr as *const u8, buffer.len());
                    let dst =
                        core::slice::from_raw_parts_mut(buffer.as_ptr() as *mut u8, buffer.len());
                    dst.copy_from_slice(src);
                }
                drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(
                    paddr as *mut u8,
                    buffer.len(),
                )));
            }
        }
    }

    fn phys_to_virt(paddr: usize) -> usize {
        paddr
    }

    impl BlockDevice for VirtIOBlock {
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
            self.0
                .lock()
                .read_blocks(base_sector, buf)
                .expect("Error when reading VirtIOBlk");
            crate::perf::block_read_end(start, buf.len());
        }
        fn write_blocks(&self, block_id: usize, buf: &[u8]) {
            assert_eq!(buf.len() % ext4_fs::BLOCK_SZ, 0);
            let sectors_per_block = ext4_fs::BLOCK_SZ / 512;
            let base_sector = block_id * sectors_per_block;
            let start = crate::perf::block_write_begin();
            self.0
                .lock()
                .write_blocks(base_sector, buf)
                .expect("Error when writing VirtIOBlk");
            crate::perf::block_write_end(start, buf.len());
        }
    }

    /// 为 PCI BAR 分配 32 位内存地址。
    struct PciMemory32Allocator {
        start: u64,
        end: u64,
    }

    impl PciMemory32Allocator {
        fn for_pci_host(pci_host: PciHostInfo) -> Self {
            let start = u64::try_from(pci_host.mem32_base)
                .expect("DTB PCI memory aperture base exceeds u64");
            let end = start
                .checked_add(
                    u64::try_from(pci_host.mem32_size)
                        .expect("DTB PCI memory aperture size exceeds u64"),
                )
                .expect("DTB PCI memory aperture overflows");
            assert!(
                end <= (u32::MAX as u64) + 1,
                "DTB PCI memory aperture exceeds 32-bit address space"
            );
            Self {
                start,
                end,
            }
        }

        fn allocate_memory_32(&mut self, size: u32) -> u32 {
            debug_assert!(size.is_power_of_two());
            let size = u64::from(size);
            let allocated_address = align_up(self.start, size);
            let next = allocated_address
                .checked_add(size)
                .expect("PCI BAR allocation overflows");
            assert!(next <= self.end, "PCI memory aperture is exhausted");
            self.start = next;
            u32::try_from(allocated_address).expect("PCI BAR address exceeds 32-bit range")
        }
    }

    const fn align_up(value: u64, alignment: u64) -> u64 {
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
                map_identical_range(addr as usize, size as usize);
            }
            bar_index += if info.takes_two_entries() { 2 } else { 1 };
        }
    }

    fn ensure_pci_allocator(pci_host: PciHostInfo) {
        let mut allocator = PCI_ALLOCATOR.lock();
        if allocator.is_none() {
            *allocator = Some(PciMemory32Allocator::for_pci_host(pci_host));
        }
    }

    fn ensure_pci_ecam_mapped(pci_host: PciHostInfo) {
        if PCI_ECAM_MAPPED.load(Ordering::SeqCst) {
            return;
        }
        map_identical_range(pci_host.ecam_base, pci_host.ecam_size);
        PCI_ECAM_MAPPED.store(true, Ordering::SeqCst);
    }

    fn virtio_blk_pci(transport: PciTransport) -> VirtIOBlock {
        let blk = VirtIOBlk::<HalImpl, PciTransport>::new(transport)
            .expect("failed to create virtio block driver");
        VirtIOBlock(Mutex::new(blk))
    }

    impl VirtIOBlock {
        pub fn new() -> Self {
            Self::try_new_with_index(0).expect("VirtIO block device not found")
        }

        pub fn try_new_second() -> Option<Self> {
            Self::try_new_with_index(1)
        }

        fn try_new_with_index(index: usize) -> Option<Self> {
            let pci_host = DTB_data::pci_host_info();
            ensure_pci_ecam_mapped(pci_host);
            ensure_pci_allocator(pci_host);
            let bus_offset = (pci_host.bus_start as usize)
                .checked_shl(20)
                .expect("DTB PCI bus start overflows ECAM offset");
            let ecam_root_base = pci_host
                .ecam_base
                .checked_sub(bus_offset)
                .expect("DTB PCI ECAM base is below its bus-range offset");
            // 安全性：ECAM 基址来自已发布的 DTB，且已映射到内核页表。
            let mut pci_root = unsafe { PciRoot::new(ecam_root_base as *mut u8, Cam::Ecam) };
            let mut blk_index = 0usize;
            for (device_function, info) in pci_root.enumerate_bus(pci_host.bus_start) {
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
                    let transport =
                        PciTransport::new::<HalImpl>(&mut pci_root, device_function).ok()?;
                    return Some(virtio_blk_pci(transport));
                }
                blk_index += 1;
            }
            None
        }
    }
}

#[cfg(target_arch = "riscv64")]
pub use virtio_mmio::VirtIOBlock;
#[cfg(target_arch = "loongarch64")]
pub use virtio_pci::VirtIOBlock;
