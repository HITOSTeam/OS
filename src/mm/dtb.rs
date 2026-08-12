//! 对启动期 DTB 缓存的架构无关访问。
//!
//! 解析由 `arch::*::dtb::init` 在内存管理之前完成；本模块只转发缓存内容，
//! 因此不会在页帧分配或 CPU 启动路径中再次读取固件 DTB。

#[derive(Clone, Copy, Debug)]
pub struct HartTopology {
    pub present_mask: usize,
    pub discovered: usize,
    pub ignored: usize,
}

pub fn hart_topology_from_dtb() -> HartTopology {
    #[cfg(target_arch = "riscv64")]
    {
        let (discovered, ignored) = crate::arch::riscv64::dtb::hart_counts();
        HartTopology {
            present_mask: crate::arch::riscv64::dtb::active_hart_mask(),
            discovered,
            ignored,
        }
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let (discovered, ignored) = crate::arch::loongarch64::dtb::hart_counts();
        HartTopology {
            present_mask: crate::arch::loongarch64::dtb::active_hart_mask(),
            discovered,
            ignored,
        }
    }
}

pub fn for_each_phys_mem_range(mut f: impl FnMut(usize, usize)) {
    #[cfg(target_arch = "riscv64")]
    crate::arch::riscv64::dtb::for_each_phys_mem_range(|start, end| f(start, end));
    #[cfg(target_arch = "loongarch64")]
    crate::arch::loongarch64::dtb::for_each_phys_mem_range(|start, end| f(start, end));
}

pub fn for_each_reserved_range(mut f: impl FnMut(usize, usize)) {
    #[cfg(target_arch = "riscv64")]
    crate::arch::riscv64::dtb::for_each_reserved_range(|start, end| f(start, end));
    #[cfg(target_arch = "loongarch64")]
    crate::arch::loongarch64::dtb::for_each_reserved_range(|start, end| f(start, end));
}

pub fn for_each_mmio_range(mut f: impl FnMut(usize, usize)) {
    #[cfg(target_arch = "riscv64")]
    crate::arch::riscv64::dtb::for_each_mmio_range(|start, end| f(start, end));
    #[cfg(target_arch = "loongarch64")]
    crate::arch::loongarch64::dtb::for_each_mmio_range(|start, end| f(start, end));
}
