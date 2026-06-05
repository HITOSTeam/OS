use core::fmt::Display;

//loongarch架构需要维护寄存器pgdl
#[cfg(target_arch = "loongarch64")]
use core::arch::asm;

#[cfg(target_arch = "loongarch64")]
#[inline(always)]
fn read_pgdl() -> usize {
    let value: usize;
    unsafe { asm!("csrrd {}, 0x19", out(reg) value) };
    value
}

#[cfg(target_arch = "loongarch64")]
#[inline(always)]
fn read_pgdh() -> usize {
    let value: usize;
    unsafe { asm!("csrrd {}, 0x1a", out(reg) value) };
    value
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct TaskContext {
    pub ra: usize,
    pub sp: usize,
    pub s: [usize; 12],
    //loongarch需要的特殊寄存器,用来读取页表
    pub pgdl: usize,
    pub pgdh: usize,
}
impl TaskContext {
    pub fn new() -> Self {
        Self {
            ra: 0,
            sp: 0,
            s: [0; 12],
            #[cfg(target_arch = "loongarch64")]
            pgdl: read_pgdl(),
            #[cfg(not(target_arch = "loongarch64"))]
            pgdl: 0,
            #[cfg(target_arch = "loongarch64")]
            pgdh: read_pgdh(),
            #[cfg(not(target_arch = "loongarch64"))]
            pgdh: 0,
        }
    }
    pub fn set_for_app(ra: usize, kernel_sp: usize) -> Self {
        Self {
            ra,
            sp: kernel_sp,
            s: [0; 12],
            #[cfg(target_arch = "loongarch64")]
            pgdl: read_pgdl(),
            #[cfg(not(target_arch = "loongarch64"))]
            pgdl: 0,
            #[cfg(target_arch = "loongarch64")]
            pgdh: read_pgdh(),
            #[cfg(not(target_arch = "loongarch64"))]
            pgdh: 0,
        }
    }
}
impl Display for TaskContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TaskContext {{ ra: {:#x}, sp: {:#x}", self.ra, self.sp)?;
        for (i, reg) in self.s.iter().enumerate() {
            write!(f, ", s{}: {:#x}", i, reg)?;
        }
        write!(f, ", pgdl: {:#x}, pgdh: {:#x} }}", self.pgdl, self.pgdh)
    }
}
