use core::{arch::asm, fmt::Display};

#[inline(always)]
fn read_pgdl() -> usize {
    let value: usize;
    unsafe { asm!("csrrd {}, 0x19", out(reg) value) };
    value
}

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
    pub pgdl: usize,
    pub pgdh: usize,
}

impl TaskContext {
    pub fn new() -> Self {
        Self {
            ra: 0,
            sp: 0,
            s: [0; 12],
            pgdl: read_pgdl(),
            pgdh: read_pgdh(),
        }
    }

    pub fn set_for_app(ra: usize, kernel_sp: usize) -> Self {
        Self {
            ra,
            sp: kernel_sp,
            s: [0; 12],
            pgdl: read_pgdl(),
            pgdh: read_pgdh(),
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
