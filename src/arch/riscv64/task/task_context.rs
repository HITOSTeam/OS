use core::fmt::Display;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct TaskContext {
    //返回地址
    pub ra: usize,
    //任务用户栈
    pub sp: usize,
    //callee-saved寄存器
    pub s: [usize; 12],
}

impl TaskContext {
    pub fn new() -> Self {
        Self {
            ra: 0,
            sp: 0,
            s: [0; 12],
        }
    }

    pub fn set_for_app(ra: usize, kernel_sp: usize) -> Self {
        Self {
            ra,
            sp: kernel_sp,
            s: [0; 12],
        }
    }
}

impl Display for TaskContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TaskContext {{ ra: {:#x}, sp: {:#x}", self.ra, self.sp)?;
        for (i, reg) in self.s.iter().enumerate() {
            write!(f, ", s{}: {:#x}", i, reg)?;
        }
        write!(f, " }}")
    }
}
