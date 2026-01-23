pub fn sys_get_hartid() -> isize {
    crate::arch::hart_id() as isize
}
