use crate::mm::{try_read_user_value, try_write_user_value};
use crate::syscall::futex::futex_wake_private_and_shared;

const ROBUST_LIST_LIMIT: usize = 2048;

// futex word layout:
// 31: FUTEX_WAITERS, 30: FUTEX_OWNER_DIED, low 30 bits: TID
const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;

#[repr(C)]
#[derive(Clone, Copy)]
struct RobustList {
    next: *mut RobustList,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RobustListHead {
    list: *mut RobustList,
    futex_offset: u64,
    list_op_pending: *mut RobustList,
}

pub const ROBUST_LIST_HEAD_LEN: usize = core::mem::size_of::<RobustListHead>();

fn handle_futex_death(token: usize, pid: usize, node: *mut RobustList, offset: u64, tid: u32) {
    let futex_addr = (node as usize).wrapping_add(offset as usize) as *mut u32;
    let Some(futex_word) = try_read_user_value(token, futex_addr as *const u32) else {
        return;
    };
    if (futex_word & FUTEX_TID_MASK) != tid {
        return;
    }
    let new_val = (futex_word & FUTEX_TID_MASK) | FUTEX_OWNER_DIED;
    let _ = try_write_user_value(token, futex_addr, &new_val);
    if (futex_word & FUTEX_WAITERS) != 0 {
        let _ = futex_wake_private_and_shared(pid, token, futex_addr as usize, 1);
    }
}

pub fn exit_robust_list(pid: usize, token: usize, head_addr: usize, tid: u32) {
    if head_addr == 0 {
        return;
    }
    let Some(head) = try_read_user_value(token, head_addr as *const RobustListHead) else {
        return;
    };
    let mut entry = head.list;
    let mut count = 0usize;
    while !entry.is_null() && (entry as usize) != head_addr && count < ROBUST_LIST_LIMIT {
        handle_futex_death(token, pid, entry, head.futex_offset, tid);
        let Some(node) = try_read_user_value(token, entry as *const RobustList) else {
            break;
        };
        entry = node.next;
        count += 1;
    }
    if !head.list_op_pending.is_null() && (head.list_op_pending as usize) != head_addr {
        handle_futex_death(token, pid, head.list_op_pending, head.futex_offset, tid);
    }
}
