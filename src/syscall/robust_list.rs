use crate::mm::{try_compare_exchange_user_u32, try_read_user_value};
use crate::syscall::futex::futex_wake_shared;

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
    futex_offset: isize,
    list_op_pending: *mut RobustList,
}

pub const ROBUST_LIST_HEAD_LEN: usize = core::mem::size_of::<RobustListHead>();

fn handle_futex_death(
    pid: usize,
    token: usize,
    node: *mut RobustList,
    offset: isize,
    tid: u32,
    pending: bool,
) -> Result<(), ()> {
    // Bit 0 is ROBUST_LIST_PI and is metadata, not part of the user pointer.
    let node_raw = node as usize;
    let pi = (node_raw & 1) != 0;
    let node_addr = node_raw & !1usize;
    let futex_addr = node_addr.wrapping_add(offset as usize) as *mut u32;
    if !(futex_addr as usize).is_multiple_of(core::mem::align_of::<u32>()) {
        return Err(());
    }

    loop {
        let Some(futex_word) = try_read_user_value(token, futex_addr as *const u32) else {
            return Err(());
        };
        let owner = futex_word & FUTEX_TID_MASK;

        // Linux handles the userspace unlock race represented by
        // list_op_pending specially: once a non-PI mutex has owner 0, wake a
        // possible waiter without manufacturing OWNER_DIED.
        if pending && !pi && owner == 0 {
            let _ = futex_wake_shared(pid, token, futex_addr as usize, 1);
            return Ok(());
        }
        if owner != tid {
            return Ok(());
        }

        // Remove the dead owner's TID, preserve FUTEX_WAITERS, and publish
        // OWNER_DIED atomically so a concurrent userspace transition cannot be
        // overwritten by exit cleanup.
        let new_val = (futex_word & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
        match try_compare_exchange_user_u32(token, futex_addr, futex_word, new_val)? {
            Ok(_) => {
                // PI futexes are woken through Linux's PI-state teardown. This
                // kernel does not yet implement that state machine, so do not
                // incorrectly wake them through the non-PI queue.
                if !pi && (futex_word & FUTEX_WAITERS) != 0 {
                    let _ = futex_wake_shared(pid, token, futex_addr as usize, 1);
                }
                return Ok(());
            }
            Err(_) => core::hint::spin_loop(),
        }
    }
}

pub fn exit_robust_list(pid: usize, token: usize, head_addr: usize, tid: u32) {
    if head_addr == 0 {
        return;
    }
    let Some(head) = try_read_user_value(token, head_addr as *const RobustListHead) else {
        return;
    };
    let pending_addr = (head.list_op_pending as usize) & !1usize;
    let mut entry = head.list;
    let mut count = 0usize;
    while !entry.is_null() && ((entry as usize) & !1usize) != head_addr && count < ROBUST_LIST_LIMIT
    {
        let entry_addr = ((entry as usize) & !1usize) as *const RobustList;
        let Some(node) = try_read_user_value(token, entry_addr) else {
            break;
        };
        // list_op_pending may already have been linked into the robust list.
        // Linux processes it only once, after the regular walk.
        if entry_addr as usize != pending_addr
            && handle_futex_death(pid, token, entry, head.futex_offset, tid, false).is_err()
        {
            return;
        }
        entry = node.next;
        count += 1;
    }
    if !head.list_op_pending.is_null() && ((head.list_op_pending as usize) & !1usize) != head_addr {
        let _ = handle_futex_death(
            pid,
            token,
            head.list_op_pending,
            head.futex_offset,
            tid,
            true,
        );
    }
}
