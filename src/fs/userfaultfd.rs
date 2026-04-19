use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{any::Any, mem::size_of};
use spin::Mutex;

use crate::{
    config::PAGE_SIZE,
    mm::UserBuffer,
    task::{
        manager::wakeup_task,
        processor::{block_current_and_run_next, current_task},
        task_block::TaskControlBlock,
    },
};

use super::{File, POLLIN, PollWaitQueue, wake_tasks};
use crate::syscall::error::{SyscallError, err};
const UFFD_EVENT_PAGEFAULT: u8 = 0x12;
const UFFD_PAGEFAULT_FLAG_WRITE: u64 = 1 << 0;
const UFFDIO_REGISTER_MODE_MISSING: u64 = 1 << 0;
const UFFD_API_IOCTLS: u64 = (1u64 << 0) | (1u64 << 3) | (1u64 << 0x3f);
const UFFD_REGISTER_IOCTLS: u64 = 1u64 << 3;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UffdMsgPagefault {
    flags: u64,
    address: u64,
    reserved: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UffdMsg {
    event: u8,
    reserved1: u8,
    reserved2: u16,
    reserved3: u32,
    pagefault: UffdMsgPagefault,
}

impl UffdMsg {
    fn pagefault(address: usize, write: bool) -> Self {
        Self {
            event: UFFD_EVENT_PAGEFAULT,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            pagefault: UffdMsgPagefault {
                flags: if write { UFFD_PAGEFAULT_FLAG_WRITE } else { 0 },
                address: address as u64,
                reserved: 0,
            },
        }
    }
}

#[derive(Clone, Copy)]
struct UffdRegistration {
    start: usize,
    end: usize,
    mode: u64,
}

struct UserfaultfdInner {
    api_enabled: bool,
    registrations: Vec<UffdRegistration>,
    pending: VecDeque<UffdMsg>,
    blocked_pages: BTreeMap<usize, Vec<Weak<TaskControlBlock>>>,
    read_waiters: Vec<Weak<TaskControlBlock>>,
    poll_waiters: PollWaitQueue,
}

pub struct UserfaultfdFile {
    inner: Mutex<UserfaultfdInner>,
}

impl UserfaultfdFile {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(UserfaultfdInner {
                api_enabled: false,
                registrations: Vec::new(),
                pending: VecDeque::new(),
                blocked_pages: BTreeMap::new(),
                read_waiters: Vec::new(),
                poll_waiters: PollWaitQueue::default(),
            }),
        }
    }

    pub fn poll_readable(&self) -> bool {
        !self.inner.lock().pending.is_empty()
    }

    pub fn enable_api(&self) -> u64 {
        let mut inner = self.inner.lock();
        inner.api_enabled = true;
        UFFD_API_IOCTLS
    }

    pub fn register_missing(&self, start: usize, len: usize, mode: u64) -> Result<u64, isize> {
        if len == 0 || mode != UFFDIO_REGISTER_MODE_MISSING {
            return Err(err(SyscallError::EINVAL));
        }
        let end = start.checked_add(len).ok_or(err(SyscallError::EINVAL))?;
        let mut inner = self.inner.lock();
        if !inner.api_enabled {
            return Err(err(SyscallError::EINVAL));
        }
        inner
            .registrations
            .push(UffdRegistration { start, end, mode });
        Ok(UFFD_REGISTER_IOCTLS)
    }

    pub fn handle_page_fault(&self, fault_addr: usize, is_write: bool) -> bool {
        let page = fault_addr & !(PAGE_SIZE - 1);
        let waiters = {
            let mut inner = self.inner.lock();
            if !inner.api_enabled
                || !inner.registrations.iter().any(|reg| {
                    reg.mode == UFFDIO_REGISTER_MODE_MISSING
                        && fault_addr >= reg.start
                        && fault_addr < reg.end
                })
            {
                return false;
            }
            if let Some(task) = current_task() {
                inner
                    .blocked_pages
                    .entry(page)
                    .or_default()
                    .push(Arc::downgrade(&task));
            }
            if !inner.blocked_pages.contains_key(&page)
                || !inner.pending.iter().any(|msg| {
                    msg.event == UFFD_EVENT_PAGEFAULT
                        && (msg.pagefault.address as usize & !(PAGE_SIZE - 1)) == page
                })
            {
                inner
                    .pending
                    .push_back(UffdMsg::pagefault(fault_addr, is_write));
            }
            let mut ready = Vec::new();
            inner.read_waiters.retain(|waiter| {
                if let Some(task) = waiter.upgrade() {
                    ready.push(task);
                    false
                } else {
                    false
                }
            });
            ready.extend(inner.poll_waiters.take_wakeups());
            ready
        };
        wake_tasks(waiters);
        block_current_and_run_next();
        true
    }

    pub fn finish_copy(&self, dst: usize, len: usize, wake: bool) {
        if len == 0 {
            return;
        }
        let start = dst & !(PAGE_SIZE - 1);
        let end = (dst + len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let tasks = {
            let mut inner = self.inner.lock();
            let mut tasks = Vec::new();
            if wake {
                let mut page = start;
                while page < end {
                    if let Some(waiters) = inner.blocked_pages.remove(&page) {
                        for waiter in waiters {
                            if let Some(task) = waiter.upgrade() {
                                tasks.push(task);
                            }
                        }
                    }
                    page += PAGE_SIZE;
                }
            }
            tasks
        };
        for task in tasks {
            wakeup_task(task);
        }
    }

    fn wait_for_message(&self) -> UffdMsg {
        loop {
            if let Some(msg) = self.inner.lock().pending.pop_front() {
                return msg;
            }
            if let Some(task) = current_task() {
                self.inner.lock().read_waiters.push(Arc::downgrade(&task));
            }
            block_current_and_run_next();
        }
    }
}

impl File for UserfaultfdFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        false
    }

    fn read(&self, buf: UserBuffer) -> usize {
        let msg = self.wait_for_message();
        let src = unsafe {
            core::slice::from_raw_parts((&msg as *const UffdMsg) as *const u8, size_of::<UffdMsg>())
        };
        let mut copied = 0usize;
        let mut it = buf.into_iter();
        while copied < src.len() {
            let Some(dst) = it.next() else {
                break;
            };
            unsafe {
                *dst = src[copied];
            }
            copied += 1;
        }
        copied
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn poll_mask(&self) -> i16 {
        if self.poll_readable() { POLLIN } else { 0 }
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        let mut inner = self.inner.lock();
        if !inner.pending.is_empty() {
            return true;
        }
        let _ = inner.poll_waiters.register_waiter(task);
        true
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
