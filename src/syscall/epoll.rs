use crate::syscall::error::{SyscallError, err};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Weak},
    vec::Vec,
};
use core::any::Any;
use core::mem::size_of;
use spin::Mutex;

use crate::{
    config::clock_freq,
    fs::{File, POLLIN, PollWaitQueue, wake_tasks},
    mm::{UserBuffer, try_read_user_value, try_write_user_value},
    task::{
        processor::{PreparedWait, current_files, current_files_and_nofile_limit, current_task},
        signal::{SIGKILL_NUM, SIGSTOP_NUM, has_wait_interrupting_pending, signal_bit},
        task_block::TaskControlBlock,
    },
    time::get_time,
    trap::get_current_token,
};

const EPOLL_CTL_ADD: isize = 1;
const EPOLL_CTL_DEL: isize = 2;
const EPOLL_CTL_MOD: isize = 3;

const EPOLLIN: u32 = 0x001;
const EPOLLPRI: u32 = 0x002;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;
const EPOLLRDHUP: u32 = 0x2000;
const EPOLLET: u32 = 1u32 << 31;
const EPOLLONESHOT: u32 = 1u32 << 30;

const EPOLL_READY_MASK: u32 = EPOLLIN | EPOLLPRI | EPOLLOUT | EPOLLRDHUP;
const EPOLL_ALWAYS_REPORT_MASK: u32 = EPOLLERR | EPOLLHUP;
const EPOLL_CLOEXEC: usize = 0x80000;
const FD_CLOEXEC: u32 = 1;
const MAX_EPOLL_NESTING: usize = 5;

const EPOLL_IDLE_SLEEP_MS: usize = 10;

type FileArc = Arc<dyn File + Send + Sync>;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserEpollEvent {
    events: u32,
    data: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct EpollTimeSpec {
    sec: i64,
    nsec: i64,
}

struct EpollInterest {
    file: Weak<dyn File + Send + Sync>,
    events: u32,
    data: u64,
    last_ready: u32,
    oneshot_disabled: bool,
}

struct InterestSnapshot {
    fd: usize,
    file: FileArc,
    events: u32,
    data: u64,
    last_ready: u32,
    oneshot_disabled: bool,
}

struct EntryUpdate {
    fd: usize,
    last_ready: u32,
    disable_oneshot: bool,
}

pub(crate) struct EpollFile {
    interests: Mutex<BTreeMap<usize, EpollInterest>>,
    poll_waiters: Mutex<PollWaitQueue>,
}

impl EpollFile {
    pub fn new() -> Self {
        Self {
            interests: Mutex::new(BTreeMap::new()),
            poll_waiters: Mutex::new(PollWaitQueue::default()),
        }
    }

    fn id(&self) -> usize {
        self as *const Self as usize
    }

    fn prune_stale_locked(interests: &mut BTreeMap<usize, EpollInterest>) {
        let stale_fds: Vec<usize> = interests
            .iter()
            .filter_map(|(fd, interest)| {
                if interest.file.upgrade().is_none() {
                    Some(*fd)
                } else {
                    None
                }
            })
            .collect();
        for fd in stale_fds {
            let _ = interests.remove(&fd);
        }
    }

    fn snapshot_interests(&self) -> Vec<InterestSnapshot> {
        let mut interests = self.interests.lock();
        Self::prune_stale_locked(&mut interests);
        interests
            .iter()
            .filter_map(|(fd, interest)| {
                interest.file.upgrade().map(|file| InterestSnapshot {
                    fd: *fd,
                    file,
                    events: interest.events,
                    data: interest.data,
                    last_ready: interest.last_ready,
                    oneshot_disabled: interest.oneshot_disabled,
                })
            })
            .collect()
    }

    fn add_interest(&self, fd: usize, file: &FileArc, events: u32, data: u64) -> Result<(), isize> {
        let mut interests = self.interests.lock();
        Self::prune_stale_locked(&mut interests);
        if interests.contains_key(&fd) {
            return Err(err(SyscallError::EEXIST));
        }
        interests.insert(
            fd,
            EpollInterest {
                file: Arc::downgrade(file),
                events,
                data,
                last_ready: 0,
                oneshot_disabled: false,
            },
        );
        Ok(())
    }

    fn mod_interest(&self, fd: usize, events: u32, data: u64) -> Result<(), isize> {
        let mut interests = self.interests.lock();
        Self::prune_stale_locked(&mut interests);
        let Some(entry) = interests.get_mut(&fd) else {
            return Err(err(SyscallError::ENOENT));
        };
        entry.events = events;
        entry.data = data;
        // EPOLLONESHOT re-arms on MOD.
        entry.last_ready = 0;
        entry.oneshot_disabled = false;
        Ok(())
    }

    fn del_interest(&self, fd: usize) -> Result<(), isize> {
        let mut interests = self.interests.lock();
        Self::prune_stale_locked(&mut interests);
        if interests.remove(&fd).is_none() {
            return Err(err(SyscallError::ENOENT));
        }
        Ok(())
    }

    fn apply_updates(&self, updates: &[EntryUpdate]) {
        if updates.is_empty() {
            return;
        }
        let mut interests = self.interests.lock();
        Self::prune_stale_locked(&mut interests);
        for update in updates {
            let Some(entry) = interests.get_mut(&update.fd) else {
                continue;
            };
            entry.last_ready = update.last_ready;
            if update.disable_oneshot {
                entry.oneshot_disabled = true;
            }
        }
    }

    fn notify_poll_waiters(&self) {
        let waiters = self.poll_waiters.lock().take_wakeups();
        wake_tasks(waiters);
    }

    fn contains_epoll_recursive(&self, target_id: usize, visited: &mut BTreeSet<usize>) -> bool {
        let my_id = self.id();
        if !visited.insert(my_id) {
            return false;
        }
        if my_id == target_id {
            return true;
        }
        let children = self.snapshot_interests();
        for child in children {
            if let Some(epoll) = child.file.as_any().downcast_ref::<EpollFile>() {
                if epoll.contains_epoll_recursive(target_id, visited) {
                    return true;
                }
            }
        }
        false
    }

    fn max_depth_recursive(&self, visited: &mut BTreeSet<usize>) -> usize {
        let my_id = self.id();
        if !visited.insert(my_id) {
            return 0;
        }
        let mut depth = 1usize;
        let children = self.snapshot_interests();
        for child in children {
            if let Some(epoll) = child.file.as_any().downcast_ref::<EpollFile>() {
                depth = depth.max(1 + epoll.max_depth_recursive(visited));
            }
        }
        visited.remove(&my_id);
        depth
    }

    fn would_create_cycle(&self, child: &EpollFile) -> bool {
        let mut visited = BTreeSet::new();
        child.contains_epoll_recursive(self.id(), &mut visited)
    }

    fn event_watch_mask(events: u32) -> u32 {
        (events & EPOLL_READY_MASK) | EPOLL_ALWAYS_REPORT_MASK
    }

    fn is_edge_trigger(events: u32) -> bool {
        (events & EPOLLET) != 0
    }

    fn is_oneshot(events: u32) -> bool {
        (events & EPOLLONESHOT) != 0
    }

    fn file_ready_mask(file: &FileArc, watch_mask: u32, visited: &mut BTreeSet<usize>) -> u32 {
        if let Some(child) = file.as_any().downcast_ref::<EpollFile>() {
            let mut ready = 0u32;
            if (watch_mask & EPOLLIN) != 0 && child.peek_has_ready_internal(visited) {
                ready |= EPOLLIN;
            }
            return ready;
        }
        let ready = file.poll_mask() as u16 as u32;
        ready & watch_mask
    }

    fn peek_has_ready_internal(&self, visited: &mut BTreeSet<usize>) -> bool {
        let my_id = self.id();
        if !visited.insert(my_id) {
            return false;
        }
        let snapshots = self.snapshot_interests();
        for snap in snapshots {
            if snap.oneshot_disabled {
                continue;
            }
            let watch_mask = Self::event_watch_mask(snap.events);
            if watch_mask == 0 {
                continue;
            }
            let ready_now = Self::file_ready_mask(&snap.file, watch_mask, visited);
            let fired = if Self::is_edge_trigger(snap.events) {
                (ready_now & !snap.last_ready) != 0
            } else {
                ready_now != 0
            };
            if fired {
                visited.remove(&my_id);
                return true;
            }
        }
        visited.remove(&my_id);
        false
    }

    fn gather_ready_events(&self, maxevents: usize) -> (Vec<UserEpollEvent>, Vec<EntryUpdate>) {
        if maxevents == 0 {
            return (Vec::new(), Vec::new());
        }
        let snapshots = self.snapshot_interests();
        let mut events = Vec::new();
        let mut updates = Vec::new();
        for snap in snapshots {
            if snap.oneshot_disabled {
                continue;
            }
            let watch_mask = Self::event_watch_mask(snap.events);
            let mut visited = BTreeSet::new();
            let ready_now = Self::file_ready_mask(&snap.file, watch_mask, &mut visited);
            let fired = if Self::is_edge_trigger(snap.events) {
                (ready_now & !snap.last_ready) != 0
            } else {
                ready_now != 0
            };
            updates.push(EntryUpdate {
                fd: snap.fd,
                last_ready: ready_now,
                disable_oneshot: fired && Self::is_oneshot(snap.events),
            });
            if fired && events.len() < maxevents {
                events.push(UserEpollEvent {
                    events: ready_now & watch_mask,
                    data: snap.data,
                });
            }
        }
        (events, updates)
    }

    fn register_poll_waiter_internal(
        &self,
        task: &Arc<TaskControlBlock>,
        visited: &mut BTreeSet<usize>,
    ) -> bool {
        let my_id = self.id();
        if !visited.insert(my_id) {
            return true;
        }
        let _ = self.poll_waiters.lock().register_waiter(task);
        let snapshots = self.snapshot_interests();
        for snap in snapshots {
            if snap.oneshot_disabled {
                continue;
            }
            if Self::event_watch_mask(snap.events) == 0 {
                continue;
            }
            let supported = if let Some(child) = snap.file.as_any().downcast_ref::<EpollFile>() {
                child.register_poll_waiter_internal(task, visited)
            } else {
                snap.file.register_poll_waiter(task)
            };
            if !supported {
                visited.remove(&my_id);
                return false;
            }
        }
        visited.remove(&my_id);
        true
    }
}

impl File for EpollFile {
    fn readable(&self) -> bool {
        false
    }

    fn writable(&self) -> bool {
        false
    }

    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn poll_mask(&self) -> i16 {
        let mut visited = BTreeSet::new();
        if self.peek_has_ready_internal(&mut visited) {
            POLLIN
        } else {
            0
        }
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        let mut visited = BTreeSet::new();
        self.register_poll_waiter_internal(task, &mut visited)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn get_fd_file(fd: usize) -> Result<FileArc, isize> {
    current_files()
        .lock()
        .get_file(fd)
        .ok_or(err(SyscallError::EBADF))
}

fn get_epoll_file(fd: usize) -> Result<FileArc, isize> {
    let file = get_fd_file(fd)?;
    if file.as_any().downcast_ref::<EpollFile>().is_none() {
        return Err(err(SyscallError::EINVAL));
    }
    Ok(file)
}

fn fd_to_epoll_ref(file: &FileArc) -> &EpollFile {
    file.as_any()
        .downcast_ref::<EpollFile>()
        .expect("epoll fd type checked")
}

fn parse_user_event(token: usize, event_ptr: usize) -> Result<UserEpollEvent, isize> {
    if event_ptr == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    try_read_user_value::<UserEpollEvent>(token, event_ptr as *const UserEpollEvent)
        .ok_or(err(SyscallError::EFAULT))
}

fn write_ready_events(
    token: usize,
    events_ptr: usize,
    events: &[UserEpollEvent],
) -> Result<(), isize> {
    for (i, ev) in events.iter().enumerate() {
        let Some(ptr) = events_ptr.checked_add(i * size_of::<UserEpollEvent>()) else {
            return Err(err(SyscallError::EFAULT));
        };
        if try_write_user_value(token, ptr as *mut UserEpollEvent, ev).is_err() {
            return Err(err(SyscallError::EFAULT));
        }
    }
    Ok(())
}

fn should_block(
    file: &FileArc,
    maxevents: usize,
    token: usize,
    events_ptr: usize,
) -> Result<isize, isize> {
    let ep = fd_to_epoll_ref(file);
    let (ready_events, updates) = ep.gather_ready_events(maxevents);
    if ready_events.is_empty() {
        // Edge-triggered entries still need their last_ready snapshot refreshed
        // when readiness drops to zero, otherwise the next edge can be missed.
        ep.apply_updates(&updates);
        return Ok(0);
    }
    write_ready_events(token, events_ptr, &ready_events)?;
    ep.apply_updates(&updates);
    Ok(ready_events.len() as isize)
}

fn target_supports_epoll(file: &FileArc) -> bool {
    if file.as_any().downcast_ref::<EpollFile>().is_some() {
        return true;
    }
    file.supports_poll()
}

fn now_ns() -> u64 {
    (get_time() as u64)
        .saturating_mul(1_000_000_000)
        .saturating_div(clock_freq() as u64)
}

fn timespec_to_deadline_ns(ts: EpollTimeSpec) -> Result<u64, isize> {
    if ts.sec < 0 || ts.nsec < 0 || ts.nsec >= 1_000_000_000 {
        return Err(err(SyscallError::EINVAL));
    }
    let delta_ns = (ts.sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.nsec as u64);
    Ok(now_ns().saturating_add(delta_ns))
}

fn install_sigmask(
    token: usize,
    task: &crate::task::task_block::TaskControlBlock,
    sigmask: usize,
    sigsetsize: usize,
) -> Result<Option<u64>, isize> {
    if sigmask == 0 {
        return Ok(None);
    }
    if sigsetsize < size_of::<u64>() {
        return Err(err(SyscallError::EINVAL));
    }
    let Some(mut new_mask) = try_read_user_value::<u64>(token, sigmask as *const u64) else {
        return Err(err(SyscallError::EFAULT));
    };
    let sigkill_bit = signal_bit(SIGKILL_NUM).unwrap_or(0);
    let sigstop_bit = signal_bit(SIGSTOP_NUM).unwrap_or(0);
    new_mask &= !(sigkill_bit | sigstop_bit);
    let old_mask = {
        let mut inner = task.borrow_mut();
        let old = inner.signal_mask;
        inner.signal_mask = new_mask;
        old
    };
    Ok(Some(old_mask))
}

fn restore_sigmask(task: &crate::task::task_block::TaskControlBlock, old_mask: Option<u64>) {
    if let Some(old_mask) = old_mask {
        let mut inner = task.borrow_mut();
        inner.signal_mask = old_mask;
    }
}

fn epoll_wait_common(
    epoll_file: FileArc,
    events_ptr: usize,
    maxevents: usize,
    deadline_ns: Option<u64>,
    sigmask: usize,
    sigsetsize: usize,
) -> isize {
    let maxevents = maxevents as isize;
    if maxevents <= 0 || maxevents > i32::MAX as isize {
        return err(SyscallError::EINVAL);
    }

    let token = get_current_token();
    let task = current_task().unwrap();
    let restore_mask = match install_sigmask(token, &task, sigmask, sigsetsize) {
        Ok(mask) => mask,
        Err(e) => return e,
    };

    let ret = loop {
        let (pending, mask) = {
            let inner = task.borrow_mut();
            (inner.pending_signals, inner.signal_mask)
        };
        if has_wait_interrupting_pending(pending, mask) {
            break err(SyscallError::EINTR);
        }

        match should_block(&epoll_file, maxevents as usize, token, events_ptr) {
            Ok(ready) if ready > 0 => break ready,
            Err(e) => break e,
            _ => {}
        }

        let waiter_armed = {
            let ep = fd_to_epoll_ref(&epoll_file);
            let mut visited = BTreeSet::new();
            ep.register_poll_waiter_internal(&task, &mut visited)
        };
        // Linux ep_poll() installs its wait entry and sets TASK_INTERRUPTIBLE
        // before the final readiness scan.  PreparedWait provides the same
        // atomic hand-off against local timer preemption and remote wakeups.
        let prepared =
            waiter_armed.then(|| PreparedWait::new().expect("epoll wait lost its current task"));

        match should_block(&epoll_file, maxevents as usize, token, events_ptr) {
            Ok(ready) if ready > 0 => break ready,
            Err(e) => break e,
            _ => {}
        }

        if let Some(deadline) = deadline_ns {
            let now = now_ns();
            if now >= deadline {
                break 0;
            }
            let remain_ns = deadline.saturating_sub(now);
            let mut sleep_ms = ((remain_ns.saturating_add(999_999)) / 1_000_000) as usize;
            if sleep_ms == 0 {
                sleep_ms = 1;
            }
            if let Some(prepared) = prepared {
                crate::task::block_sleep::add_timer(Arc::clone(&task), sleep_ms);
                prepared.sleep();
            } else {
                let r = crate::syscall::thread::sys_sleep(sleep_ms);
                if r == err(SyscallError::EINTR) {
                    let (pending, mask) = {
                        let inner = task.borrow_mut();
                        (inner.pending_signals, inner.signal_mask)
                    };
                    if has_wait_interrupting_pending(pending, mask) {
                        break err(SyscallError::EINTR);
                    }
                }
            }
        } else if let Some(prepared) = prepared {
            prepared.sleep();
        } else {
            // We do not have wait-queue registration for all epoll targets yet,
            // so keep the task in a stable sleeping state long enough for
            // signal/peer-driven wakeup tests to observe it as blocked.
            let r = crate::syscall::thread::sys_sleep(EPOLL_IDLE_SLEEP_MS);
            if r == err(SyscallError::EINTR) {
                let (pending, mask) = {
                    let inner = task.borrow_mut();
                    (inner.pending_signals, inner.signal_mask)
                };
                if has_wait_interrupting_pending(pending, mask) {
                    break err(SyscallError::EINTR);
                }
            }
        }
    };

    restore_sigmask(&task, restore_mask);
    ret
}

pub fn syscall_epoll_create1(flags: usize) -> isize {
    if (flags & !EPOLL_CLOEXEC) != 0 {
        return err(SyscallError::EINVAL);
    }
    let mut descriptor_flags = 0u32;
    if (flags & EPOLL_CLOEXEC) != 0 {
        descriptor_flags |= FD_CLOEXEC;
    }
    let (files, limit) = current_files_and_nofile_limit();
    let installed = files
        .lock()
        .install_fd(Arc::new(EpollFile::new()), descriptor_flags, limit);
    installed.map(|fd| fd as isize).unwrap_or_else(|rejected| {
        rejected.discard();
        err(SyscallError::EMFILE)
    })
}

pub fn syscall_epoll_ctl(epfd: usize, op: usize, fd: usize, event_ptr: usize) -> isize {
    let epoll_file = match get_epoll_file(epfd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let ep = fd_to_epoll_ref(&epoll_file);

    let op = op as isize;
    if op != EPOLL_CTL_ADD && op != EPOLL_CTL_DEL && op != EPOLL_CTL_MOD {
        return err(SyscallError::EINVAL);
    }

    let target_file = match get_fd_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };

    if fd == epfd {
        return err(SyscallError::EINVAL);
    }

    let token = get_current_token();
    let event = if op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD {
        match parse_user_event(token, event_ptr) {
            Ok(ev) => Some(ev),
            Err(e) => return e,
        }
    } else {
        None
    };

    if op == EPOLL_CTL_ADD {
        if !target_supports_epoll(&target_file) {
            return err(SyscallError::EPERM);
        }
        if let Some(child) = target_file.as_any().downcast_ref::<EpollFile>() {
            if child.id() == ep.id() {
                return err(SyscallError::EINVAL);
            }
            if ep.would_create_cycle(child) {
                return err(SyscallError::ELOOP);
            }
            let mut visited = BTreeSet::new();
            if child.max_depth_recursive(&mut visited) >= MAX_EPOLL_NESTING {
                return err(SyscallError::EINVAL);
            }
        }
    }

    let ret = match op {
        EPOLL_CTL_ADD => {
            let ev = event.expect("ADD has event");
            match ep.add_interest(fd, &target_file, ev.events, ev.data) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        EPOLL_CTL_MOD => {
            let ev = event.expect("MOD has event");
            match ep.mod_interest(fd, ev.events, ev.data) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        EPOLL_CTL_DEL => match ep.del_interest(fd) {
            Ok(()) => 0,
            Err(e) => e,
        },
        _ => err(SyscallError::EINVAL),
    };
    if ret == 0 {
        ep.notify_poll_waiters();
    }
    ret
}

pub fn syscall_epoll_pwait(
    epfd: usize,
    events_ptr: usize,
    maxevents: usize,
    timeout: usize,
    sigmask: usize,
    sigsetsize: usize,
) -> isize {
    let epoll_file = match get_epoll_file(epfd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let timeout = timeout as isize;
    let deadline_ns = if timeout < -1 {
        return err(SyscallError::EINVAL);
    } else if timeout < 0 {
        None
    } else {
        Some(now_ns().saturating_add((timeout as u64).saturating_mul(1_000_000)))
    };
    epoll_wait_common(
        epoll_file,
        events_ptr,
        maxevents,
        deadline_ns,
        sigmask,
        sigsetsize,
    )
}

pub fn syscall_epoll_pwait2(
    epfd: usize,
    events_ptr: usize,
    maxevents: usize,
    timeout_ptr: usize,
    sigmask: usize,
    sigsetsize: usize,
) -> isize {
    let epoll_file = match get_epoll_file(epfd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let deadline_ns = if timeout_ptr == 0 {
        None
    } else {
        let token = get_current_token();
        let Some(ts) =
            try_read_user_value::<EpollTimeSpec>(token, timeout_ptr as *const EpollTimeSpec)
        else {
            return err(SyscallError::EFAULT);
        };
        match timespec_to_deadline_ns(ts) {
            Ok(deadline) => Some(deadline),
            Err(e) => return e,
        }
    };
    epoll_wait_common(
        epoll_file,
        events_ptr,
        maxevents,
        deadline_ns,
        sigmask,
        sigsetsize,
    )
}
