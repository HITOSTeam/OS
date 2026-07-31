//! Scheduler-aware kernel synchronization primitives.
//!
//! The small metadata spinlocks in these types are never held while a task is
//! switched out.  Contended owners sleep on a wait queue, which makes the
//! primitives suitable for filesystem operations that can block on device I/O.

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering},
};
use spin::Mutex as SpinMutex;

use crate::task::{
    manager::{wakeup_task, wakeup_tasks},
    processor::{block_current_and_run_next_uninterruptible, current_task},
    task_block::TaskControlBlock,
};

/// Disable local interrupts until this guard is dropped.
///
/// Locks shared with a hard-interrupt handler must use irq-save semantics:
/// otherwise the interrupt can preempt the lock owner and spin forever trying
/// to acquire the same lock.  This is the small RAII equivalent of Linux's
/// `spin_lock_irqsave()`/`spin_unlock_irqrestore()` pair.
#[must_use = "dropping the guard immediately restores the previous IRQ state"]
pub struct LocalIrqSaveGuard {
    interrupts_were_enabled: bool,
}

impl LocalIrqSaveGuard {
    #[inline]
    pub fn new() -> Self {
        Self {
            interrupts_were_enabled: crate::arch::disable_interrupts(),
        }
    }
}

impl Default for LocalIrqSaveGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for LocalIrqSaveGuard {
    #[inline]
    fn drop(&mut self) {
        crate::arch::restore_interrupts(self.interrupts_were_enabled);
    }
}

/// FIFO wait queue with a predicate recheck under the queue lock.
///
/// Rechecking while holding `inner` pairs with wake operations taking the same
/// lock and prevents the classic "condition changed immediately before enqueue"
/// lost-wakeup race.
pub struct WaitQueue {
    inner: SpinMutex<VecDeque<Arc<TaskControlBlock>>>,
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self {
            inner: SpinMutex::new(VecDeque::new()),
        }
    }

    pub fn wait_until(&self, mut ready: impl FnMut() -> bool) {
        loop {
            if ready() {
                return;
            }
            let Some(task) = current_task() else {
                core::hint::spin_loop();
                continue;
            };
            {
                // Linux wait_queue_head uses spin_lock_irqsave because wakeups
                // may come from a device hardirq.
                let _irq_guard = LocalIrqSaveGuard::new();
                let mut waiters = self.inner.lock();
                if ready() {
                    return;
                }
                if !waiters.iter().any(|waiter| Arc::ptr_eq(waiter, &task)) {
                    waiters.push_back(task);
                }
            }
            block_current_and_run_next_uninterruptible();
        }
    }

    pub fn wake_one(&self) {
        let waiter = {
            let _irq_guard = LocalIrqSaveGuard::new();
            let waiter = self.inner.lock().pop_front();
            waiter
        };
        if let Some(waiter) = waiter {
            wakeup_task(waiter);
        }
    }

    pub fn wake_all(&self) {
        let waiters: Vec<_> = {
            let _irq_guard = LocalIrqSaveGuard::new();
            let waiters = self.inner.lock().drain(..).collect();
            waiters
        };
        if !waiters.is_empty() {
            wakeup_tasks(waiters);
        }
    }

    #[cfg(test)]
    pub fn waiter_count(&self) -> usize {
        let _irq_guard = LocalIrqSaveGuard::new();
        let count = self.inner.lock().len();
        count
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Sleeping mutex for kernel data that may be held across blocking I/O.
pub struct KernelMutex<T: ?Sized> {
    locked: AtomicBool,
    waiters: WaitQueue,
    value: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send> Send for KernelMutex<T> {}
unsafe impl<T: ?Sized + Send> Sync for KernelMutex<T> {}

impl<T> KernelMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            waiters: WaitQueue::new(),
            value: UnsafeCell::new(value),
        }
    }
}

impl<T: ?Sized> KernelMutex<T> {
    fn try_acquire(&self) -> bool {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    pub fn try_lock(&self) -> Option<KernelMutexGuard<'_, T>> {
        self.try_acquire()
            .then_some(KernelMutexGuard { lock: self })
    }

    pub fn lock(&self) -> KernelMutexGuard<'_, T> {
        self.waiters.wait_until(|| self.try_acquire());
        KernelMutexGuard { lock: self }
    }
}

pub struct KernelMutexGuard<'a, T: ?Sized> {
    lock: &'a KernelMutex<T>,
}

impl<T: ?Sized> Deref for KernelMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: the guard owns the mutex until Drop.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T: ?Sized> DerefMut for KernelMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: the guard owns the mutex exclusively until Drop.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T: ?Sized> Drop for KernelMutexGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
        self.lock.waiters.wake_one();
    }
}

/// Writer-preferring sleeping read/write semaphore.
pub struct KernelRwSemaphore<T: ?Sized> {
    /// `-1` means a writer owns the lock; non-negative values count readers.
    state: AtomicIsize,
    writers_waiting: AtomicUsize,
    reader_waiters: WaitQueue,
    writer_waiters: WaitQueue,
    value: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send> Send for KernelRwSemaphore<T> {}
unsafe impl<T: ?Sized + Send + Sync> Sync for KernelRwSemaphore<T> {}

impl<T> KernelRwSemaphore<T> {
    pub const fn new(value: T) -> Self {
        Self {
            state: AtomicIsize::new(0),
            writers_waiting: AtomicUsize::new(0),
            reader_waiters: WaitQueue::new(),
            writer_waiters: WaitQueue::new(),
            value: UnsafeCell::new(value),
        }
    }
}

impl<T: ?Sized> KernelRwSemaphore<T> {
    fn try_acquire_read(&self) -> bool {
        if self.writers_waiting.load(Ordering::Acquire) != 0 {
            return false;
        }
        let mut state = self.state.load(Ordering::Relaxed);
        loop {
            if state < 0 {
                return false;
            }
            match self.state.compare_exchange_weak(
                state,
                state + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(current) => state = current,
            }
        }
    }

    fn try_acquire_write(&self) -> bool {
        self.state
            .compare_exchange(0, -1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    pub fn try_read(&self) -> Option<KernelRwSemaphoreReadGuard<'_, T>> {
        self.try_acquire_read()
            .then_some(KernelRwSemaphoreReadGuard { lock: self })
    }

    pub fn read(&self) -> KernelRwSemaphoreReadGuard<'_, T> {
        self.reader_waiters.wait_until(|| self.try_acquire_read());
        KernelRwSemaphoreReadGuard { lock: self }
    }

    pub fn try_write(&self) -> Option<KernelRwSemaphoreWriteGuard<'_, T>> {
        self.try_acquire_write()
            .then_some(KernelRwSemaphoreWriteGuard { lock: self })
    }

    pub fn write(&self) -> KernelRwSemaphoreWriteGuard<'_, T> {
        self.writers_waiting.fetch_add(1, Ordering::AcqRel);
        self.writer_waiters.wait_until(|| self.try_acquire_write());
        self.writers_waiting.fetch_sub(1, Ordering::AcqRel);
        KernelRwSemaphoreWriteGuard { lock: self }
    }

    fn release_read(&self) {
        let previous = self.state.fetch_sub(1, Ordering::Release);
        debug_assert!(previous > 0);
        if previous == 1 && self.writers_waiting.load(Ordering::Acquire) != 0 {
            self.writer_waiters.wake_one();
        }
    }

    fn release_write(&self) {
        let previous = self.state.swap(0, Ordering::Release);
        debug_assert_eq!(previous, -1);
        if self.writers_waiting.load(Ordering::Acquire) != 0 {
            self.writer_waiters.wake_one();
        } else {
            self.reader_waiters.wake_all();
        }
    }
}

pub struct KernelRwSemaphoreReadGuard<'a, T: ?Sized> {
    lock: &'a KernelRwSemaphore<T>,
}

impl<T: ?Sized> Deref for KernelRwSemaphoreReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: a read guard excludes writers for its lifetime.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T: ?Sized> Drop for KernelRwSemaphoreReadGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.release_read();
    }
}

pub struct KernelRwSemaphoreWriteGuard<'a, T: ?Sized> {
    lock: &'a KernelRwSemaphore<T>,
}

impl<T: ?Sized> Deref for KernelRwSemaphoreWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: a write guard owns the semaphore exclusively.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T: ?Sized> DerefMut for KernelRwSemaphoreWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: a write guard owns the semaphore exclusively.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T: ?Sized> Drop for KernelRwSemaphoreWriteGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.release_write();
    }
}
