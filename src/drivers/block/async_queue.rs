//! Linux-style split submission and completion for VirtIO block requests.
//!
//! Request buffers are owned by the driver until the device returns their
//! descriptor chain.  This makes it safe to put the submitting task to sleep
//! and permits several requests to be in flight on the same VirtQueue.

use alloc::{sync::Arc, vec::Vec};
use core::{
    cell::UnsafeCell,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
};
use spin::Mutex;
use virtio_drivers::{
    Error, Hal,
    device::blk::{BlkReq, BlkResp, VirtIOBlk},
    transport::Transport,
};

use crate::sync::{LocalIrqSaveGuard, WaitQueue};

const MAX_TRACKED_REQUESTS: usize = 32;
// Linux blk_hctx_poll() busy-polls only while the current task does not need
// rescheduling.  A small fixed budget is sufficient for QEMU's short VirtIO
// completion latency and avoids a sleep/wakeup cycle for every 4 KiB request.
const COMPLETION_POLL_SPINS: usize = 64;
const STALL_WARNING_MS: usize = 1_000;
// Linux blk-mq defaults to a 30-second request timeout when a driver does not
// provide one.  CongCore does not yet have blk-mq-style queue reset/recovery,
// so crossing this threshold is diagnosed but cannot safely release DMA state.
const STUCK_WARNING_MS: usize = 30_000;
const RESULT_PENDING: u8 = 0;
const RESULT_OK: u8 = 1;
const RESULT_IO_ERROR: u8 = 2;
const RESULT_UNSUPPORTED: u8 = 3;
const RESULT_NOT_READY: u8 = 4;
const RESULT_OTHER: u8 = 5;

#[derive(Clone, Copy)]
enum RequestKind {
    Read,
    Write,
}

#[derive(Clone, Copy)]
enum InterruptAck {
    Always,
    IfCompleted,
}

struct RequestBuffers {
    request: BlkReq,
    data: NonNull<u8>,
    data_len: usize,
    response: BlkResp,
}

struct BlockRequest {
    kind: RequestKind,
    sector: usize,
    buffers: UnsafeCell<RequestBuffers>,
    result: AtomicU8,
    completed: AtomicBool,
    submitted_at_ms: AtomicUsize,
    stall_warned: AtomicBool,
    stuck_warned: AtomicBool,
    waiters: WaitQueue,
}

// SAFETY: the synchronous submitter pins the caller's buffer by not returning
// (or consuming fatal signals) until `completed` is observed. While completion
// is pending only the queue owner accesses the raw slice, under the queue lock.
// This is the minimal analogue of Linux pinning bio pages for an in-flight
// request instead of copying each block into a second request buffer.
unsafe impl Send for BlockRequest {}
unsafe impl Sync for BlockRequest {}

impl BlockRequest {
    fn new(kind: RequestKind, sector: usize, data: NonNull<u8>, data_len: usize) -> Self {
        Self {
            kind,
            sector,
            buffers: UnsafeCell::new(RequestBuffers {
                request: BlkReq::default(),
                data,
                data_len,
                response: BlkResp::default(),
            }),
            result: AtomicU8::new(RESULT_PENDING),
            completed: AtomicBool::new(false),
            submitted_at_ms: AtomicUsize::new(0),
            stall_warned: AtomicBool::new(false),
            stuck_warned: AtomicBool::new(false),
            waiters: WaitQueue::new(),
        }
    }

    fn mark_submitted(&self) {
        // Zero means "not submitted"; bias the timestamp so time zero remains
        // representable during early boot.
        self.submitted_at_ms.store(
            crate::time::get_time_ms().saturating_add(1),
            Ordering::Release,
        );
    }

    fn elapsed_ms(&self, now_ms: usize) -> Option<usize> {
        let biased = self.submitted_at_ms.load(Ordering::Acquire);
        (biased != 0).then(|| now_ms.saturating_sub(biased - 1))
    }

    fn kind_name(&self) -> &'static str {
        match self.kind {
            RequestKind::Read => "read",
            RequestKind::Write => "write",
        }
    }

    fn complete(&self, result: virtio_drivers::Result) {
        let result = match result {
            Ok(()) => RESULT_OK,
            Err(Error::IoError) => RESULT_IO_ERROR,
            Err(Error::Unsupported) => RESULT_UNSUPPORTED,
            Err(Error::NotReady) => RESULT_NOT_READY,
            Err(_) => RESULT_OTHER,
        };
        self.result.store(result, Ordering::Relaxed);
        self.completed.store(true, Ordering::Release);
    }

    fn result(&self) -> virtio_drivers::Result {
        match self.result.load(Ordering::Acquire) {
            RESULT_OK => Ok(()),
            RESULT_IO_ERROR => Err(Error::IoError),
            RESULT_UNSUPPORTED => Err(Error::Unsupported),
            RESULT_NOT_READY => Err(Error::NotReady),
            _ => Err(Error::IoError),
        }
    }
}

struct DriverState<H: Hal, T: Transport> {
    device: VirtIOBlk<H, T>,
    requests: Vec<Option<Arc<BlockRequest>>>,
}

/// Diagnostic counters for the asynchronous block path.
#[derive(Clone, Copy, Debug, Default)]
pub struct AsyncBlockDiagnostics {
    pub submitted: u64,
    pub completed: u64,
    pub queue_full_retries: u64,
    pub interrupts: u64,
    pub fallback_polls: u64,
    pub short_poll_completions: u64,
    pub cooperative_yields: u64,
    pub stall_warnings: u64,
    pub stuck_warnings: u64,
    pub in_flight: usize,
    pub peak_in_flight: usize,
}

/// One hardware VirtQueue with multiple driver-owned requests in flight.
pub struct AsyncVirtIOBlock<H: Hal, T: Transport> {
    state: Mutex<DriverState<H, T>>,
    queue_progress: AtomicU64,
    queue_waiters: WaitQueue,
    submitted: AtomicU64,
    completed: AtomicU64,
    queue_full_retries: AtomicU64,
    interrupts: AtomicU64,
    fallback_polls: AtomicU64,
    short_poll_completions: AtomicU64,
    cooperative_yields: AtomicU64,
    stall_warnings: AtomicU64,
    stuck_warnings: AtomicU64,
    in_flight: AtomicUsize,
    peak_in_flight: AtomicUsize,
}

impl<H: Hal, T: Transport> AsyncVirtIOBlock<H, T> {
    pub fn new(mut device: VirtIOBlk<H, T>) -> Self {
        device.enable_interrupts();
        let queue_size = usize::from(device.virt_queue_size());
        assert!(queue_size <= MAX_TRACKED_REQUESTS);
        Self {
            state: Mutex::new(DriverState {
                device,
                requests: (0..queue_size).map(|_| None).collect(),
            }),
            queue_progress: AtomicU64::new(0),
            queue_waiters: WaitQueue::new(),
            submitted: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            queue_full_retries: AtomicU64::new(0),
            interrupts: AtomicU64::new(0),
            fallback_polls: AtomicU64::new(0),
            short_poll_completions: AtomicU64::new(0),
            cooperative_yields: AtomicU64::new(0),
            stall_warnings: AtomicU64::new(0),
            stuck_warnings: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
            peak_in_flight: AtomicUsize::new(0),
        }
    }

    pub fn read_blocks(&self, sector: usize, output: &mut [u8]) -> virtio_drivers::Result {
        if output.is_empty() {
            return Ok(());
        }
        let request = Arc::new(BlockRequest::new(
            RequestKind::Read,
            sector,
            NonNull::new(output.as_mut_ptr()).expect("non-empty block buffer"),
            output.len(),
        ));
        self.submit_and_wait(sector, request)
    }

    pub fn write_blocks(&self, sector: usize, input: &[u8]) -> virtio_drivers::Result {
        if input.is_empty() {
            return Ok(());
        }
        let request = Arc::new(BlockRequest::new(
            RequestKind::Write,
            sector,
            NonNull::new(input.as_ptr() as *mut u8).expect("non-empty block buffer"),
            input.len(),
        ));
        self.submit_and_wait(sector, request)
    }

    fn submit_and_wait(&self, sector: usize, request: Arc<BlockRequest>) -> virtio_drivers::Result {
        loop {
            // Snapshot progress before attempting submission.  If the queue
            // is full, every completion that could make descriptors
            // available must advance this generation after this load.  This
            // is the same prepare-to-wait ordering used by Linux wait queues:
            // publish/observe the wait condition before checking it, then
            // recheck after enqueueing to avoid a lost wakeup.
            let observed = self.queue_progress.load(Ordering::Acquire);
            let submission = {
                // Linux virtio_queue_rq() protects the virtqueue with
                // spin_lock_irqsave because virtblk_done() takes the same lock
                // in hardirq context.
                let _irq_guard = LocalIrqSaveGuard::new();
                let mut state = self.state.lock();
                // SAFETY: `request` owns stable buffers and the request table
                // retains it until the matching descriptor chain is popped.
                unsafe {
                    let buffers = &mut *request.buffers.get();
                    match request.kind {
                        RequestKind::Read => {
                            let data = core::slice::from_raw_parts_mut(
                                buffers.data.as_ptr(),
                                buffers.data_len,
                            );
                            state.device.read_blocks_nb(
                                sector,
                                &mut buffers.request,
                                data,
                                &mut buffers.response,
                            )
                        }
                        RequestKind::Write => {
                            let data = core::slice::from_raw_parts(
                                buffers.data.as_ptr(),
                                buffers.data_len,
                            );
                            state.device.write_blocks_nb(
                                sector,
                                &mut buffers.request,
                                data,
                                &mut buffers.response,
                            )
                        }
                    }
                }
                .map(|token| {
                    let slot = &mut state.requests[usize::from(token)];
                    assert!(
                        slot.is_none(),
                        "VirtIO token reused while request is active"
                    );
                    *slot = Some(Arc::clone(&request));
                    // Publish ownership and accounting before releasing the
                    // queue lock.  A fast device may already have completed,
                    // but its IRQ handler cannot pop this token until these
                    // fields are visible.
                    request.mark_submitted();
                    self.submitted.fetch_add(1, Ordering::Relaxed);
                    let in_flight = self.in_flight.fetch_add(1, Ordering::AcqRel) + 1;
                    self.peak_in_flight.fetch_max(in_flight, Ordering::Relaxed);
                })
            };

            match submission {
                Ok(()) => break,
                Err(Error::QueueFull) => {
                    self.queue_full_retries.fetch_add(1, Ordering::Relaxed);
                    if crate::task::processor::current_task().is_none() {
                        while self.queue_progress.load(Ordering::Acquire) == observed {
                            self.poll();
                            core::hint::spin_loop();
                        }
                    } else {
                        self.queue_waiters
                            .wait_until(|| self.queue_progress.load(Ordering::Acquire) != observed);
                    }
                }
                Err(error) => return Err(error),
            }
        }

        if crate::task::processor::current_task().is_none() {
            while !request.completed.load(Ordering::Acquire) {
                self.poll();
                core::hint::spin_loop();
            }
        } else {
            let mut polled_completions = 0;
            while !request.completed.load(Ordering::Acquire) {
                for spin in 0..COMPLETION_POLL_SPINS {
                    if request.completed.load(Ordering::Acquire) {
                        break;
                    }
                    polled_completions += self.drain_used(InterruptAck::IfCompleted).1;
                    if request.completed.load(Ordering::Acquire) {
                        break;
                    }
                    // Match Linux blk_hctx_poll(): stop burning CPU once the
                    // scheduler has higher-priority work to run.
                    if spin % 8 == 7 && crate::task::processor::should_resched_for_busy_poll() {
                        break;
                    }
                    core::hint::spin_loop();
                }
                if !request.completed.load(Ordering::Acquire) {
                    // Linux's poll loop returns at need_resched/budget expiry.
                    // Our minimal block layer has no upper completion waiter,
                    // so yield to the scheduler and resume polling. Keep the
                    // request uninterruptible while DMA owns its buffers.
                    self.cooperative_yields.fetch_add(1, Ordering::Relaxed);
                    crate::task::processor::suspend_current_and_run_next_uninterruptible();
                }
            }
            self.short_poll_completions
                .fetch_add(polled_completions as u64, Ordering::Relaxed);
        }
        request.result()
    }

    fn drain_used(&self, interrupt_ack: InterruptAck) -> (bool, usize) {
        let mut completed_requests: [Option<Arc<BlockRequest>>; MAX_TRACKED_REQUESTS] =
            [const { None }; MAX_TRACKED_REQUESTS];
        let (acknowledged, completed_count) = {
            let _irq_guard = LocalIrqSaveGuard::new();
            let mut state = self.state.lock();
            let mut completed_count = 0;
            while let Some(token) = state.device.peek_used() {
                let request = state.requests[usize::from(token)]
                    .take()
                    .expect("VirtIO used ring returned an unknown token");
                // SAFETY: the table entry proves that these are the exact
                // buffers used to submit `token`, and the device returned it.
                let result = unsafe {
                    let buffers = &mut *request.buffers.get();
                    match request.kind {
                        RequestKind::Read => {
                            let data = core::slice::from_raw_parts_mut(
                                buffers.data.as_ptr(),
                                buffers.data_len,
                            );
                            state.device.complete_read_blocks(
                                token,
                                &buffers.request,
                                data,
                                &mut buffers.response,
                            )
                        }
                        RequestKind::Write => {
                            let data = core::slice::from_raw_parts(
                                buffers.data.as_ptr(),
                                buffers.data_len,
                            );
                            state.device.complete_write_blocks(
                                token,
                                &buffers.request,
                                data,
                                &mut buffers.response,
                            )
                        }
                    }
                };
                request.complete(result);
                completed_requests[completed_count] = Some(request);
                completed_count += 1;
            }
            // Pollers avoid an MMIO interrupt-status read on every empty
            // iteration.  Once they consume work they acknowledge the pending
            // level interrupt before local IRQs are restored.  The hardirq
            // path always acknowledges, including spurious/config interrupts.
            let acknowledged = match interrupt_ack {
                InterruptAck::Always => state.device.ack_interrupt(),
                InterruptAck::IfCompleted if completed_count != 0 => state.device.ack_interrupt(),
                InterruptAck::IfCompleted => false,
            };
            (acknowledged, completed_count)
        };

        for request in completed_requests
            .into_iter()
            .take(completed_count)
            .flatten()
        {
            self.completed.fetch_add(1, Ordering::Relaxed);
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            self.queue_progress.fetch_add(1, Ordering::Release);
            request.waiters.wake_one();
            self.queue_waiters.wake_one();
        }
        (acknowledged, completed_count)
    }

    fn check_stalled_requests(&self) {
        let mut active: [Option<Arc<BlockRequest>>; MAX_TRACKED_REQUESTS] =
            [const { None }; MAX_TRACKED_REQUESTS];
        let (active_count, queue_state) = {
            let _irq_guard = LocalIrqSaveGuard::new();
            let state = self.state.lock();
            let mut count = 0;
            for request in state.requests.iter().flatten() {
                active[count] = Some(Arc::clone(request));
                count += 1;
            }
            (count, state.device.queue_state())
        };
        let now_ms = crate::time::get_time_ms();
        for request in active.into_iter().take(active_count).flatten() {
            let Some(elapsed_ms) = request.elapsed_ms(now_ms) else {
                continue;
            };
            if elapsed_ms >= STUCK_WARNING_MS
                && request
                    .stuck_warned
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                self.stuck_warnings.fetch_add(1, Ordering::Relaxed);
                crate::println!(
                    "[virtio-blk][error] {} sector={} pending={}ms q={} avail={} used={} consumed={} descriptors={}",
                    request.kind_name(),
                    request.sector,
                    elapsed_ms,
                    queue_state.queue_index,
                    queue_state.available_index,
                    queue_state.used_index,
                    queue_state.last_used_index,
                    queue_state.descriptors_in_use
                );
            } else if elapsed_ms >= STALL_WARNING_MS
                && request
                    .stall_warned
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                self.stall_warnings.fetch_add(1, Ordering::Relaxed);
                crate::println!(
                    "[virtio-blk][warn] {} sector={} pending={}ms q={} avail={} used={} consumed={} descriptors={}",
                    request.kind_name(),
                    request.sector,
                    elapsed_ms,
                    queue_state.queue_index,
                    queue_state.available_index,
                    queue_state.used_index,
                    queue_state.last_used_index,
                    queue_state.descriptors_in_use
                );
            }
        }
    }

    /// Complete all buffers returned by the device interrupt.
    pub fn handle_interrupt(&self) -> bool {
        self.interrupts.fetch_add(1, Ordering::Relaxed);
        let (acknowledged, completed) = self.drain_used(InterruptAck::Always);
        acknowledged || completed != 0
    }

    /// Early-boot and watchdog fallback. Runtime completion normally uses IRQs.
    pub fn poll(&self) -> usize {
        if self.in_flight.load(Ordering::Acquire) == 0 {
            return 0;
        }
        self.fallback_polls.fetch_add(1, Ordering::Relaxed);
        let completed = self.drain_used(InterruptAck::Always).1;
        self.check_stalled_requests();
        completed
    }

    pub fn diagnostics(&self) -> AsyncBlockDiagnostics {
        AsyncBlockDiagnostics {
            submitted: self.submitted.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            queue_full_retries: self.queue_full_retries.load(Ordering::Relaxed),
            interrupts: self.interrupts.load(Ordering::Relaxed),
            fallback_polls: self.fallback_polls.load(Ordering::Relaxed),
            short_poll_completions: self.short_poll_completions.load(Ordering::Relaxed),
            cooperative_yields: self.cooperative_yields.load(Ordering::Relaxed),
            stall_warnings: self.stall_warnings.load(Ordering::Relaxed),
            stuck_warnings: self.stuck_warnings.load(Ordering::Relaxed),
            in_flight: self.in_flight.load(Ordering::Relaxed),
            peak_in_flight: self.peak_in_flight.load(Ordering::Relaxed),
        }
    }
}
