//! Kernel log ring buffer for `dmesg` (`syslog(2)` / `klogctl(2)`).
//!
//! We keep a fixed-size in-memory ring buffer and append all console output to it.
//! Userspace can retrieve it via syscall 116.

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;

const KLOG_CAPACITY: usize = 256 * 1024;

struct KlogInner {
    buf: [u8; KLOG_CAPACITY],
    head: usize, // next write position
    len: usize,  // number of valid bytes in buffer (<= capacity)
}

impl KlogInner {
    const fn new() -> Self {
        Self {
            buf: [0u8; KLOG_CAPACITY],
            head: 0,
            len: 0,
        }
    }

    fn capacity(&self) -> usize {
        KLOG_CAPACITY
    }

    fn tail(&self) -> usize {
        (self.head + KLOG_CAPACITY - self.len) % KLOG_CAPACITY
    }

    fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    fn append(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.buf[self.head] = b;
            self.head += 1;
            if self.head == KLOG_CAPACITY {
                self.head = 0;
            }
            if self.len < KLOG_CAPACITY {
                self.len += 1;
            }
        }
    }

    fn snapshot(&self, max_len: usize) -> Vec<u8> {
        let to_copy = self.len.min(max_len);
        let mut out = Vec::with_capacity(to_copy);
        if to_copy == 0 {
            return out;
        }
        let tail = self.tail();
        let first = (KLOG_CAPACITY - tail).min(to_copy);
        out.extend_from_slice(&self.buf[tail..tail + first]);
        let remain = to_copy - first;
        if remain > 0 {
            out.extend_from_slice(&self.buf[..remain]);
        }
        out
    }
}

static KLOG: Mutex<KlogInner> = Mutex::new(KlogInner::new());

pub fn capacity() -> usize {
    KLOG.lock().capacity()
}

pub fn len() -> usize {
    KLOG.lock().len
}

pub fn clear() {
    KLOG.lock().clear();
}

pub fn append_bytes(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    KLOG.lock().append(bytes);
}

pub fn append_str(s: &str) {
    append_bytes(s.as_bytes());
}

pub fn snapshot(max_len: usize) -> Vec<u8> {
    KLOG.lock().snapshot(max_len)
}

pub fn snapshot_and_clear(max_len: usize) -> Vec<u8> {
    let mut inner = KLOG.lock();
    let out = inner.snapshot(max_len);
    inner.clear();
    out
}
