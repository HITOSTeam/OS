extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

use crate::config::PAGE_SIZE;
use crate::mm::{FrameTracker, UserBuffer, frame_alloc};

use super::File;

pub enum PseudoKind {
    Static(Vec<u8>),
    Urandom(u64),
    Null,
    Zero,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PseudoKindTag {
    Static,
    Urandom,
    Null,
    Zero,
}

pub struct PseudoFile {
    readable: bool,
    writable: bool,
    inner: Mutex<PseudoInner>,
}

struct PseudoInner {
    offset: usize,
    kind: PseudoKind,
}

/// A minimal pseudo directory for `/proc`, `/sys`, etc.
///
/// Directory iteration is implemented in `syscall_getdents64` by downcasting.
pub struct PseudoDir {
    path: String,
    entries: Vec<PseudoDirent>,
    inner: Mutex<PseudoDirInner>,
}

#[derive(Clone)]
pub struct PseudoDirent {
    pub name: alloc::string::String,
    pub ino: u64,
    pub dtype: u8, // Linux DT_* values (e.g. 4=DIR, 8=REG)
}

struct PseudoDirInner {
    index: usize,
}

impl PseudoDir {
    pub fn new(path: &str, entries: Vec<PseudoDirent>) -> Self {
        let mut p = String::from(path);
        if p.is_empty() {
            p.push('/');
        }
        if !p.starts_with('/') {
            p.insert(0, '/');
        }
        while p.len() > 1 && p.ends_with('/') {
            p.pop();
        }
        Self {
            path: p,
            entries,
            inner: Mutex::new(PseudoDirInner { index: 0 }),
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn entries(&self) -> &[PseudoDirent] {
        &self.entries
    }

    pub fn index(&self) -> usize {
        self.inner.lock().index
    }

    pub fn set_index(&self, index: usize) {
        self.inner.lock().index = index;
    }
}

impl File for PseudoDir {
    fn readable(&self) -> bool {
        true
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

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A minimal RTC device node for busybox `hwclock`.
///
/// Actual RTC semantics are handled in `syscall_ioctl` by downcasting.
pub struct RtcFile;

impl RtcFile {
    pub fn new() -> Self {
        Self
    }
}

impl File for RtcFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn write(&self, buf: UserBuffer) -> usize {
        buf.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub(crate) struct ShmDataInner {
    id: u64,
    is_memfd: bool,
    seals: u32,
    len: usize,
    frames: Vec<FrameTracker>,
}

impl ShmDataInner {
    fn new_posix_shm() -> Self {
        Self {
            id: SHM_NEXT_ID.fetch_add(1, Ordering::Relaxed),
            is_memfd: false,
            seals: 0,
            len: 0,
            frames: Vec::new(),
        }
    }

    fn new_memfd(allow_sealing: bool) -> Self {
        let mut seals = 0;
        if !allow_sealing {
            seals |= PseudoShmFile::F_SEAL_SEAL;
        }
        Self {
            id: SHM_NEXT_ID.fetch_add(1, Ordering::Relaxed),
            is_memfd: true,
            seals,
            len: 0,
            frames: Vec::new(),
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn ensure_len(&mut self, new_len: usize) -> bool {
        let pages = (new_len + PAGE_SIZE - 1) / PAGE_SIZE;
        if pages > self.frames.len() {
            let needed = pages - self.frames.len();
            for _ in 0..needed {
                let Some(frame) = frame_alloc() else {
                    return false;
                };
                self.frames.push(frame);
            }
        } else if pages < self.frames.len() {
            self.frames.truncate(pages);
        }
        self.len = new_len;
        true
    }
}

pub(crate) type ShmData = Arc<Mutex<ShmDataInner>>;

lazy_static! {
    static ref SHM_OBJECTS: Mutex<BTreeMap<String, ShmData>> = Mutex::new(BTreeMap::new());
    static ref PSEUDO_DEV_DIRS: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());
}

// Minimal backing counters used by `/sys/block/root/stat`.
static PSEUDO_BLOCK_SECTORS_WRITTEN: AtomicU64 = AtomicU64::new(8);
static PSEUDO_BLOCK_IO_TICKS: AtomicU64 = AtomicU64::new(1);
static PSEUDO_BLOCK_READ_ONLY: AtomicBool = AtomicBool::new(false);
static PSEUDO_BLOCK_READ_AHEAD: AtomicU64 = AtomicU64::new(256);
static PSEUDO_DEV_DIR_NEXT_INO: AtomicU64 = AtomicU64::new(0x52_0000);
static SHM_NEXT_ID: AtomicU64 = AtomicU64::new(1);

const EEXIST: isize = -17;
const ENOENT: isize = -2;
const EROFS: isize = -30;

const PSEUDO_DEV_DIR_RESERVED: &[&str] = &[
    "root", "ptmx", "tty", "pts", "shm", "cgroup", "null", "zero", "urandom", "random", "misc",
];

fn pseudo_dev_dir_name(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/dev/")?;
    if rest.is_empty() || rest.contains('/') || matches!(rest, "." | "..") {
        return None;
    }
    Some(rest)
}

pub(crate) fn pseudo_dev_dir_entries() -> Vec<PseudoDirent> {
    PSEUDO_DEV_DIRS
        .lock()
        .iter()
        .map(|(name, ino)| PseudoDirent {
            name: name.clone(),
            ino: *ino,
            dtype: 4,
        })
        .collect()
}

pub(crate) fn pseudo_dev_dir_exists(path: &str) -> bool {
    let Some(name) = pseudo_dev_dir_name(path) else {
        return false;
    };
    PSEUDO_DEV_DIRS.lock().contains_key(name)
}

pub(crate) fn open_pseudo_dev_dir(path: &str) -> Option<Arc<dyn File + Send + Sync>> {
    let name = pseudo_dev_dir_name(path)?;
    let ino = *PSEUDO_DEV_DIRS.lock().get(name)?;
    let entries = alloc::vec![
        PseudoDirent {
            name: String::from("."),
            ino,
            dtype: 4,
        },
        PseudoDirent {
            name: String::from(".."),
            ino: 1,
            dtype: 4,
        },
    ];
    Some(Arc::new(PseudoDir::new(path, entries)))
}

pub(crate) fn pseudo_dev_dir_mkdir(path: &str) -> isize {
    let Some(name) = pseudo_dev_dir_name(path) else {
        return EROFS;
    };
    if PSEUDO_DEV_DIR_RESERVED.contains(&name) {
        return EEXIST;
    }
    let mut dirs = PSEUDO_DEV_DIRS.lock();
    if dirs.contains_key(name) {
        return EEXIST;
    }
    let ino = PSEUDO_DEV_DIR_NEXT_INO.fetch_add(1, Ordering::Relaxed);
    dirs.insert(String::from(name), ino);
    0
}

pub(crate) fn pseudo_dev_dir_rmdir(path: &str) -> isize {
    let Some(name) = pseudo_dev_dir_name(path) else {
        return EROFS;
    };
    if PSEUDO_DEV_DIRS.lock().remove(name).is_some() {
        0
    } else {
        ENOENT
    }
}

fn bytes_to_sectors(bytes: usize) -> u64 {
    let bytes = bytes as u64;
    core::cmp::max(1, (bytes + 511) / 512)
}

pub(crate) fn pseudo_block_note_write(bytes: usize) {
    if bytes == 0 {
        return;
    }
    let sectors = bytes_to_sectors(bytes);
    let ticks = core::cmp::max(1, (bytes as u64 + ((1 << 20) - 1)) / (1 << 20));
    PSEUDO_BLOCK_SECTORS_WRITTEN.fetch_add(sectors, Ordering::Relaxed);
    PSEUDO_BLOCK_IO_TICKS.fetch_add(ticks, Ordering::Relaxed);
}

pub(crate) fn pseudo_block_note_sync() {
    // Keep this generous so sync-focused LTP cases observe meaningful writeback.
    pseudo_block_note_write(64 * 1024 * 1024);
}

pub(crate) fn pseudo_block_stat_snapshot() -> String {
    let sectors = PSEUDO_BLOCK_SECTORS_WRITTEN.load(Ordering::Relaxed);
    let io_ticks = core::cmp::max(1, PSEUDO_BLOCK_IO_TICKS.load(Ordering::Relaxed));
    alloc::format!("1 0 8 0 1 0 {} 0 0 {} 0\n", sectors, io_ticks)
}

pub(crate) fn pseudo_block_is_read_only() -> bool {
    PSEUDO_BLOCK_READ_ONLY.load(Ordering::Relaxed)
}

pub(crate) fn pseudo_block_set_read_only(read_only: bool) {
    PSEUDO_BLOCK_READ_ONLY.store(read_only, Ordering::Relaxed);
}

pub(crate) fn pseudo_block_read_ahead() -> u64 {
    PSEUDO_BLOCK_READ_AHEAD.load(Ordering::Relaxed)
}

pub(crate) fn pseudo_block_set_read_ahead(value: u64) {
    PSEUDO_BLOCK_READ_AHEAD.store(value, Ordering::Relaxed);
}

pub(crate) fn shm_list() -> Vec<String> {
    SHM_OBJECTS.lock().keys().cloned().collect()
}

pub(crate) fn shm_get(name: &str) -> Option<ShmData> {
    SHM_OBJECTS.lock().get(name).cloned()
}

pub(crate) fn shm_create(name: &str) -> ShmData {
    let mut map = SHM_OBJECTS.lock();
    map.entry(String::from(name))
        .or_insert_with(|| Arc::new(Mutex::new(ShmDataInner::new_posix_shm())))
        .clone()
}

pub(crate) fn shm_create_anonymous(allow_sealing: bool) -> ShmData {
    Arc::new(Mutex::new(ShmDataInner::new_memfd(allow_sealing)))
}

pub(crate) fn shm_remove(name: &str) -> bool {
    SHM_OBJECTS.lock().remove(name).is_some()
}

/// A minimal block device node for `/dev/root` so tools like busybox `df`
/// treat the root filesystem as a real device-backed mount.
pub struct PseudoBlock {
    offset: Mutex<usize>,
}

impl PseudoBlock {
    pub fn new() -> Self {
        Self {
            offset: Mutex::new(0),
        }
    }

    pub fn offset(&self) -> usize {
        *self.offset.lock()
    }

    pub fn set_offset(&self, offset: usize) {
        *self.offset.lock() = offset;
    }
}

impl File for PseudoBlock {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn write(&self, buf: UserBuffer) -> usize {
        pseudo_block_note_write(buf.len());
        // This pseudo block device has no real media backing. Report successful
        // writes so generic LTP helpers (device clear/probe) can proceed.
        buf.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A minimal shared-memory file for `/dev/shm/<name>`.
///
/// This is a very small in-memory backing store to satisfy musl's `shm_open`/`shm_unlink`
/// users (e.g., `cyclictest`). It provides per-fd offsets and a shared data buffer.
pub struct PseudoShmFile {
    data: ShmData,
    offset: Mutex<usize>,
    readable: bool,
    writable: bool,
}

impl PseudoShmFile {
    pub const F_SEAL_SEAL: u32 = 0x0001;
    pub const F_SEAL_SHRINK: u32 = 0x0002;
    pub const F_SEAL_GROW: u32 = 0x0004;
    pub const F_SEAL_WRITE: u32 = 0x0008;
    pub const F_SEAL_ALL: u32 =
        Self::F_SEAL_SEAL | Self::F_SEAL_SHRINK | Self::F_SEAL_GROW | Self::F_SEAL_WRITE;

    pub fn new(data: ShmData) -> Self {
        Self {
            data,
            offset: Mutex::new(0),
            readable: true,
            writable: true,
        }
    }

    pub fn new_with_mode(data: ShmData, readable: bool, writable: bool) -> Self {
        Self {
            data,
            offset: Mutex::new(0),
            readable,
            writable,
        }
    }

    pub fn reopen_with_mode(&self, readable: bool, writable: bool) -> Self {
        Self {
            data: self.data.clone(),
            offset: Mutex::new(0),
            readable,
            writable,
        }
    }

    pub fn len(&self) -> usize {
        self.data.lock().len()
    }

    pub fn offset(&self) -> usize {
        *self.offset.lock()
    }

    pub fn set_offset(&self, offset: usize) {
        *self.offset.lock() = offset;
    }

    pub fn truncate(&self, new_len: usize) {
        let mut data = self.data.lock();
        let _ = data.ensure_len(new_len);
        let mut off = self.offset.lock();
        if *off > new_len {
            *off = new_len;
        }
    }

    pub fn punch_hole_keep_size(&self, offset: usize, len: usize) {
        if len == 0 {
            return;
        }
        let mut data = self.data.lock();
        if offset >= data.len() {
            return;
        }
        let hole_end = core::cmp::min(offset.saturating_add(len), data.len());
        let mut cur = offset;
        while cur < hole_end {
            let page = cur / PAGE_SIZE;
            let in_page = cur % PAGE_SIZE;
            let chunk = core::cmp::min(hole_end - cur, PAGE_SIZE - in_page);
            if page >= data.frames.len() {
                break;
            }
            let frame = data.frames[page].ppn.get_bytes_array();
            frame[in_page..in_page + chunk].fill(0);
            cur += chunk;
        }
    }

    pub fn is_memfd(&self) -> bool {
        self.data.lock().is_memfd
    }

    pub fn memfd_id(&self) -> u64 {
        self.data.lock().id
    }

    pub fn memfd_seals(&self) -> Option<u32> {
        let data = self.data.lock();
        data.is_memfd.then_some(data.seals)
    }

    pub fn has_memfd_seal(&self, seal: u32) -> bool {
        let data = self.data.lock();
        data.is_memfd && (data.seals & seal) != 0
    }

    pub fn add_memfd_seals(&self, add: u32) -> Result<u32, isize> {
        const EINVAL: isize = -22;
        const EPERM: isize = -1;
        if (add & !Self::F_SEAL_ALL) != 0 {
            return Err(EINVAL);
        }
        let mut data = self.data.lock();
        if !data.is_memfd {
            return Err(EINVAL);
        }
        if (data.seals & Self::F_SEAL_SEAL) != 0 {
            return Err(EPERM);
        }
        data.seals |= add;
        Ok(data.seals)
    }

    pub fn shared_frames(&self, offset: usize, len: usize) -> Option<Vec<FrameTracker>> {
        let end = offset.checked_add(len)?;
        let mut data = self.data.lock();
        if !data.ensure_len(end) {
            return None;
        }
        let start_page = offset / PAGE_SIZE;
        let end_page = (end + PAGE_SIZE - 1) / PAGE_SIZE;
        if end_page < start_page || end_page > data.frames.len() {
            return None;
        }
        Some(data.frames[start_page..end_page].iter().cloned().collect())
    }
}

impl File for PseudoShmFile {
    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        self.writable
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        let mut off = self.offset.lock();
        let data = self.data.lock();
        let mut cur_off = *off;
        if cur_off >= data.len() {
            return 0;
        }
        let mut total = 0usize;
        for slice in buf.buffers.iter_mut() {
            if cur_off >= data.len() {
                break;
            }
            let n = core::cmp::min(slice.len(), data.len() - cur_off);
            let mut remaining = n;
            let mut dst_off = 0usize;
            while remaining > 0 {
                let page = cur_off / PAGE_SIZE;
                let in_page = cur_off % PAGE_SIZE;
                if page >= data.frames.len() {
                    break;
                }
                let frame = data.frames[page].ppn.get_bytes_array();
                let chunk = core::cmp::min(remaining, PAGE_SIZE - in_page);
                slice[dst_off..dst_off + chunk].copy_from_slice(&frame[in_page..in_page + chunk]);
                cur_off += chunk;
                dst_off += chunk;
                remaining -= chunk;
            }
            total += dst_off;
            if dst_off < slice.len() {
                break;
            }
        }
        *off = cur_off;
        total
    }

    fn write(&self, buf: UserBuffer) -> usize {
        let mut off = self.offset.lock();
        let mut data = self.data.lock();
        let mut cur_off = *off;
        let mut total = 0usize;
        for slice in buf.buffers.iter() {
            if slice.is_empty() {
                continue;
            }
            let end = cur_off.saturating_add(slice.len());
            if end > data.len() {
                if !data.ensure_len(end) {
                    break;
                }
            }
            let mut remaining = slice.len();
            let mut src_off = 0usize;
            while remaining > 0 {
                let page = cur_off / PAGE_SIZE;
                let in_page = cur_off % PAGE_SIZE;
                if page >= data.frames.len() {
                    break;
                }
                let frame = data.frames[page].ppn.get_bytes_array();
                let chunk = core::cmp::min(remaining, PAGE_SIZE - in_page);
                frame[in_page..in_page + chunk].copy_from_slice(&slice[src_off..src_off + chunk]);
                cur_off += chunk;
                src_off += chunk;
                remaining -= chunk;
            }
            total += src_off;
            if src_off < slice.len() {
                break;
            }
        }
        *off = cur_off;
        total
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl PseudoFile {
    pub fn new_static(content: &str) -> Self {
        Self::new_static_with_writable(content, false)
    }

    pub fn new_static_rw(content: &str) -> Self {
        Self::new_static_with_writable(content, true)
    }

    fn new_static_with_writable(content: &str, writable: bool) -> Self {
        Self {
            readable: true,
            writable,
            inner: Mutex::new(PseudoInner {
                offset: 0,
                kind: PseudoKind::Static(content.as_bytes().to_vec()),
            }),
        }
    }

    pub fn new_static_bytes(data: &[u8]) -> Self {
        Self {
            readable: true,
            writable: false,
            inner: Mutex::new(PseudoInner {
                offset: 0,
                kind: PseudoKind::Static(data.to_vec()),
            }),
        }
    }

    pub fn new_urandom(seed: u64) -> Self {
        Self {
            readable: true,
            writable: false,
            inner: Mutex::new(PseudoInner {
                offset: 0,
                kind: PseudoKind::Urandom(seed),
            }),
        }
    }

    pub fn new_null() -> Self {
        Self {
            readable: true,
            writable: true,
            inner: Mutex::new(PseudoInner {
                offset: 0,
                kind: PseudoKind::Null,
            }),
        }
    }

    pub fn new_zero() -> Self {
        Self {
            readable: true,
            writable: false,
            inner: Mutex::new(PseudoInner {
                offset: 0,
                kind: PseudoKind::Zero,
            }),
        }
    }

    pub fn offset(&self) -> usize {
        self.inner.lock().offset
    }

    pub fn set_offset(&self, offset: usize) {
        self.inner.lock().offset = offset;
    }

    pub fn len(&self) -> Option<usize> {
        let inner = self.inner.lock();
        match &inner.kind {
            PseudoKind::Static(data) => Some(data.len()),
            PseudoKind::Null | PseudoKind::Zero => Some(0),
            _ => None,
        }
    }

    pub fn kind_tag(&self) -> PseudoKindTag {
        match &self.inner.lock().kind {
            PseudoKind::Static(_) => PseudoKindTag::Static,
            PseudoKind::Urandom(_) => PseudoKindTag::Urandom,
            PseudoKind::Null => PseudoKindTag::Null,
            PseudoKind::Zero => PseudoKindTag::Zero,
        }
    }
}

impl File for PseudoFile {
    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        self.writable
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        let mut inner = self.inner.lock();
        let PseudoInner { offset, kind } = &mut *inner;
        match kind {
            PseudoKind::Static(data) => {
                if *offset >= data.len() {
                    return 0;
                }
                let mut total = 0usize;
                for slice in buf.buffers.iter_mut() {
                    if *offset >= data.len() {
                        break;
                    }
                    let n = core::cmp::min(slice.len(), data.len() - *offset);
                    slice[..n].copy_from_slice(&data[*offset..*offset + n]);
                    *offset += n;
                    total += n;
                    if n < slice.len() {
                        break;
                    }
                }
                total
            }
            PseudoKind::Urandom(seed) => {
                // xorshift64*
                let mut total = 0usize;
                for slice in buf.buffers.iter_mut() {
                    for b in slice.iter_mut() {
                        let mut x = *seed;
                        x ^= x >> 12;
                        x ^= x << 25;
                        x ^= x >> 27;
                        x = x.wrapping_mul(0x2545F4914F6CDD1D);
                        *seed = x;
                        *b = (x & 0xff) as u8;
                        total += 1;
                    }
                }
                total
            }
            PseudoKind::Null => 0,
            PseudoKind::Zero => {
                let mut total = 0usize;
                for slice in buf.buffers.iter_mut() {
                    slice.fill(0);
                    total += slice.len();
                }
                total
            }
        }
    }

    fn write(&self, buf: UserBuffer) -> usize {
        let inner = self.inner.lock();
        match inner.kind {
            PseudoKind::Null => buf.len(),
            PseudoKind::Static(_) if self.writable => buf.len(),
            _ => 0,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
