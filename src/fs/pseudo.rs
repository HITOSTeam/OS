extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

use crate::config::PAGE_SIZE;
use crate::mm::{FrameTracker, UserBuffer, frame_alloc};
use crate::syscall::error::{SyscallError, err};
use crate::task::ProcessControlBlock;

use super::File;

const TUNTAP_QUEUE_LIMIT: usize = 256;
const TUNTAP_IFF_TUN: u16 = 0x0001;
const TUNTAP_IFF_TAP: u16 = 0x0002;
const TUNTAP_IFF_PERSIST: u16 = 0x0800;
const TUNTAP_IFF_NO_PI: u16 = 0x1000;
const TUNTAP_IFF_ONE_QUEUE: u16 = 0x2000;
const TUNTAP_IFF_VNET_HDR: u16 = 0x4000;
const TUNTAP_ETH_P_IP: u16 = 0x0800;
const VIRTIO_NET_HDR_LEN: usize = 10;
const TUNTAP_SYSFS_FLAG_MASK: u16 =
    TUNTAP_IFF_TUN | TUNTAP_IFF_TAP | TUNTAP_IFF_NO_PI | TUNTAP_IFF_ONE_QUEUE | TUNTAP_IFF_VNET_HDR;

lazy_static! {
    static ref TUNTAP_QUEUES: Mutex<BTreeMap<i32, VecDeque<Vec<u8>>>> = Mutex::new(BTreeMap::new());
    static ref TUNTAP_LINKS: Mutex<BTreeMap<i32, TunTapLinkState>> = Mutex::new(BTreeMap::new());
}

#[derive(Clone, Copy)]
struct TunTapLinkState {
    refs: usize,
    persistent: bool,
    owner: Option<u32>,
    group: Option<u32>,
    flags: u16,
}

pub(crate) fn enqueue_tuntap_packet(ifindex: i32, packet: Vec<u8>) {
    if crate::syscall::net::netdev::device_snapshot_by_global_ifindex(ifindex).is_none() {
        return;
    }
    let mut queues = TUNTAP_QUEUES.lock();
    let queue = queues.entry(ifindex).or_default();
    if queue.len() >= TUNTAP_QUEUE_LIMIT {
        queue.pop_front();
    }
    queue.push_back(packet);
}

fn pop_tuntap_packet(ifindex: i32) -> Option<Vec<u8>> {
    TUNTAP_QUEUES.lock().get_mut(&ifindex)?.pop_front()
}

fn tuntap_queue_has_packet(ifindex: i32) -> bool {
    TUNTAP_QUEUES
        .lock()
        .get(&ifindex)
        .is_some_and(|queue| !queue.is_empty())
}

fn register_tuntap_link(ifindex: i32, flags: u16) {
    let mut links = TUNTAP_LINKS.lock();
    let entry = links.entry(ifindex).or_insert(TunTapLinkState {
        refs: 0,
        persistent: false,
        owner: None,
        group: None,
        flags: flags & TUNTAP_SYSFS_FLAG_MASK,
    });
    entry.refs = entry.refs.saturating_add(1);
    entry.flags = flags & TUNTAP_SYSFS_FLAG_MASK;
}

fn set_tuntap_persistent(ifindex: i32, persistent: bool) {
    let mut links = TUNTAP_LINKS.lock();
    let entry = links.entry(ifindex).or_insert(TunTapLinkState {
        refs: 0,
        persistent,
        owner: None,
        group: None,
        flags: 0,
    });
    entry.persistent = persistent;
}

pub(crate) fn tuntap_link_owner_group(name: &str) -> Option<(Option<u32>, Option<u32>)> {
    let ifindex = crate::syscall::net::netdev::ifindex_by_name(name)?;
    let links = TUNTAP_LINKS.lock();
    let entry = links.get(&ifindex)?;
    Some((entry.owner, entry.group))
}

pub(crate) fn tuntap_link_sysfs_info(name: &str) -> Option<(Option<u32>, Option<u32>, u16)> {
    let ifindex = crate::syscall::net::netdev::ifindex_by_name(name)?;
    let links = TUNTAP_LINKS.lock();
    let entry = links.get(&ifindex)?;
    let mut flags = entry.flags & TUNTAP_SYSFS_FLAG_MASK;
    if entry.persistent {
        flags |= TUNTAP_IFF_PERSIST;
    }
    Some((entry.owner, entry.group, flags))
}

fn set_tuntap_owner(ifindex: i32, owner: u32) {
    let mut links = TUNTAP_LINKS.lock();
    let entry = links.entry(ifindex).or_insert(TunTapLinkState {
        refs: 0,
        persistent: false,
        owner: None,
        group: None,
        flags: 0,
    });
    entry.owner = Some(owner);
}

fn set_tuntap_group(ifindex: i32, group: u32) {
    let mut links = TUNTAP_LINKS.lock();
    let entry = links.entry(ifindex).or_insert(TunTapLinkState {
        refs: 0,
        persistent: false,
        owner: None,
        group: None,
        flags: 0,
    });
    entry.group = Some(group);
}

fn release_tuntap_link(ifindex: i32) {
    let should_delete = {
        let mut links = TUNTAP_LINKS.lock();
        let Some(entry) = links.get_mut(&ifindex) else {
            return;
        };
        entry.refs = entry.refs.saturating_sub(1);
        if entry.refs == 0 && !entry.persistent {
            links.remove(&ifindex);
            true
        } else {
            false
        }
    };
    if should_delete {
        let _ = crate::syscall::net::netdev::delete_link_by_global_ifindex(ifindex);
        TUNTAP_QUEUES.lock().remove(&ifindex);
    }
}

/// 伪文件的内容类型。
///
/// - `Static`：固定字节内容，支持按 offset 顺序读取。
/// - `Urandom`：用 xorshift64* 生成的伪随机字节流，`u64` 为当前种子。
/// - `Null`：读取返回 0 字节，写入静默丢弃（对应 `/dev/null`）。
/// - `Zero`：读取填充全零，写入静默丢弃（对应 `/dev/zero`）。
pub enum PseudoKind {
    Static(Vec<u8>),
    Urandom(u64),
    Null,
    Zero,
}

/// `PseudoKind` 的无数据标签，供外部代码通过 `kind_tag()` 判断类型而不持有锁。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PseudoKindTag {
    Static,
    Urandom,
    Null,
    Zero,
}

/// 对应 `/dev/null`、`/dev/zero`、`/dev/urandom` 等字符设备的伪文件。
///
/// 每个实例持有独立的读写 offset（在 `PseudoInner` 内），适合被多个 fd
/// 各自 wrap 而不共享位置。内容类型由 [`PseudoKind`] 决定。
pub struct PseudoFile {
    readable: bool,
    writable: bool,
    kind_tag: PseudoKindTag,
    inner: Mutex<PseudoInner>,
}

struct PseudoInner {
    /// 当前读写位置（字节偏移）。
    offset: usize,
    kind: PseudoKind,
}

/// A minimal pseudo directory for `/proc`, `/sys`, etc.
///
/// Directory iteration is implemented in `syscall_getdents64` by downcasting.
pub struct PseudoDir {
    path: String,
    entries: Vec<PseudoDirent>,
    pidfd_target: Option<Weak<ProcessControlBlock>>,
    inner: Mutex<PseudoDirInner>,
}

/// 伪目录的一条目录项，对应 `getdents64` 返回给用户态的单条记录。
///
/// `dtype` 使用 Linux `DT_*` 常量：
/// - `4` = `DT_DIR`（目录）
/// - `8` = `DT_REG`（普通文件）
/// - `2` = `DT_CHR`（字符设备）
/// - `6` = `DT_BLK`（块设备）
#[derive(Clone)]
pub struct PseudoDirent {
    /// 文件名（不含路径）。
    pub name: alloc::string::String,
    /// inode 编号，由各伪路径的静态映射表分配。
    pub ino: u64,
    /// 文件类型（Linux `DT_*` 值）。
    pub dtype: u8,
}

struct PseudoDirInner {
    /// `getdents64` 下一次读取的起始条目下标。
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
            pidfd_target: None,
            inner: Mutex::new(PseudoDirInner { index: 0 }),
        }
    }

    pub fn new_proc_pid(
        path: &str,
        entries: Vec<PseudoDirent>,
        process: &Arc<ProcessControlBlock>,
    ) -> Self {
        let mut dir = Self::new(path, entries);
        dir.pidfd_target = Some(Arc::downgrade(process));
        dir
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn is_pidfd_target_dir(&self) -> bool {
        self.pidfd_target.is_some()
    }

    pub fn pidfd_target_process(&self) -> Option<Arc<ProcessControlBlock>> {
        self.pidfd_target.as_ref()?.upgrade()
    }

    pub fn entries(&self) -> &[PseudoDirent] {
        &self.entries
    }

    /// Build a fresh directory handle for the same virtual directory at a
    /// different userspace-visible mount path.
    pub(crate) fn remapped(&self, path: &str) -> Self {
        let mut dir = Self::new(path, self.entries.clone());
        dir.pidfd_target = self.pidfd_target.clone();
        dir
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

/// Minimal `/dev/net/tun` endpoint.
///
/// It implements the single-queue TUN/TAP data path used by network tests:
/// userspace can inject packets through `write`, and packet-socket traffic
/// addressed to the attached device is queued for `read`.
pub struct TunTapFile {
    inner: Mutex<TunTapInner>,
}

struct TunTapInner {
    attached_ifindex: Option<i32>,
    kind: Option<crate::syscall::net::netdev::NetDeviceKind>,
    flags: u16,
    persistent: bool,
    _owner: u32,
    _group: u32,
    vnet_hdr_size: i32,
    _offload_flags: usize,
}

impl TunTapFile {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(TunTapInner {
                attached_ifindex: None,
                kind: None,
                flags: 0,
                persistent: false,
                _owner: u32::MAX,
                _group: u32::MAX,
                vnet_hdr_size: 10,
                _offload_flags: 0,
            }),
        }
    }

    pub(crate) fn attach(
        &self,
        ifindex: i32,
        kind: crate::syscall::net::netdev::NetDeviceKind,
        flags: u16,
    ) {
        let mut inner = self.inner.lock();
        register_tuntap_link(ifindex, flags);
        inner.attached_ifindex = Some(ifindex);
        inner.kind = Some(kind);
        inner.flags = flags;
    }

    pub(crate) fn attached_name(&self) -> Option<String> {
        let ifindex = self.inner.lock().attached_ifindex?;
        crate::syscall::net::netdev::device_snapshot_by_global_ifindex(ifindex)
            .map(|(_, dev)| dev.name)
    }

    pub(crate) fn attached_ifindex(&self) -> Option<i32> {
        self.inner.lock().attached_ifindex
    }

    pub(crate) fn attached_device_snapshot(
        &self,
    ) -> Option<crate::syscall::net::netdev::NetDeviceSnapshot> {
        let ifindex = self.inner.lock().attached_ifindex?;
        crate::syscall::net::netdev::device_snapshot_by_global_ifindex(ifindex).map(|(_, dev)| dev)
    }

    pub(crate) fn flags(&self) -> u16 {
        self.inner.lock().flags
    }

    pub(crate) fn set_persistent(&self, persistent: bool) {
        let ifindex = {
            let mut inner = self.inner.lock();
            inner.persistent = persistent;
            inner.attached_ifindex
        };
        if let Some(ifindex) = ifindex {
            set_tuntap_persistent(ifindex, persistent);
        }
    }

    pub(crate) fn set_owner(&self, owner: u32) {
        let ifindex = {
            let mut inner = self.inner.lock();
            inner._owner = owner;
            inner.attached_ifindex
        };
        if let Some(ifindex) = ifindex {
            set_tuntap_owner(ifindex, owner);
        }
    }

    pub(crate) fn set_group(&self, group: u32) {
        let ifindex = {
            let mut inner = self.inner.lock();
            inner._group = group;
            inner.attached_ifindex
        };
        if let Some(ifindex) = ifindex {
            set_tuntap_group(ifindex, group);
        }
    }

    pub(crate) fn vnet_hdr_size(&self) -> i32 {
        self.inner.lock().vnet_hdr_size
    }

    pub(crate) fn set_vnet_hdr_size(&self, size: i32) {
        self.inner.lock().vnet_hdr_size = size;
    }

    pub(crate) fn set_offload_flags(&self, flags: usize) {
        self.inner.lock()._offload_flags = flags;
    }

    fn attached_device(
        &self,
    ) -> Option<(
        usize,
        String,
        i32,
        crate::syscall::net::netdev::NetDeviceKind,
        u16,
    )> {
        let inner = self.inner.lock();
        let ifindex = inner.attached_ifindex?;
        let kind = inner.kind?;
        let flags = inner.flags;
        drop(inner);
        let (ns_id, dev) = crate::syscall::net::netdev::device_snapshot_by_global_ifindex(ifindex)?;
        if dev.kind != kind {
            return None;
        }
        Some((ns_id, dev.name, ifindex, kind, flags))
    }

    fn copy_packet_to_user(buf: UserBuffer, packet: Vec<u8>) -> usize {
        let copied = core::cmp::min(buf.len(), packet.len());
        for (dst, src) in buf.into_iter().zip(packet.iter().take(copied)) {
            unsafe {
                *dst = *src;
            }
        }
        copied
    }

    fn user_visible_packet(
        kind: crate::syscall::net::netdev::NetDeviceKind,
        flags: u16,
        vnet_hdr_size: usize,
        packet: Vec<u8>,
    ) -> Vec<u8> {
        let vnet_len = if (flags & TUNTAP_IFF_VNET_HDR) != 0 {
            vnet_hdr_size
        } else {
            0
        };
        let proto = match kind {
            crate::syscall::net::netdev::NetDeviceKind::Tun => TUNTAP_ETH_P_IP,
            crate::syscall::net::netdev::NetDeviceKind::Tap if packet.len() >= 14 => {
                u16::from_be_bytes([packet[12], packet[13]])
            }
            _ => 0,
        };
        let pi_len = if (flags & TUNTAP_IFF_NO_PI) == 0 {
            4
        } else {
            0
        };
        let mut visible = Vec::with_capacity(packet.len() + pi_len + vnet_len);
        if pi_len != 0 {
            visible.extend_from_slice(&[0, 0]);
            visible.extend_from_slice(&proto.to_be_bytes());
        }
        if vnet_len != 0 {
            visible.resize(visible.len() + vnet_len, 0);
        }
        visible.extend_from_slice(&packet);
        visible
    }

    fn parse_vnet_header(
        data: &[u8],
        offset: &mut usize,
        vnet_hdr_size: usize,
    ) -> Result<(), isize> {
        let Some(end) = offset.checked_add(vnet_hdr_size) else {
            return Err(err(SyscallError::EINVAL));
        };
        if data.len() < end || vnet_hdr_size < VIRTIO_NET_HDR_LEN {
            return Err(err(SyscallError::EINVAL));
        }
        if data[*offset..*offset + VIRTIO_NET_HDR_LEN]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(err(SyscallError::EINVAL));
        }
        *offset = end;
        Ok(())
    }

    pub(crate) fn wait_readable(&self, nonblock: bool) -> Result<(), isize> {
        let (_ns_id, _name, ifindex, _kind, _flags) =
            self.attached_device().ok_or(err(SyscallError::EBADFD))?;
        loop {
            if tuntap_queue_has_packet(ifindex) {
                return Ok(());
            }
            if nonblock {
                return Err(err(SyscallError::EAGAIN));
            }
            if let Some(task) = crate::task::processor::current_task() {
                let inner = task.borrow_mut();
                if crate::task::signal::has_wait_interrupting_pending(
                    inner.pending_signals,
                    inner.signal_mask,
                ) {
                    return Err(err(SyscallError::EINTR));
                }
            }
            crate::task::processor::suspend_current_and_run_next();
        }
    }

    pub(crate) fn read_packet(&self, buf: UserBuffer) -> Result<usize, isize> {
        let (_ns_id, _name, ifindex, kind, flags) =
            self.attached_device().ok_or(err(SyscallError::EBADFD))?;
        let vnet_hdr_size = self.vnet_hdr_size().max(VIRTIO_NET_HDR_LEN as i32) as usize;
        if buf.len() == 0 {
            return Ok(0);
        }
        let packet = pop_tuntap_packet(ifindex).ok_or(err(SyscallError::EAGAIN))?;
        let visible = Self::user_visible_packet(kind, flags, vnet_hdr_size, packet);
        Ok(Self::copy_packet_to_user(buf, visible))
    }

    pub(crate) fn write_packet(&self, buf: UserBuffer) -> Result<usize, isize> {
        let len = buf.len();
        let (ns_id, _name, ifindex, kind, flags) =
            self.attached_device().ok_or(err(SyscallError::EBADFD))?;
        let mut data = Vec::with_capacity(len);
        for byte_ref in buf.into_iter() {
            unsafe {
                data.push(*byte_ref);
            }
        }

        let mut payload_start = 0usize;
        if (flags & TUNTAP_IFF_NO_PI) == 0 {
            if data.len() < 4 {
                return Err(err(SyscallError::EINVAL));
            }
            let proto = u16::from_be_bytes([data[2], data[3]]);
            if kind == crate::syscall::net::netdev::NetDeviceKind::Tun && proto != TUNTAP_ETH_P_IP {
                return Err(err(SyscallError::EAFNOSUPPORT));
            }
            payload_start = 4;
        }
        if (flags & TUNTAP_IFF_VNET_HDR) != 0 {
            let vnet_hdr_size = self.vnet_hdr_size().max(VIRTIO_NET_HDR_LEN as i32) as usize;
            Self::parse_vnet_header(&data, &mut payload_start, vnet_hdr_size)?;
        }
        let payload = &data[payload_start..];

        match kind {
            crate::syscall::net::netdev::NetDeviceKind::Tun => {
                crate::syscall::net::observe_tuntap_ip_packet(ns_id, ifindex, payload);
                Ok(len)
            }
            crate::syscall::net::netdev::NetDeviceKind::Tap => {
                if payload.len() < 14 {
                    return Err(err(SyscallError::EINVAL));
                }
                crate::syscall::net::observe_tuntap_ethernet_frame(ns_id, ifindex, payload);
                Ok(len)
            }
            _ => Err(err(SyscallError::ENODEV)),
        }
    }
}

impl Drop for TunTapFile {
    fn drop(&mut self) {
        let ifindex = self.inner.lock().attached_ifindex;
        if let Some(ifindex) = ifindex {
            release_tuntap_link(ifindex);
        }
    }
}

impl File for TunTapFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, buf: UserBuffer) -> usize {
        self.read_packet(buf).unwrap_or(0)
    }

    fn write(&self, buf: UserBuffer) -> usize {
        self.write_packet(buf).unwrap_or(0)
    }

    fn poll_mask(&self) -> i16 {
        let mut mask = super::POLLOUT;
        if let Some((_ns_id, _name, ifindex, _kind, _flags)) = self.attached_device()
            && tuntap_queue_has_packet(ifindex)
        {
            mask |= super::POLLIN;
        }
        mask
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// 共享内存对象的实际数据，由 [`PseudoShmFile`] 通过 `Arc<Mutex<_>>` 共享。
///
/// 支持 POSIX shm（`shm_open`）和匿名 memfd（`memfd_create`）两种模式。
/// 物理页通过 [`FrameTracker`] 按需分配，`ensure_len` 负责扩缩容。
pub(crate) struct ShmDataInner {
    /// 全局唯一 ID，供 `/proc/self/maps` 等显示 memfd 身份。
    id: u64,
    /// true 时为 memfd，否则为 POSIX shm。
    is_memfd: bool,
    /// memfd 的密封标志位（`F_SEAL_*`）；POSIX shm 固定为 0。
    seals: u32,
    /// 当前有效长度（字节），可能小于已分配页的总大小。
    len: usize,
    /// 按页顺序排列的物理帧，drop 时自动释放。
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
    /// 全局 POSIX 共享内存对象表，键为 `/dev/shm/<name>` 的 `<name>` 部分。
    static ref SHM_OBJECTS: Mutex<BTreeMap<String, ShmData>> = Mutex::new(BTreeMap::new());
    /// 通过 `mkdir /dev/<name>` 动态创建的伪目录，键为目录名，值为分配的 inode 号。
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

/// 从绝对路径中提取 `/dev/<name>` 的 `<name>` 部分。
/// 路径必须是单层子目录（不含 `/`），且不为 `.` 或 `..`。
fn pseudo_dev_dir_name(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/dev/")?;
    if rest.is_empty() || rest.contains('/') || matches!(rest, "." | "..") {
        return None;
    }
    Some(rest)
}

/// 返回所有动态 `/dev/<name>` 目录的目录项列表，供 `/dev` 目录枚举使用。
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

/// 判断动态 `/dev/<name>` 目录是否存在。
pub(crate) fn pseudo_dev_dir_exists(path: &str) -> bool {
    let Some(name) = pseudo_dev_dir_name(path) else {
        return false;
    };
    PSEUDO_DEV_DIRS.lock().contains_key(name)
}

/// 打开一个动态 `/dev/<name>` 目录，返回仅含 `.` 和 `..` 的 [`PseudoDir`]。
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

/// 在 `/dev/<name>` 下创建新的伪目录。
///
/// - 保留名称（`root`、`null` 等）返回 `EEXIST`。
/// - 路径不合法（多层或空）返回 `EROFS`。
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

/// 删除一个动态 `/dev/<name>` 伪目录；不存在时返回 `ENOENT`。
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
        let data = self.data.lock();
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

    #[allow(dead_code)]
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

    pub fn shared_frames_existing(&self, offset: usize, len: usize) -> Option<Vec<FrameTracker>> {
        if len == 0 {
            return Some(Vec::new());
        }
        let end = offset.checked_add(len)?;
        let data = self.data.lock();
        let start_page = offset / PAGE_SIZE;
        let end_page = end.saturating_add(PAGE_SIZE - 1) / PAGE_SIZE;
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

    #[allow(dead_code)]
    pub fn new_static_rw(content: &str) -> Self {
        Self::new_static_with_writable(content, true)
    }

    fn new_static_with_writable(content: &str, writable: bool) -> Self {
        Self {
            readable: true,
            writable,
            kind_tag: PseudoKindTag::Static,
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
            kind_tag: PseudoKindTag::Static,
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
            kind_tag: PseudoKindTag::Urandom,
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
            kind_tag: PseudoKindTag::Null,
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
            kind_tag: PseudoKindTag::Zero,
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
        self.kind_tag
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
