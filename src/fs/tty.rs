extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use lazy_static::lazy_static;
use spin::Mutex;

use crate::mm::UserBuffer;
use crate::syscall::error::{SyscallError, err};

use super::{File, POLLHUP, POLLIN, POLLOUT};

const NCC: usize = 8;
const NCCS: usize = 19;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LinuxTermio {
    pub c_iflag: u16,
    pub c_oflag: u16,
    pub c_cflag: u16,
    pub c_lflag: u16,
    pub c_line: u8,
    pub c_cc: [u8; NCC],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LinuxTermios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; NCCS],
}

impl Default for LinuxTermios {
    fn default() -> Self {
        Self {
            c_iflag: 0,
            c_oflag: 0,
            c_cflag: 0,
            c_lflag: 0,
            c_line: 0,
            c_cc: [0; NCCS],
        }
    }
}

#[derive(Clone, Copy, Default)]
struct TtyAttrState {
    termio: LinuxTermio,
    termios: LinuxTermios,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LinuxWinSize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

struct PtyPairState {
    index: u32,
    locked: bool,
    attr: TtyAttrState,
    winsize: LinuxWinSize,
    line_discipline: i32,
    master_open: bool,
    slave_open_count: usize,
    to_master: VecDeque<u8>,
    to_slave: VecDeque<u8>,
    master_hangups: usize,
}

struct PtyManager {
    next_index: u32,
    pairs: BTreeMap<u32, Arc<Mutex<PtyPairState>>>,
}

impl PtyManager {
    fn new() -> Self {
        Self {
            next_index: 0,
            pairs: BTreeMap::new(),
        }
    }

    fn allocate_pair(&mut self) -> Arc<Mutex<PtyPairState>> {
        let idx = self.next_index;
        self.next_index = self.next_index.wrapping_add(1);
        let pair = Arc::new(Mutex::new(PtyPairState {
            index: idx,
            // Linux ptmx starts locked; unlockpt() uses TIOCSPTLCK.
            locked: true,
            attr: TtyAttrState::default(),
            winsize: LinuxWinSize::default(),
            line_discipline: 0,
            master_open: true,
            slave_open_count: 0,
            to_master: VecDeque::new(),
            to_slave: VecDeque::new(),
            master_hangups: 0,
        }));
        self.pairs.insert(idx, Arc::clone(&pair));
        pair
    }

    fn get_pair(&self, index: u32) -> Option<Arc<Mutex<PtyPairState>>> {
        self.pairs.get(&index).cloned()
    }

    fn remove_pair(&mut self, index: u32) {
        self.pairs.remove(&index);
    }

    fn contains_pair(&self, index: u32) -> bool {
        self.pairs.contains_key(&index)
    }

    fn list_indices(&self) -> Vec<u32> {
        self.pairs.keys().copied().collect()
    }
}

lazy_static! {
    static ref PTY_MANAGER: Mutex<PtyManager> = Mutex::new(PtyManager::new());
    static ref DEV_TTY_STATE: Arc<Mutex<TtyAttrState>> =
        Arc::new(Mutex::new(TtyAttrState::default()));
}

pub struct TtyFile {
    state: Arc<Mutex<TtyAttrState>>,
}

impl TtyFile {
    fn with_shared_state(state: Arc<Mutex<TtyAttrState>>) -> Self {
        Self { state }
    }

    pub fn termio(&self) -> LinuxTermio {
        self.state.lock().termio
    }

    pub fn set_termio(&self, termio: LinuxTermio) {
        self.state.lock().termio = termio;
    }

    pub fn termios(&self) -> LinuxTermios {
        self.state.lock().termios
    }

    pub fn set_termios(&self, termios: LinuxTermios) {
        self.state.lock().termios = termios;
    }
}

impl File for TtyFile {
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

pub struct PtyMasterFile {
    pair: Arc<Mutex<PtyPairState>>,
}

impl PtyMasterFile {
    fn new(pair: Arc<Mutex<PtyPairState>>) -> Self {
        Self { pair }
    }

    pub fn pty_index(&self) -> u32 {
        self.pair.lock().index
    }

    pub fn set_locked(&self, locked: bool) {
        self.pair.lock().locked = locked;
    }

    pub fn winsize(&self) -> LinuxWinSize {
        self.pair.lock().winsize
    }

    pub fn set_winsize(&self, winsize: LinuxWinSize) {
        self.pair.lock().winsize = winsize;
    }

    pub fn line_discipline(&self) -> i32 {
        self.pair.lock().line_discipline
    }

    pub fn set_line_discipline(&self, line: i32) {
        self.pair.lock().line_discipline = line;
    }

    pub fn termio(&self) -> LinuxTermio {
        self.pair.lock().attr.termio
    }

    pub fn set_termio(&self, termio: LinuxTermio) {
        self.pair.lock().attr.termio = termio;
    }

    pub fn termios(&self) -> LinuxTermios {
        self.pair.lock().attr.termios
    }

    pub fn set_termios(&self, termios: LinuxTermios) {
        self.pair.lock().attr.termios = termios;
    }

    pub fn queued_bytes(&self) -> usize {
        self.pair.lock().to_master.len()
    }

    pub fn flush_queues(&self, queue_sel: i32) -> bool {
        pty_flush(self.pair.clone(), PtyEndpoint::Master, queue_sel)
    }

    pub fn read_result(&self, buf: UserBuffer) -> Result<usize, isize> {
        pty_read(self.pair.clone(), PtyEndpoint::Master, buf)
    }

    pub fn write_result(&self, buf: UserBuffer) -> Result<usize, isize> {
        pty_write(self.pair.clone(), PtyEndpoint::Master, buf)
    }
}

impl File for PtyMasterFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, buf: UserBuffer) -> usize {
        self.read_result(buf).unwrap_or(0)
    }

    fn write(&self, buf: UserBuffer) -> usize {
        self.write_result(buf).unwrap_or(0)
    }

    fn poll_mask(&self) -> i16 {
        let pair = self.pair.lock();
        let mut mask = POLLOUT;
        if !pair.to_master.is_empty() || pair.master_hangups > 0 {
            mask |= POLLIN;
        }
        if pair.master_hangups > 0 {
            mask |= POLLHUP;
        }
        mask
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Drop for PtyMasterFile {
    fn drop(&mut self) {
        let index = self.pair.lock().index;
        PTY_MANAGER.lock().remove_pair(index);
        let mut pair = self.pair.lock();
        pair.master_open = false;
        pair.to_master.clear();
        pair.to_slave.clear();
    }
}

pub struct PtySlaveFile {
    pair: Arc<Mutex<PtyPairState>>,
}

impl PtySlaveFile {
    fn new(pair: Arc<Mutex<PtyPairState>>) -> Self {
        pair.lock().slave_open_count += 1;
        Self { pair }
    }

    pub fn termio(&self) -> LinuxTermio {
        self.pair.lock().attr.termio
    }

    pub fn set_termio(&self, termio: LinuxTermio) {
        self.pair.lock().attr.termio = termio;
    }

    pub fn termios(&self) -> LinuxTermios {
        self.pair.lock().attr.termios
    }

    pub fn set_termios(&self, termios: LinuxTermios) {
        self.pair.lock().attr.termios = termios;
    }

    pub fn winsize(&self) -> LinuxWinSize {
        self.pair.lock().winsize
    }

    pub fn set_winsize(&self, winsize: LinuxWinSize) {
        self.pair.lock().winsize = winsize;
    }

    pub fn line_discipline(&self) -> i32 {
        self.pair.lock().line_discipline
    }

    pub fn set_line_discipline(&self, line: i32) {
        self.pair.lock().line_discipline = line;
    }

    pub fn queued_bytes(&self) -> usize {
        self.pair.lock().to_slave.len()
    }

    pub fn flush_queues(&self, queue_sel: i32) -> bool {
        pty_flush(self.pair.clone(), PtyEndpoint::Slave, queue_sel)
    }

    pub fn read_result(&self, buf: UserBuffer) -> Result<usize, isize> {
        pty_read(self.pair.clone(), PtyEndpoint::Slave, buf)
    }

    pub fn write_result(&self, buf: UserBuffer) -> Result<usize, isize> {
        pty_write(self.pair.clone(), PtyEndpoint::Slave, buf)
    }
}

impl File for PtySlaveFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, buf: UserBuffer) -> usize {
        self.read_result(buf).unwrap_or(0)
    }

    fn write(&self, buf: UserBuffer) -> usize {
        self.write_result(buf).unwrap_or(0)
    }

    fn poll_mask(&self) -> i16 {
        let pair = self.pair.lock();
        let mut mask = 0;
        if !pair.to_slave.is_empty() {
            mask |= POLLIN;
        }
        if pair.master_open {
            mask |= POLLOUT;
        } else {
            mask |= POLLHUP;
        }
        mask
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Drop for PtySlaveFile {
    fn drop(&mut self) {
        let mut pair = self.pair.lock();
        pair.slave_open_count = pair.slave_open_count.saturating_sub(1);
        if pair.slave_open_count == 0 && pair.master_open {
            pair.master_hangups = pair.master_hangups.saturating_add(1);
        }
    }
}

#[derive(Clone, Copy)]
enum PtyEndpoint {
    Master,
    Slave,
}

fn user_buffer_to_vec(buf: UserBuffer) -> Vec<u8> {
    buf.to_vec()
}

fn drain_queue_to_user(queue: &mut VecDeque<u8>, mut buf: UserBuffer) -> usize {
    let to_read = core::cmp::min(queue.len(), buf.len());
    let mut bytes = Vec::with_capacity(to_read);
    for _ in 0..to_read {
        let Some(byte) = queue.pop_front() else {
            break;
        };
        bytes.push(byte);
    }
    buf.copy_from_slice(&bytes)
}

fn pty_read(
    pair: Arc<Mutex<PtyPairState>>,
    endpoint: PtyEndpoint,
    buf: UserBuffer,
) -> Result<usize, isize> {
    if buf.len() == 0 {
        return Ok(0);
    }
    loop {
        let mut state = pair.lock();
        match endpoint {
            PtyEndpoint::Master => {
                if !state.to_master.is_empty() {
                    return Ok(drain_queue_to_user(&mut state.to_master, buf));
                }
                if state.master_hangups > 0 {
                    state.master_hangups -= 1;
                    return Err(err(SyscallError::EIO));
                }
            }
            PtyEndpoint::Slave => {
                if !state.to_slave.is_empty() {
                    return Ok(drain_queue_to_user(&mut state.to_slave, buf));
                }
                if !state.master_open {
                    return Err(err(SyscallError::EIO));
                }
            }
        }
        drop(state);
        crate::task::processor::suspend_current_and_run_next();
    }
}

fn pty_write(
    pair: Arc<Mutex<PtyPairState>>,
    endpoint: PtyEndpoint,
    buf: UserBuffer,
) -> Result<usize, isize> {
    let data = user_buffer_to_vec(buf);
    if data.is_empty() {
        return Ok(0);
    }
    let mut state = pair.lock();
    match endpoint {
        PtyEndpoint::Master => {
            state.to_slave.extend(data.iter().copied());
        }
        PtyEndpoint::Slave => {
            if !state.master_open {
                return Err(err(SyscallError::EIO));
            }
            state.to_master.extend(data.iter().copied());
        }
    }
    Ok(data.len())
}

fn pty_flush(pair: Arc<Mutex<PtyPairState>>, endpoint: PtyEndpoint, queue_sel: i32) -> bool {
    if !(0..=2).contains(&queue_sel) {
        return false;
    }
    let mut state = pair.lock();
    let clear_input = queue_sel == 0 || queue_sel == 2;
    let clear_output = queue_sel == 1 || queue_sel == 2;
    match endpoint {
        PtyEndpoint::Master => {
            if clear_input {
                state.to_master.clear();
            }
            if clear_output {
                state.to_slave.clear();
            }
        }
        PtyEndpoint::Slave => {
            if clear_input {
                state.to_slave.clear();
            }
            if clear_output {
                state.to_master.clear();
            }
        }
    }
    true
}

pub fn open_dev_tty() -> Arc<dyn File + Send + Sync> {
    Arc::new(TtyFile::with_shared_state(Arc::clone(&DEV_TTY_STATE)))
}

pub fn open_dev_ptmx() -> Arc<dyn File + Send + Sync> {
    let pair = PTY_MANAGER.lock().allocate_pair();
    Arc::new(PtyMasterFile::new(pair))
}

pub fn open_dev_pts(index: u32) -> Option<Arc<dyn File + Send + Sync>> {
    let pair = PTY_MANAGER.lock().get_pair(index)?;
    if pair.lock().locked {
        return None;
    }
    Some(Arc::new(PtySlaveFile::new(pair)))
}

pub fn dev_pts_exists(index: u32) -> bool {
    PTY_MANAGER.lock().contains_pair(index)
}

pub fn dev_pts_index_from_path(path: &str) -> Option<u32> {
    let rest = path.strip_prefix("/dev/pts/")?;
    if rest.is_empty() || rest.contains('/') || !rest.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    rest.parse::<u32>().ok()
}

pub fn list_dev_pts() -> Vec<u32> {
    PTY_MANAGER.lock().list_indices()
}
