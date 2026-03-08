extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use lazy_static::lazy_static;
use spin::Mutex;

use crate::mm::UserBuffer;

use super::File;

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

struct PtyPairState {
    index: u32,
    locked: bool,
    attr: TtyAttrState,
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
        }));
        self.pairs.insert(idx, Arc::clone(&pair));
        pair
    }

    fn get_pair(&self, index: u32) -> Option<Arc<Mutex<PtyPairState>>> {
        self.pairs.get(&index).cloned()
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
}

impl File for PtyMasterFile {
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

pub struct PtySlaveFile {
    pair: Arc<Mutex<PtyPairState>>,
}

impl PtySlaveFile {
    fn new(pair: Arc<Mutex<PtyPairState>>) -> Self {
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
}

impl File for PtySlaveFile {
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

pub fn list_dev_pts() -> Vec<u32> {
    PTY_MANAGER.lock().list_indices()
}
