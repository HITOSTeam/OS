//! File system in os
mod dummy;
mod inode;
mod net_socket;
mod pipe;
mod procfs;
mod pseudo;
mod socketpair;
mod stdio;
use crate::mm::UserBuffer;
use core::any::Any;

/// File trait
pub trait File: Send + Sync {
    /// If readable
    fn readable(&self) -> bool;
    /// If writable
    fn writable(&self) -> bool;
    /// Read file to `UserBuffer`
    fn read(&self, buf: UserBuffer) -> usize;
    /// Write `UserBuffer` to file
    fn write(&self, buf: UserBuffer) -> usize;
    fn as_any(&self) -> &dyn Any;
}

pub use dummy::DummyFile;
pub(crate) use inode::{
    debug_track_iozone_inode, ext4_lock, find_path_in_roots, root_inode_for_path,
    secondary_root_inode,
};
pub use inode::{list_apps, open_file, OSInode, OpenFlags, EXT4_FS, ROOT_INODE, USER_INODE};
pub use net_socket::{NetSocketFile, NetSocketKind};
pub use pipe::{make_pipe, Pipe};
pub use procfs::{
    build_proc_root_entries, collect_pids, init_procfs, is_proc_pseudo_path, is_proc_root,
    open_proc_pseudo, proc_file_content, proc_file_kind, proc_file_len, proc_readlink,
    sync_proc_path,
};
pub use pseudo::PseudoBlock;
pub(crate) use pseudo::{shm_create, shm_get, shm_list, shm_remove};
pub use pseudo::{PseudoDir, PseudoDirent, PseudoFile, PseudoKindTag, PseudoShmFile, RtcFile};
pub use socketpair::{make_socketpair, SocketPairEnd};
pub use stdio::{Stdin, Stdout};
