//! File system in os
mod cgroupfs;
mod dummy;
mod inode;
mod net_socket;
mod pipe;
mod procfs;
mod pseudo;
mod socketpair;
mod stdio;
mod tty;
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

pub use dummy::{DummyFile, NamespaceFile, NamespaceKind, PidFdFile, UserfaultfdFile};
pub use cgroupfs::{
    CgroupFile, cgroup_attach_fork_child, cgroup_charge_anon_current, cgroup_charge_file_write,
    cgroup_exit_process, cgroup_fork_precheck, cgroup_logical_path_for_file, cgroup_mkdir,
    cgroup_mount, cgroup_proc_cgroups_content, cgroup_proc_pid_content, cgroup_rmdir,
    cgroup_umount, is_cgroup_pseudo_path, open_cgroup_pseudo,
};
pub(crate) use inode::{
    debug_track_iozone_inode, ext4_lock, find_path_in_roots, register_deferred_unlink_cleanup,
    root_inode_for_path, secondary_root_inode,
};
pub use inode::{list_apps, open_file, OSInode, OpenFlags, EXT4_FS, ROOT_INODE, USER_INODE};
pub use net_socket::{NetSocketFile, NetSocketKind};
pub(crate) use pipe::remove_task_waiters as remove_pipe_waiters_for_task;
pub use pipe::{debug_count_task_waiters as debug_count_pipe_waiters_for_task, make_pipe, Pipe};
pub use procfs::{
    build_proc_root_entries, collect_pids, init_procfs, is_proc_pseudo_path, is_proc_root,
    open_proc_pseudo, proc_file_content, proc_file_kind, proc_file_len, proc_readlink,
    sync_proc_path, vm_commit_limit_bytes, vm_committed_as_bytes, vm_overcommit_memory,
    vm_overcommit_ratio, ProcPseudoFile,
};
pub use pseudo::PseudoBlock;
pub(crate) use pseudo::{
    pseudo_block_is_read_only, pseudo_block_note_sync, pseudo_block_read_ahead,
    pseudo_block_set_read_ahead, pseudo_block_set_read_only, pseudo_block_stat_snapshot,
    shm_create, shm_create_anonymous, shm_get, shm_list, shm_remove,
};
pub use pseudo::{PseudoDir, PseudoDirent, PseudoFile, PseudoKindTag, PseudoShmFile, RtcFile};
pub use socketpair::{make_socketpair, SocketPairEnd};
pub use stdio::{Stdin, Stdout};
pub use tty::{
    list_dev_pts, open_dev_ptmx, open_dev_pts, open_dev_tty, LinuxTermio, LinuxTermios,
    PtyMasterFile, PtySlaveFile, TtyFile,
};
