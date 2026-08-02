use crate::{
    fs::namespace_file_from_open_file,
    syscall::error::{SyscallError, err},
    task::processor::{current_files, current_process},
};

/// Linux `unshare(2)` (syscall 97 on riscv64).
///
/// Minimal support:
/// - `CLONE_FILES`: unshare file descriptor table from CLONE_FILES owner.
/// - `CLONE_FS`: detach the shared root/cwd/umask context.
/// - `CLONE_NEWUSER`: allocate a user namespace handle and reset proc uid/gid maps.
/// - `CLONE_NEWNS`: clone the current mount namespace.
/// - `CLONE_NEWNET`: allocate a net namespace handle; devices remain global for now.
/// - `CLONE_NEWCGROUP`: pin the caller's current cgroup as its namespace root.
pub fn syscall_unshare(flags: usize) -> isize {
    const CLONE_FS: usize = 0x0000_0200;
    const CLONE_FILES: usize = 0x0000_0400;
    const CLONE_NEWNS: usize = 0x0002_0000;
    const CLONE_NEWUSER: usize = 0x1000_0000;
    const CLONE_NEWUTS: usize = 0x0400_0000;
    const CLONE_NEWCGROUP: usize = 0x0200_0000;
    const CLONE_NEWNET: usize = 0x4000_0000;
    let valid = CLONE_FILES
        | CLONE_FS
        | CLONE_NEWNS
        | CLONE_NEWUSER
        | CLONE_NEWUTS
        | CLONE_NEWCGROUP
        | CLONE_NEWNET;
    if (flags & !valid) != 0 {
        return err(SyscallError::EINVAL);
    }
    let process = current_process();
    if (flags & (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWCGROUP | CLONE_NEWNET)) != 0 {
        let inner = process.borrow_mut();
        if inner.euid != 0 && inner.user_ns_id == 0 && (flags & CLONE_NEWUSER) == 0 {
            return err(SyscallError::EPERM);
        }
    }
    if (flags & CLONE_FILES) != 0 {
        process.unshare_files();
    }
    if (flags & CLONE_FS) != 0 {
        process.unshare_fs();
    }
    if (flags & CLONE_NEWUSER) != 0 {
        process.unshare_user_namespace();
    }
    if (flags & CLONE_NEWNS) != 0 {
        process.unshare_mount_namespace();
    }
    if (flags & CLONE_NEWUTS) != 0 {
        process.unshare_uts_namespace();
    }
    if (flags & CLONE_NEWCGROUP) != 0 {
        process.unshare_cgroup_namespace(crate::fs::cgroup_current_path(process.getpid()));
    }
    if (flags & CLONE_NEWNET) != 0 {
        process.unshare_net_namespace();
    }
    0
}

/// Linux `setns(2)` (syscall 268 on riscv64).
///
/// Minimal support:
/// - IPC namespace fd from `/proc/<pid>/ns/ipc`
/// - mount namespace fd from `/proc/<pid>/ns/mnt`
/// - net namespace fd from `/proc/<pid>/ns/net`
/// - cgroup namespace fd from `/proc/<pid>/ns/cgroup`
/// - `nstype` of 0 or the matching namespace clone flag
pub fn syscall_setns(fd: isize, nstype: usize) -> isize {
    const EBADF: isize = -9;
    const CLONE_NEWNS: usize = 0x0002_0000;
    const CLONE_NEWCGROUP: usize = 0x0200_0000;
    const CLONE_NEWIPC: usize = 0x0800_0000;
    const CLONE_NEWNET: usize = 0x4000_0000;

    if fd < 0 {
        return EBADF;
    }

    let file = {
        let idx = fd as usize;
        let files = current_files();
        let Some(file) = files.lock().get_file(idx) else {
            return EBADF;
        };
        file
    };

    let Some(ns_file) = namespace_file_from_open_file(&file) else {
        return err(SyscallError::EINVAL);
    };

    let expected = ns_file.kind().clone_flag();
    if nstype != 0 && nstype != expected {
        return err(SyscallError::EINVAL);
    }

    let process = current_process();
    let mut inner = process.borrow_mut();
    if inner.euid != 0 {
        return err(SyscallError::EPERM);
    }

    match ns_file.kind() {
        crate::fs::NamespaceKind::Ipc => {
            if expected != CLONE_NEWIPC {
                return err(SyscallError::EINVAL);
            }
            inner.ipc_ns_id = ns_file.ns_id();
            0
        }
        crate::fs::NamespaceKind::Mount => {
            if expected != CLONE_NEWNS {
                return err(SyscallError::EINVAL);
            }
            drop(inner);
            let Some(namespace) = ns_file.mount_namespace() else {
                return err(SyscallError::EINVAL);
            };
            process.set_mount_namespace(namespace);
            0
        }
        crate::fs::NamespaceKind::Net => {
            if expected != CLONE_NEWNET {
                return err(SyscallError::EINVAL);
            }
            inner.net_ns_id = ns_file.ns_id();
            0
        }
        crate::fs::NamespaceKind::Cgroup => {
            if expected != CLONE_NEWCGROUP {
                return err(SyscallError::EINVAL);
            }
            let Some(root) = ns_file.cgroup_root() else {
                return err(SyscallError::EINVAL);
            };
            inner.cgroup_ns_id = ns_file.ns_id();
            inner.cgroup_ns_root = root;
            0
        }
    }
}
