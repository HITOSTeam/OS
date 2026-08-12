//! Filesystem-type registration and instance construction.
//!
//! The registry belongs to the filesystem composition layer: syscall code
//! supplies a mount context, while concrete backend selection stays here.

use super::ext4::Ext4Vfs;
use super::tmpfs::TmpFs;
use super::vfs::{
    VfsError, VfsFileSystem, VfsFileSystemFactory, VfsFileSystemRegistry, VfsMountContext,
    VfsResult,
};
use super::{
    Cgroup2FsFactory, CgroupV1FsFactory, DevTmpFsFactory, ProcFsFactory, SysFsFactory,
    block_root_for_source,
};
use alloc::string::String;
use alloc::sync::Arc;
use lazy_static::lazy_static;

struct Ext4MountFactory;

impl VfsFileSystemFactory for Ext4MountFactory {
    fn create(&self, context: &VfsMountContext) -> VfsResult<Arc<dyn VfsFileSystem>> {
        let source = context.source.as_deref().ok_or(VfsError::Invalid)?;
        let root = block_root_for_source(source).ok_or(VfsError::NoDevice)?;
        Ok(Ext4Vfs::new(root))
    }

    fn requires_device(&self) -> bool {
        true
    }
}

struct TmpFsMountFactory;

impl VfsFileSystemFactory for TmpFsMountFactory {
    fn create(&self, context: &VfsMountContext) -> VfsResult<Arc<dyn VfsFileSystem>> {
        let memory_bytes =
            crate::config::phys_mem_end().saturating_sub(crate::config::phys_mem_start());
        TmpFs::new(memory_bytes, &context.data)
            .map(|filesystem| filesystem as Arc<dyn VfsFileSystem>)
    }
}

lazy_static! {
    static ref FILESYSTEM_REGISTRY: VfsFileSystemRegistry = {
        let registry = VfsFileSystemRegistry::default();
        registry
            .register("ext4", Arc::new(Ext4MountFactory))
            .expect("register ext4 VFS factory");
        registry
            .register("tmpfs", Arc::new(TmpFsMountFactory))
            .expect("register tmpfs VFS factory");
        registry
            .register("proc", Arc::new(ProcFsFactory))
            .expect("register procfs VFS factory");
        registry
            .register("sysfs", Arc::new(SysFsFactory))
            .expect("register sysfs VFS factory");
        registry
            .register("devtmpfs", Arc::new(DevTmpFsFactory))
            .expect("register devtmpfs VFS factory");
        registry
            .register("cgroup2", Arc::new(Cgroup2FsFactory))
            .expect("register cgroup2 VFS factory");
        registry
            .register("cgroup", Arc::new(CgroupV1FsFactory))
            .expect("register cgroup VFS factory");
        registry
    };
}

/// Instantiate one registered filesystem from a mount context.
pub(crate) fn create_registered_vfs_filesystem(
    fs_type: &str,
    source: Option<&str>,
    data: &str,
    pid_namespace_id: u64,
    cgroup_namespace_root: &str,
) -> VfsResult<Arc<dyn VfsFileSystem>> {
    FILESYSTEM_REGISTRY.create(
        fs_type,
        &VfsMountContext {
            source: source.map(String::from),
            data: String::from(data),
            pid_namespace_id: Some(pid_namespace_id),
            cgroup_namespace_root: Some(String::from(cgroup_namespace_root)),
        },
    )
}

/// Render registered filesystem types using Linux `/proc/filesystems` syntax.
pub(crate) fn registered_filesystems_snapshot() -> String {
    let mut output = String::new();
    for (filesystem_type, requires_device) in FILESYSTEM_REGISTRY.filesystem_types() {
        if requires_device {
            output.push('\t');
        } else {
            output.push_str("nodev\t");
        }
        output.push_str(&filesystem_type);
        output.push('\n');
    }
    output
}
