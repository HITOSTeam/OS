# VFS migration boundary

CongCore has one pathname and mount model in `fs::vfs`. The generic `File`
trait is the kernel descriptor ABI for regular files, pipes, sockets and
devices; it is not a second pathname resolver.

## Ownership rules

- `fs::vfs` owns dentries, mounts, path walking, filesystem/node operations
  and shared object-VFS file descriptions.
- `fs::registry` owns filesystem type registration and backend construction.
  Syscalls provide a mount context and only translate `VfsError` to errno.
- Every pathname-backed descriptor exposes `PathFileDescription`. Common
  status, position and writeback syscalls use that capability rather than
  selecting `OSInode` or `VfsOpenedFile`.
- Concrete `Ext4VfsNode` downcasts stay inside the ext4/filesystem layer.
  Legacy-only callers use `vfs_path_is_ext4` or
  `ext4_inode_from_vfs_path`, which make the transition explicit.

## Transitional ext4 data path

Path lookup, mount crossing and inode identity already use the object VFS.
Online ext4 opens still create `OSInode`, because it currently owns behavior
that `VfsFileOperations` cannot yet replace safely:

- buffered writes and visible-size accounting;
- mmap coherency and writeback hooks;
- fanotify notifications and permissions;
- flock/lease ownership and deferred-unlink lifetime handling.

`OSInode` and `VfsOpenedFile` therefore implement the same
`PathFileDescription` capability. Append status is shared by the open file
description (including after `dup`/`fork`), and `lseek`, `fsync`, `syncfs`,
`sync_file_range` and `fadvise` have one syscall path.

Do not switch ext4 opens directly to `VfsOpenedFile` until the capabilities
above have backend-neutral interfaces and focused regressions. Doing so would
remove duplicate code but silently lose kernel semantics.

## Next migration steps

1. Move ext4 buffered I/O and mmap/writeback coordination behind reusable VFS
   file-operation hooks.
2. Move fanotify and lock ownership to backend-neutral inode/file identities.
3. Migrate ext4 `getdents` and data I/O to those hooks in focused LTP batches.
4. Remove the ext4 bridge helpers and the pathname-specific parts of
   `OSInode`; keep `File` as the descriptor ABI for non-path objects.

Both architecture targets must continue to pass:

```zsh
TMPDIR=$PWD/../.tmp ARCH=riscv64 cargo check --target riscv64gc-unknown-none-elf
TMPDIR=$PWD/../.tmp ARCH=loongarch64 cargo check --target loongarch64-unknown-none-softfloat
```
