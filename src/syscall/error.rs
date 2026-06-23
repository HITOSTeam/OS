/// Unified Linux errno values for the syscall layer.
///
/// Variants match Linux's `asm-generic/errno-base.h` and `asm-generic/errno.h`.
/// The numeric values are the positive errno; conversions to `isize`/`usize`
/// return the negative form expected by the kernel ABI.
#[repr(isize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum SyscallError {
    /// Operation is not permitted for the caller's credentials or capabilities.
    EPERM = 1,
    /// A referenced path, file, directory entry, or object does not exist.
    ENOENT = 2,
    /// A referenced process, thread, or process group does not exist.
    ESRCH = 3,
    /// A blocking operation was interrupted by a signal before completion.
    EINTR = 4,
    /// A low-level I/O operation failed or the device reported an error.
    EIO = 5,
    /// The requested device or address exists in the namespace but is unavailable.
    ENXIO = 6,
    /// An argument list, environment, BPF program, or other input is too large.
    E2BIG = 7,
    /// An executable image has an unsupported or invalid format.
    ENOEXEC = 8,
    /// A file descriptor is invalid, closed, or not suitable for the operation.
    EBADF = 9,
    /// The caller has no matching child process to wait for or manage.
    ECHILD = 10,
    /// Memory allocation failed or there is not enough memory for the request.
    ENOMEM = 12,
    /// Access is denied by permissions, mode bits, mount flags, or policy.
    EACCES = 13,
    /// A user-space pointer, buffer, or address range is invalid or inaccessible.
    EFAULT = 14,
    /// A block device was required but the referenced object is not one.
    ENOTBLK = 15,
    /// A resource is busy, mounted, locked, or otherwise in active use.
    EBUSY = 16,
    /// An entry already exists where creation required a new object.
    EEXIST = 17,
    /// The operation would cross filesystems where that is not supported.
    EXDEV = 18,
    /// The referenced device does not exist or the device type is unsupported.
    ENODEV = 19,
    /// A path component expected to be a directory is not a directory.
    ENOTDIR = 20,
    /// A directory was supplied where a non-directory object was required.
    EISDIR = 21,
    /// One or more arguments are malformed, out of range, or inconsistent.
    EINVAL = 22,
    /// The system-wide open file limit has been reached.
    ENFILE = 23,
    /// The process open file descriptor limit has been reached.
    EMFILE = 24,
    /// The object is not a terminal or does not support the requested ioctl.
    ENOTTY = 25,
    /// A text executable is busy, commonly because it is currently mapped or running.
    ETXTBSY = 26,
    /// The operation would exceed the maximum allowed file size.
    EFBIG = 27,
    /// The filesystem or backing store has no free space left.
    ENOSPC = 28,
    /// An invalid seek was requested, commonly on a pipe, FIFO, or socket.
    ESPIPE = 29,
    /// The operation would modify a read-only filesystem or read-only mount.
    EROFS = 30,
    /// Too many hard links exist for the target object.
    EMLINK = 31,
    /// A pipe or socket endpoint has no reader, or the connection was broken.
    EPIPE = 32,
    /// A numeric argument is outside the domain accepted by the operation.
    EDOM = 33,
    /// A numeric result cannot be represented in the requested type or range.
    ERANGE = 34,
    /// The operation would create or encounter a resource deadlock.
    EDEADLK = 35,
    /// A path name, component, or generated name exceeds the supported length.
    ENAMETOOLONG = 36,
    /// No record lock is available or the lock table is exhausted.
    ENOLCK = 37,
    /// The syscall, command, helper, or operation is not implemented.
    ENOSYS = 38,
    /// A directory must be empty for the requested operation but is not.
    ENOTEMPTY = 39,
    /// Too many symbolic links were followed while resolving a path.
    ELOOP = 40,
    /// The operation would block or a transient resource is temporarily unavailable.
    EAGAIN = 11,
    /// No message of the requested type is available.
    ENOMSG = 42,
    /// An IPC identifier was removed while it was being used or waited on.
    EIDRM = 43,
    /// No data is available for the requested stream or attribute.
    ENODATA = 61,
    /// A requested package, module, or subsystem is not installed or available.
    ENOPKG = 65,
    /// A value is too large to store in the target type or ABI field.
    EOVERFLOW = 75,
    /// A file descriptor is in a bad state for the requested operation.
    EBADFD = 77,
    /// A socket operation was requested on a non-socket file descriptor.
    ENOTSOCK = 88,
    /// A destination address is required but was not supplied.
    EDESTADDRREQ = 89,
    /// A message, datagram, or packet is too large for the protocol or buffer.
    EMSGSIZE = 90,
    /// The protocol option is unknown, unsupported, or invalid at this level.
    ENOPROTOOPT = 92,
    /// The requested protocol is not supported by the socket family or stack.
    EPROTONOSUPPORT = 93,
    /// The operation is not supported for this object, protocol, or state.
    EOPNOTSUPP = 95,
    /// The requested protocol family is not supported.
    EPFNOSUPPORT = 96,
    /// The requested address family is not supported.
    EAFNOSUPPORT = 97,
    /// The local address or port is already bound or otherwise in use.
    EADDRINUSE = 98,
    /// The requested address is not assigned, valid, or usable locally.
    EADDRNOTAVAIL = 99,
    /// The network interface or network is down.
    ENETDOWN = 100,
    /// No route or connectivity exists to the requested network.
    ENETUNREACH = 101,
    /// Kernel or device network buffers are exhausted.
    ENOBUFS = 105,
    /// The socket is already connected where a disconnected state was required.
    EISCONN = 106,
    /// The socket is not connected where a connected state was required.
    ENOTCONN = 107,
    /// The operation timed out before completion.
    ETIMEDOUT = 110,
    /// The remote endpoint refused the connection.
    ECONNREFUSED = 111,
    /// A nonblocking connection or operation is already in progress.
    EALREADY = 114,
    /// The operation was canceled before completion.
    ECANCELED = 125,
    /// A key, token, or credential was rejected by policy or validation.
    EKEYREJECTED = 129,
}

impl From<SyscallError> for isize {
    #[inline]
    fn from(e: SyscallError) -> isize {
        -(e as isize)
    }
}

impl From<SyscallError> for usize {
    #[inline]
    fn from(e: SyscallError) -> usize {
        isize::from(e) as usize
    }
}

/// Shorthand: convert a `SyscallError` to the negative `isize` the kernel ABI expects.
#[inline]
pub fn err(e: SyscallError) -> isize {
    isize::from(e)
}

// ---------------------------------------------------------------------------
// From impls for subsystem error types → SyscallError
// ---------------------------------------------------------------------------

impl From<crate::task::ForkError> for SyscallError {
    fn from(e: crate::task::ForkError) -> Self {
        use crate::task::ForkError;
        match e {
            ForkError::PidExhausted
            | ForkError::RlimitNprocExceeded
            | ForkError::CgroupPidsMaxExceeded => SyscallError::EAGAIN,

            ForkError::KernelStackOom | ForkError::TrapCxAllocFailed | ForkError::VmCloneOom => {
                SyscallError::ENOMEM
            }
        }
    }
}

impl From<crate::task::task_block::TaskAllocError> for SyscallError {
    fn from(e: crate::task::task_block::TaskAllocError) -> Self {
        use crate::task::task_block::TaskAllocError;
        match e {
            TaskAllocError::TrapCxAllocFailed | TaskAllocError::KernelStackOom => {
                SyscallError::ENOMEM
            }
        }
    }
}
