/// Unified Linux errno values for the syscall layer.
///
/// Variants match Linux's `asm-generic/errno-base.h` and `asm-generic/errno.h`.
/// The numeric values are the positive errno; conversions to `isize`/`usize`
/// return the negative form expected by the kernel ABI.
#[repr(isize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum SyscallError {
    EPERM           = 1,
    ENOENT          = 2,
    ESRCH           = 3,
    EINTR           = 4,
    EIO             = 5,
    ENXIO           = 6,
    E2BIG           = 7,
    ENOEXEC         = 8,   // Exec format error
    EBADF           = 9,
    ECHILD          = 10,  // No child processes
    ENOMEM          = 12,
    EACCES          = 13,
    EFAULT          = 14,
    ENOTBLK         = 15,
    EBUSY           = 16,
    EEXIST          = 17,
    EXDEV           = 18,
    ENODEV          = 19,
    ENOTDIR         = 20,
    EISDIR          = 21,
    EINVAL          = 22,
    ENFILE          = 23,
    EMFILE          = 24,
    ENOTTY          = 25,  // Not a typewriter / inappropriate ioctl
    ETXTBSY         = 26,
    EFBIG           = 27,
    ENOSPC          = 28,
    ESPIPE          = 29,
    EROFS           = 30,
    EMLINK          = 31,
    EPIPE           = 32,
    ERANGE          = 34,
    EDEADLK         = 35,
    ENAMETOOLONG    = 36,
    ENOLCK          = 37,
    ENOSYS          = 38,
    ENOTEMPTY       = 39,
    ELOOP           = 40,
    EAGAIN          = 11,
    ENOMSG          = 42,
    EIDRM           = 43,
    ENODATA         = 61,
    EOVERFLOW       = 75,
    ENOTSOCK        = 88,
    EDESTADDRREQ    = 89,  // Destination address required
    EMSGSIZE        = 90,
    ENOPROTOOPT     = 92,
    EPROTONOSUPPORT = 93,
    EOPNOTSUPP      = 95,
    EAFNOSUPPORT    = 97,
    EADDRINUSE      = 98,
    EADDRNOTAVAIL   = 99,
    EISCONN         = 106,
    ENOTCONN        = 107,
    ETIMEDOUT       = 110,
    ECONNREFUSED    = 111,
    ECANCELED       = 125,
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

/// `EWOULDBLOCK` is an alias for `EAGAIN` on Linux.
#[allow(dead_code)]
pub const EWOULDBLOCK: SyscallError = SyscallError::EAGAIN;

#[allow(dead_code)]
pub type SyscallResult = Result<usize, SyscallError>;

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

            ForkError::KernelStackOom
            | ForkError::TrapCxAllocFailed
            | ForkError::VmCloneOom => SyscallError::ENOMEM,
        }
    }
}

impl From<crate::task::task_block::TaskAllocError> for SyscallError {
    fn from(e: crate::task::task_block::TaskAllocError) -> Self {
        use crate::task::task_block::TaskAllocError;
        match e {
            TaskAllocError::TrapCxAllocFailed
            | TaskAllocError::KernelStackOom => SyscallError::ENOMEM,
        }
    }
}
