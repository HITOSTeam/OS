use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
pub mod error;
pub(crate) mod filesystem;

mod condvar;
pub(crate) mod dummy;
mod epoll;
mod flow;
pub(crate) mod futex;
mod memory;
pub(crate) mod misc;
mod mutex;
pub(crate) mod net;
pub(crate) mod posix_mq;
pub(crate) mod process;
pub(crate) mod robust_list;
mod sched;
mod semaphore;
pub(crate) mod signal;
mod smp;
mod socket;
pub(crate) mod sysv_ipc;
pub(crate) mod sysv_shm;
mod thread;
mod time_sys;
pub(crate) use time_sys::timer_clock_now_ns;
static CYCLIC_SYSCALL_LOGS: AtomicUsize = AtomicUsize::new(1024);
static LAST_SYSCALL_ID: AtomicUsize = AtomicUsize::new(usize::MAX);
static LAST_SYSCALL_A0: AtomicUsize = AtomicUsize::new(0);
static LAST_SYSCALL_A1: AtomicUsize = AtomicUsize::new(0);
static LAST_SYSCALL_A2: AtomicUsize = AtomicUsize::new(0);
static LAST_SYSCALL_A3: AtomicUsize = AtomicUsize::new(0);
static LAST_SYSCALL_A4: AtomicUsize = AtomicUsize::new(0);
static LAST_SYSCALL_A5: AtomicUsize = AtomicUsize::new(0);
static CYCLIC_DIAG_PID: AtomicUsize = AtomicUsize::new(usize::MAX);
static CYCLIC_DIAG_CLONES: AtomicUsize = AtomicUsize::new(0);
static CYCLIC_DIAG_AFFINITY: AtomicUsize = AtomicUsize::new(0);
static CYCLIC_DIAG_SETSCHED: AtomicUsize = AtomicUsize::new(0);
static CYCLIC_DIAG_SLEEP: AtomicUsize = AtomicUsize::new(0);
static CYCLIC_DIAG_CLONE_TIDS: AtomicUsize = AtomicUsize::new(0);
static CYCLIC_DIAG_AFFINITY_TIDS: AtomicUsize = AtomicUsize::new(0);
static CYCLIC_DIAG_SETSCHED_TIDS: AtomicUsize = AtomicUsize::new(0);
static CYCLIC_DIAG_SLEEP_TIDS: AtomicUsize = AtomicUsize::new(0);
static CYCLIC_DIAG_START_NS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub(crate) enum CyclicDiagEvent {
    Clone,
    SetAffinity,
    SetScheduler,
    ClockNanosleep,
}

fn cyclic_diag_reset(pid: usize, start_ns: u64) {
    CYCLIC_DIAG_PID.store(pid, Ordering::Relaxed);
    CYCLIC_DIAG_CLONES.store(0, Ordering::Relaxed);
    CYCLIC_DIAG_AFFINITY.store(0, Ordering::Relaxed);
    CYCLIC_DIAG_SETSCHED.store(0, Ordering::Relaxed);
    CYCLIC_DIAG_SLEEP.store(0, Ordering::Relaxed);
    CYCLIC_DIAG_CLONE_TIDS.store(0, Ordering::Relaxed);
    CYCLIC_DIAG_AFFINITY_TIDS.store(0, Ordering::Relaxed);
    CYCLIC_DIAG_SETSCHED_TIDS.store(0, Ordering::Relaxed);
    CYCLIC_DIAG_SLEEP_TIDS.store(0, Ordering::Relaxed);
    CYCLIC_DIAG_START_NS.store(start_ns, Ordering::Relaxed);
}

pub(crate) fn cyclic_diag_note(event: CyclicDiagEvent, pid: usize, tid: usize) {
    if !crate::debug_config::DEBUG_CYCLICTEST {
        return;
    }
    let now_ns = crate::time::get_time_ns();
    if CYCLIC_DIAG_PID.load(Ordering::Relaxed) != pid {
        cyclic_diag_reset(pid, now_ns);
    }
    let (name, counter, tid_mask) = match event {
        CyclicDiagEvent::Clone => ("clone", &CYCLIC_DIAG_CLONES, &CYCLIC_DIAG_CLONE_TIDS),
        CyclicDiagEvent::SetAffinity => (
            "setaffinity",
            &CYCLIC_DIAG_AFFINITY,
            &CYCLIC_DIAG_AFFINITY_TIDS,
        ),
        CyclicDiagEvent::SetScheduler => (
            "setscheduler",
            &CYCLIC_DIAG_SETSCHED,
            &CYCLIC_DIAG_SETSCHED_TIDS,
        ),
        CyclicDiagEvent::ClockNanosleep => (
            "clock_nanosleep",
            &CYCLIC_DIAG_SLEEP,
            &CYCLIC_DIAG_SLEEP_TIDS,
        ),
    };
    let delta_us = now_ns.saturating_sub(CYCLIC_DIAG_START_NS.load(Ordering::Relaxed)) / 1_000;
    if tid < usize::BITS as usize {
        tid_mask.fetch_or(1usize << tid, Ordering::Relaxed);
    }
    let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if count <= 16 || count.is_power_of_two() {
        log::warn!(
            "[cyclic_diag] pid={} t_us={} event={} tid={} count={} clone_threads={} affinity_threads={} setsched_threads={} sleep_threads={}",
            pid,
            delta_us,
            name,
            tid,
            count,
            CYCLIC_DIAG_CLONE_TIDS.load(Ordering::Relaxed).count_ones(),
            CYCLIC_DIAG_AFFINITY_TIDS
                .load(Ordering::Relaxed)
                .count_ones(),
            CYCLIC_DIAG_SETSCHED_TIDS
                .load(Ordering::Relaxed)
                .count_ones(),
            CYCLIC_DIAG_SLEEP_TIDS.load(Ordering::Relaxed).count_ones()
        );
    }
}

// The base image ships `/bin/busybox` but not individual applet symlinks.
// Allow a conservative subset of common LTP shell dependencies to fall back
// to busybox when the standalone binary path is absent.
const BUSYBOX_APPLET_ALLOWLIST: [&str; 21] = [
    "awk",
    "cmp",
    "dmesg",
    "find",
    "grep",
    "insmod",
    "lsmod",
    "modprobe",
    "mount",
    "mountpoint",
    "pgrep",
    "pkill",
    "ps",
    "rmmod",
    "seq",
    "sysctl",
    "umount",
    "wc",
    "which",
    "xargs",
    "zcat",
];

pub(crate) fn busybox_applet_allowed(name: &str) -> bool {
    BUSYBOX_APPLET_ALLOWLIST
        .iter()
        .any(|&allowed| allowed == name)
}

pub fn last_syscall_snapshot() -> (usize, [usize; 6]) {
    (LAST_SYSCALL_ID.load(Ordering::Relaxed), [
        LAST_SYSCALL_A0.load(Ordering::Relaxed),
        LAST_SYSCALL_A1.load(Ordering::Relaxed),
        LAST_SYSCALL_A2.load(Ordering::Relaxed),
        LAST_SYSCALL_A3.load(Ordering::Relaxed),
        LAST_SYSCALL_A4.load(Ordering::Relaxed),
        LAST_SYSCALL_A5.load(Ordering::Relaxed),
    ])
}

const SYSCALL_EVENTFD2: usize = 19;
const SYSCALL_EPOLL_CREATE1: usize = 20;
const SYSCALL_EPOLL_CTL: usize = 21;
const SYSCALL_EPOLL_PWAIT: usize = 22;
const SYSCALL_EPOLL_PWAIT2: usize = 441;
const SYSCALL_INOTIFY_INIT1: usize = 26;
const SYSCALL_SETXATTR: usize = 5;
const SYSCALL_LSETXATTR: usize = 6;
const SYSCALL_FSETXATTR: usize = 7;
const SYSCALL_GETXATTR: usize = 8;
const SYSCALL_LGETXATTR: usize = 9;
const SYSCALL_FGETXATTR: usize = 10;
const SYSCALL_LISTXATTR: usize = 11;
const SYSCALL_LLISTXATTR: usize = 12;
const SYSCALL_FLISTXATTR: usize = 13;
const SYSCALL_REMOVEXATTR: usize = 14;
const SYSCALL_LREMOVEXATTR: usize = 15;
const SYSCALL_FREMOVEXATTR: usize = 16;
const SYSCALL_GETCWD: usize = 17;
const SYSCALL_FCNTL: usize = 25;
const SYSCALL_FLOCK: usize = 32;
const SYSCALL_DUP: usize = 23;
const SYSCALL_DUP3: usize = 24;
const SYSCALL_RENAMEAT: usize = 38;
const SYSCALL_SYMLINKAT: usize = 36;
const SYSCALL_LINKAT: usize = 37;
const SYSCALL_IOCTL: usize = 29;
const SYSCALL_IOPRIO_SET: usize = 30;
const SYSCALL_IOPRIO_GET: usize = 31;
const SYSCALL_MKNODAT: usize = 33;
const SYSCALL_MKDIRAT: usize = 34;
const SYSCALL_UNLINKAT: usize = 35;
const SYSCALL_FCHMOD: usize = 52;
const SYSCALL_FCHMODAT: usize = 53;
const SYSCALL_FCHMODAT2: usize = 452;
const SYSCALL_FCHOWNAT: usize = 54;
const SYSCALL_FCHOWN: usize = 55;
const SYSCALL_FTRUNCATE: usize = 46;
const SYSCALL_FALLOCATE: usize = 47;
const SYSCALL_FACCESSAT: usize = 48;
const SYSCALL_FACCESSAT2: usize = 439;
const SYSCALL_UMOUNT2: usize = 39;
const SYSCALL_MOUNT: usize = 40;
const SYSCALL_CHDIR: usize = 49;
const SYSCALL_FCHDIR: usize = 50;
const SYSCALL_CHROOT: usize = 51;
const SYSCALL_OPENAT: usize = 56;
const SYSCALL_CLOSE: usize = 57;
const SYSCALL_CLOSE_RANGE: usize = 436;
const SYSCALL_VFORK: usize = 58;
const SYSCALL_PIPE2: usize = 59;
const SYSCALL_GETDENTS64: usize = 61;
const SYSCALL_LSEEK: usize = 62;
const SYSCALL_READ: usize = 63;
const SYSCALL_WRITE: usize = 64;
const SYSCALL_READV: usize = 65;
const SYSCALL_WRITEV: usize = 66;
const SYSCALL_PREAD64: usize = 67;
const SYSCALL_PWRITE64: usize = 68;
const SYSCALL_PREADV: usize = 69;
const SYSCALL_PWRITEV: usize = 70;
const SYSCALL_SENDFILE: usize = 71;
const SYSCALL_PSELECT6: usize = 72;
const SYSCALL_PPOLL: usize = 73;
const SYSCALL_SIGNALFD4: usize = 74;
const SYSCALL_VMSPLICE: usize = 75;
const SYSCALL_SPLICE: usize = 76;
const SYSCALL_TEE: usize = 77;
const SYSCALL_READLINKAT: usize = 78;
const SYSCALL_NEWFSTATAT: usize = 79;
const SYSCALL_FSTAT: usize = 80;
const SYSCALL_SYNC: usize = 81;
const SYSCALL_FSYNC: usize = 82;
const SYSCALL_FDATASYNC: usize = 83;
const SYSCALL_SYNC_FILE_RANGE: usize = 84;
const SYSCALL_TIMERFD_CREATE: usize = 85;
const SYSCALL_TIMERFD_SETTIME: usize = 86;
const SYSCALL_TIMERFD_GETTIME: usize = 87;
const SYSCALL_STATX: usize = 291;
// riscv64 Linux syscall numbers (match upstream): statfs=43, fstatfs=44.
const SYSCALL_STATFS: usize = 43;
const SYSCALL_FSTATFS: usize = 44;
const SYSCALL_TRUNCATE: usize = 45;
const SYSCALL_UTIMENSAT: usize = 88;
const SYSCALL_ACCT: usize = 89;
const SYSCALL_CAPGET: usize = 90;
const SYSCALL_CAPSET: usize = 91;
const SYSCALL_PERSONALITY: usize = 92;
const SYSCALL_EXIT: usize = 93;
const SYSCALL_EXIT_GROUP: usize = 94;
const SYSCALL_WAITID: usize = 95;
const SYSCALL_SET_TID_ADDRESS: usize = 96;
const SYSCALL_UNSHARE: usize = 97;
const SYSCALL_FUTEX: usize = 98;
const SYSCALL_SET_ROBUST_LIST: usize = 99;
const SYSCALL_GET_ROBUST_LIST: usize = 100;
const SYSCALL_NANOSLEEP: usize = 101;
const SYSCALL_GETITIMER: usize = 102;
const SYSCALL_SETITIMER: usize = 103;
const SYSCALL_INIT_MODULE: usize = 105;
const SYSCALL_DELETE_MODULE: usize = 106;
const SYSCALL_TIMER_CREATE: usize = 107;
const SYSCALL_TIMER_GETTIME: usize = 108;
const SYSCALL_TIMER_GETOVERRUN: usize = 109;
const SYSCALL_TIMER_SETTIME: usize = 110;
const SYSCALL_TIMER_DELETE: usize = 111;
const SYSCALL_PTRACE: usize = 117;
const SYSCALL_SYSLOG: usize = 116;
const SYSCALL_CLOCK_SETTIME: usize = 112;
const SYSCALL_CLOCK_GETTIME: usize = 113;
const SYSCALL_CLOCK_GETRES: usize = 114;
const SYSCALL_CLOCK_NANOSLEEP: usize = 115;
const SYSCALL_SCHED_SETPARAM: usize = 118;
const SYSCALL_SCHED_SETSCHEDULER: usize = 119;
const SYSCALL_SCHED_GETSCHEDULER: usize = 120;
const SYSCALL_SCHED_GETPARAM: usize = 121;
const SYSCALL_SCHED_SETAFFINITY: usize = 122;
const SYSCALL_SCHED_GETAFFINITY: usize = 123;
const SYSCALL_YIELD: usize = 124;
const SYSCALL_SCHED_GET_PRIORITY_MAX: usize = 125;
const SYSCALL_SCHED_GET_PRIORITY_MIN: usize = 126;
const SYSCALL_SCHED_RR_GET_INTERVAL: usize = 127;
const SYSCALL_CLOCK_ADJTIME: usize = 266;
const SYSCALL_SYNCFS: usize = 267;
const SYSCALL_SETNS: usize = 268;
const SYSCALL_FINIT_MODULE: usize = 273;
const SYSCALL_CLOCK_ADJTIME64: usize = 405;
const SYSCALL_SCHED_SETATTR: usize = 274;
const SYSCALL_SCHED_GETATTR: usize = 275;
const SYSCALL_PREADV2: usize = 286;
const SYSCALL_PWRITEV2: usize = 287;
const SYSCALL_TIMES: usize = 153;
const SYSCALL_SETPGID: usize = 154;
const SYSCALL_GETPGID: usize = 155;
const SYSCALL_GETSID: usize = 156;
const SYSCALL_SETSID: usize = 157;
const SYSCALL_GETGROUPS: usize = 158;
const SYSCALL_SETGROUPS: usize = 159;
const SYSCALL_UNAME: usize = 160;
const SYSCALL_SETHOSTNAME: usize = 161;
const SYSCALL_SETDOMAINNAME: usize = 162;
const SYSCALL_SETPRIORITY: usize = 140;
const SYSCALL_GETPRIORITY: usize = 141;
const SYSCALL_UMASK: usize = 166;
const SYSCALL_PRCTL: usize = 167;
const SYSCALL_GETCPU: usize = 168;
const SYSCALL_SYSINFO: usize = 179;
const SYSCALL_SETREGID: usize = 143;
const SYSCALL_SETGID: usize = 144;
const SYSCALL_SETREUID: usize = 145;
const SYSCALL_SETUID: usize = 146;
const SYSCALL_SETRESUID: usize = 147;
const SYSCALL_GETRESUID: usize = 148;
const SYSCALL_SETRESGID: usize = 149;
const SYSCALL_GETRESGID: usize = 150;
const SYSCALL_SETFSUID: usize = 151;
const SYSCALL_SETFSGID: usize = 152;
const SYSCALL_REBOOT: usize = 142;
const SYSCALL_GETTIMEOFDAY: usize = 169;
const SYSCALL_SETTIMEOFDAY: usize = 170;
const SYSCALL_ADJTIMEX: usize = 171;
const SYSCALL_MADVISE: usize = 233;
const SYSCALL_GETPID: usize = 172;
const SYSCALL_GETPPID: usize = 173;
const SYSCALL_GETUID: usize = 174;
const SYSCALL_GETEUID: usize = 175;
const SYSCALL_GETGID: usize = 176;
const SYSCALL_GETEGID: usize = 177;
const SYSCALL_GETTID_LINUX: usize = 178;
const SYSCALL_MQ_OPEN: usize = 180;
const SYSCALL_MQ_UNLINK: usize = 181;
const SYSCALL_MQ_TIMEDSEND: usize = 182;
const SYSCALL_MQ_TIMEDRECEIVE: usize = 183;
const SYSCALL_MQ_NOTIFY: usize = 184;
const SYSCALL_MQ_GETSETATTR: usize = 185;
const SYSCALL_MSGGET: usize = 186;
const SYSCALL_MSGCTL: usize = 187;
const SYSCALL_MSGRCV: usize = 188;
const SYSCALL_MSGSND: usize = 189;
const SYSCALL_SEMGET: usize = 190;
const SYSCALL_SEMCTL: usize = 191;
const SYSCALL_SEMTIMEDOP: usize = 192;
const SYSCALL_SEMOP: usize = 193;
const SYSCALL_SHMGET: usize = 194;
const SYSCALL_SHMCTL: usize = 195;
const SYSCALL_SHMAT: usize = 196;
const SYSCALL_SHMDT: usize = 197;
const SYSCALL_SOCKET: usize = 198;
const SYSCALL_SOCKETPAIR: usize = 199;
const SYSCALL_BIND: usize = 200;
const SYSCALL_LISTEN: usize = 201;
const SYSCALL_ACCEPT: usize = 202;
const SYSCALL_ACCEPT4: usize = 242;
const SYSCALL_CONNECT: usize = 203;
const SYSCALL_GETSOCKNAME: usize = 204;
const SYSCALL_GETPEERNAME: usize = 205;
const SYSCALL_SENDTO: usize = 206;
const SYSCALL_RECVFROM: usize = 207;
const SYSCALL_SETSOCKOPT: usize = 208;
const SYSCALL_GETSOCKOPT: usize = 209;
const SYSCALL_SHUTDOWN: usize = 210;
const SYSCALL_SENDMSG: usize = 211;
const SYSCALL_RECVMSG: usize = 212;
const SYSCALL_RECVMMSG: usize = 243;
const SYSCALL_SENDMMSG: usize = 269;
const SYSCALL_RECVMMSG_TIME64: usize = 417;
const SYSCALL_MQ_TIMEDSEND_TIME64: usize = 418;
const SYSCALL_MQ_TIMEDRECEIVE_TIME64: usize = 419;
const SYSCALL_BRK: usize = 214;
const SYSCALL_MUNMAP: usize = 215;
const SYSCALL_MREMAP: usize = 216;
const SYSCALL_CLONE: usize = 220;
const SYSCALL_EXECVE: usize = 221;
const SYSCALL_EXECVEAT: usize = 281;
const SYSCALL_MMAP: usize = 222;
const SYSCALL_FADVISE64: usize = 223;
const SYSCALL_MPROTECT: usize = 226;
const SYSCALL_MSYNC: usize = 227;
const SYSCALL_MLOCK: usize = 228;
const SYSCALL_MUNLOCK: usize = 229;
const SYSCALL_MLOCKALL: usize = 230;
const SYSCALL_MUNLOCKALL: usize = 231;
const SYSCALL_MINCORE: usize = 232;
const SYSCALL_GETRLIMIT: usize = 163;
const SYSCALL_SETRLIMIT: usize = 164;
const SYSCALL_GETRUSAGE: usize = 165;
const SYSCALL_WAIT4: usize = 260;
const SYSCALL_PRLIMIT64: usize = 261;
const SYSCALL_RENAMEAT2: usize = 276;
const SYSCALL_GETRANDOM: usize = 278;
const SYSCALL_MEMFD_CREATE: usize = 279;
const SYSCALL_BPF: usize = 280;
const SYSCALL_COPY_FILE_RANGE: usize = 285;
const SYSCALL_USERFAULTFD: usize = 282;
const SYSCALL_PERF_EVENT_OPEN: usize = 241;
const SYSCALL_PIDFD_SEND_SIGNAL: usize = 424;
const SYSCALL_FANOTIFY_INIT: usize = 262;
const SYSCALL_FANOTIFY_MARK: usize = 263;
const SYSCALL_IO_URING_SETUP: usize = 425;
const SYSCALL_OPEN_TREE: usize = 428;
const SYSCALL_MOVE_MOUNT: usize = 429;
const SYSCALL_FSOPEN: usize = 430;
const SYSCALL_FSCONFIG: usize = 431;
const SYSCALL_FSMOUNT: usize = 432;
const SYSCALL_FSPICK: usize = 433;
const SYSCALL_MOUNT_SETATTR: usize = 442;
const SYSCALL_PIDFD_OPEN: usize = 434;
const SYSCALL_CLONE3: usize = 435;
const SYSCALL_MEMFD_SECRET: usize = 447;
const SYSCALL_SIGACTION: usize = 134; // rt_sigaction
const SYSCALL_SIGPROCMASK: usize = 135; // rt_sigprocmask
const SYSCALL_SIGPENDING: usize = 136; // rt_sigpending
const SYSCALL_SIGSUSPEND: usize = 133; // rt_sigsuspend
const SYSCALL_SIGALTSTACK: usize = 132; // sigaltstack
const SYSCALL_SIGTIMEDWAIT: usize = 137; // rt_sigtimedwait
const SYSCALL_SIGRETURN: usize = 139; // rt_sigreturn
const SYSCALL_KILL: usize = 129;
const SYSCALL_TKILL: usize = 130;
const SYSCALL_TGKILL: usize = 131;
// thread
const SYSCALL_THREAD_CREATE: usize = 1000;
const SYSCALL_GETTID: usize = 1001;
const SYSCALL_WAITTID: usize = 1002;
const SYSCALL_MUTEX_CREATE: usize = 1010;
const SYSCALL_MUTEX_LOCK: usize = 1011;
const SYSCALL_MUTEX_UNLOCK: usize = 1012;
const SYSCALL_SEMAPHORE_CREATE: usize = 1020;
const SYSCALL_SEMAPHORE_UP: usize = 1021;
const SYSCALL_SEMAPHORE_DOWN: usize = 1022;
const SYSCALL_CONDVAR_CREATE: usize = 1030;
const SYSCALL_CONDVAR_SIGNAL: usize = 1031;
const SYSCALL_CONDVAR_WAIT: usize = 1032;
const SYSCALL_GET_HARTID: usize = 998;

/// Consolidated debug tracing for syscall entry.
/// All conditional debug logging is centralized here to keep `syscall()` clean.
#[inline(always)]
fn trace_syscall_entry(id: usize, args: &[usize; 6]) {
    if !(crate::debug_config::DEBUG_CYCLICTEST
        || crate::debug_config::DEBUG_SIGNAL
        || crate::debug_config::DEBUG_SYSCALL)
    {
        return;
    }

    // -- cyclictest: log all syscalls for "cyclictest" processes (with countdown) --
    if crate::debug_config::DEBUG_CYCLICTEST {
        let proc = crate::task::processor::current_process();
        let is_cyclic = {
            let inner = proc.borrow_mut();
            inner
                .argv
                .first()
                .map(|s| s.contains("cyclictest"))
                .unwrap_or(false)
        };
        if is_cyclic {
            let left = CYCLIC_SYSCALL_LOGS
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |val| {
                    if val == 0 { None } else { Some(val - 1) }
                })
                .unwrap_or(0);
            if left > 0 {
                crate::println!(
                    "[cyclic_syscall] id={} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x}",
                    id,
                    args[0],
                    args[1],
                    args[2],
                    args[3],
                    args[4],
                    args[5]
                );
            }
        }
    }

    // -- cyclictest: log scheduler-related syscalls --
    if crate::debug_config::DEBUG_CYCLICTEST {
        match id {
            118 | 119 | 120 | 121 | 122 | 123 | 124 | 125 | 126 | 127 | 142 | 143 | 144 | 145
            | 146 | 147 | 148 | 274 | 275 => {
                let pid = crate::task::processor::current_process().getpid();
                crate::println!(
                    "[sched_syscall] pid={} id={} a0={:#x} a1={:#x} a2={:#x} a3={:#x}",
                    pid,
                    id,
                    args[0],
                    args[1],
                    args[2],
                    args[3]
                );
            }
            _ => {}
        }
    }

    // -- signal: log all syscalls for "sleep" processes --
    if crate::debug_config::DEBUG_SIGNAL {
        let is_sleep = {
            let proc = crate::task::processor::current_process();
            let inner = proc.borrow_mut();
            inner
                .argv
                .first()
                .map(|s| s.as_str() == "sleep")
                .unwrap_or(false)
        };
        if is_sleep {
            let now_ms = crate::time::get_time_ms();
            crate::log_if!(
                crate::debug_config::DEBUG_SIGNAL,
                info,
                "[sleep_syscall] now_ms={} id={} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x}",
                now_ms,
                id,
                args[0],
                args[1],
                args[2],
                args[3],
                args[4],
                args[5]
            );
        }
    }

    // -- signal: log time-related syscalls --
    if crate::debug_config::DEBUG_SIGNAL {
        let pid = crate::task::processor::current_process().getpid();
        match id {
            SYSCALL_PSELECT6
            | SYSCALL_PPOLL
            | SYSCALL_NANOSLEEP
            | SYSCALL_SETITIMER
            | SYSCALL_CLOCK_NANOSLEEP
            | SYSCALL_SIGTIMEDWAIT => {
                crate::log_if!(
                    crate::debug_config::DEBUG_SIGNAL,
                    info,
                    "[time_syscall] pid={} id={} a0={:#x} a1={:#x} a2={:#x} a3={:#x}",
                    pid,
                    id,
                    args[0],
                    args[1],
                    args[2],
                    args[3]
                );
            }
            _ => {}
        }
    }

    // -- general syscall trace (with countdown) --
    static TRACE_LEFT: AtomicUsize = AtomicUsize::new(256);
    if crate::debug_config::DEBUG_SYSCALL {
        let pid = crate::task::processor::current_process().getpid();
        if pid >= 2 {
            let left = TRACE_LEFT.fetch_sub(1, Ordering::Relaxed);
            if left > 0 {
                crate::println!(
                    "[syscall] pid={} id={} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x}",
                    pid,
                    id,
                    args[0],
                    args[1],
                    args[2],
                    args[3],
                    args[4],
                    args[5]
                );
            }
        }
    }
}

pub fn syscall(id: usize, args: [usize; 6]) -> isize {
    LAST_SYSCALL_ID.store(id, Ordering::Relaxed);
    LAST_SYSCALL_A0.store(args[0], Ordering::Relaxed);
    LAST_SYSCALL_A1.store(args[1], Ordering::Relaxed);
    LAST_SYSCALL_A2.store(args[2], Ordering::Relaxed);
    LAST_SYSCALL_A3.store(args[3], Ordering::Relaxed);
    LAST_SYSCALL_A4.store(args[4], Ordering::Relaxed);
    LAST_SYSCALL_A5.store(args[5], Ordering::Relaxed);
    trace_syscall_entry(id, &args);
    let ret = match id {
        SYSCALL_GETCWD => filesystem::syscall_getcwd(args[0], args[1]),
        SYSCALL_FCNTL => filesystem::syscall_fcntl(args[0], args[1], args[2]),
        SYSCALL_FLOCK => filesystem::syscall_flock(args[0], args[1]),
        SYSCALL_DUP => filesystem::syscall_dup(args[0]),
        SYSCALL_DUP3 => filesystem::syscall_dup3(args[0], args[1], args[2]),
        SYSCALL_IOCTL => misc::syscall_ioctl(args[0], args[1], args[2]),
        SYSCALL_EVENTFD2 => dummy::syscall_eventfd2(args[0] as u64, args[1]),
        SYSCALL_EPOLL_CREATE1 => epoll::syscall_epoll_create1(args[0]),
        SYSCALL_EPOLL_CTL => epoll::syscall_epoll_ctl(args[0], args[1], args[2], args[3]),
        SYSCALL_EPOLL_PWAIT => {
            epoll::syscall_epoll_pwait(args[0], args[1], args[2], args[3], args[4], args[5])
        }
        SYSCALL_EPOLL_PWAIT2 => {
            epoll::syscall_epoll_pwait2(args[0], args[1], args[2], args[3], args[4], args[5])
        }
        SYSCALL_INOTIFY_INIT1 => dummy::syscall_inotify_init1(args[0]),
        SYSCALL_SETXATTR => {
            filesystem::syscall_setxattr(args[0], args[1], args[2], args[3], args[4])
        }
        SYSCALL_LSETXATTR => {
            filesystem::syscall_lsetxattr(args[0], args[1], args[2], args[3], args[4])
        }
        SYSCALL_FSETXATTR => {
            filesystem::syscall_fsetxattr(args[0], args[1], args[2], args[3], args[4])
        }
        SYSCALL_GETXATTR => filesystem::syscall_getxattr(args[0], args[1], args[2], args[3]),
        SYSCALL_LGETXATTR => filesystem::syscall_lgetxattr(args[0], args[1], args[2], args[3]),
        SYSCALL_FGETXATTR => filesystem::syscall_fgetxattr(args[0], args[1], args[2], args[3]),
        SYSCALL_LISTXATTR => filesystem::syscall_listxattr(args[0], args[1], args[2]),
        SYSCALL_LLISTXATTR => filesystem::syscall_llistxattr(args[0], args[1], args[2]),
        SYSCALL_FLISTXATTR => filesystem::syscall_flistxattr(args[0], args[1], args[2]),
        SYSCALL_REMOVEXATTR => filesystem::syscall_removexattr(args[0], args[1]),
        SYSCALL_LREMOVEXATTR => filesystem::syscall_lremovexattr(args[0], args[1]),
        SYSCALL_FREMOVEXATTR => filesystem::syscall_fremovexattr(args[0], args[1]),
        SYSCALL_MKNODAT => filesystem::syscall_mknodat(args[0] as isize, args[1], args[2], args[3]),
        SYSCALL_MKDIRAT => filesystem::syscall_mkdirat(args[0] as isize, args[1], args[2]),
        SYSCALL_UNLINKAT => filesystem::syscall_unlinkat(args[0] as isize, args[1], args[2]),
        SYSCALL_LINKAT => filesystem::syscall_linkat(
            args[0] as isize,
            args[1],
            args[2] as isize,
            args[3],
            args[4],
        ),
        SYSCALL_FCHMOD => filesystem::syscall_fchmod(args[0], args[1]),
        SYSCALL_FCHMODAT => {
            filesystem::syscall_fchmodat(args[0] as isize, args[1], args[2], args[3])
        }
        SYSCALL_FCHMODAT2 => {
            filesystem::syscall_fchmodat2(args[0] as isize, args[1], args[2], args[3])
        }
        SYSCALL_FCHOWNAT => {
            filesystem::syscall_fchownat(args[0] as isize, args[1], args[2], args[3], args[4])
        }
        SYSCALL_FCHOWN => filesystem::syscall_fchown(args[0], args[1], args[2]),
        SYSCALL_FTRUNCATE => filesystem::syscall_ftruncate(args[0], args[1]),
        SYSCALL_FALLOCATE => filesystem::syscall_fallocate(args[0], args[1], args[2], args[3]),
        SYSCALL_RENAMEAT => {
            filesystem::syscall_renameat(args[0] as isize, args[1], args[2] as isize, args[3])
        }
        SYSCALL_SYMLINKAT => filesystem::syscall_symlinkat(args[0], args[1] as isize, args[2]),
        SYSCALL_UMOUNT2 => filesystem::syscall_umount2(args[0], args[1]),
        SYSCALL_MOUNT => filesystem::syscall_mount(args[0], args[1], args[2], args[3], args[4]),
        SYSCALL_FACCESSAT => {
            filesystem::syscall_faccessat(args[0] as isize, args[1], args[2], args[3])
        }
        SYSCALL_FACCESSAT2 => {
            filesystem::syscall_faccessat2(args[0] as isize, args[1], args[2], args[3])
        }
        SYSCALL_CHDIR => filesystem::syscall_chdir(args[0]),
        SYSCALL_FCHDIR => filesystem::syscall_fchdir(args[0]),
        SYSCALL_CHROOT => filesystem::syscall_chroot(args[0]),
        SYSCALL_OPENAT => filesystem::syscall_openat(args[0] as isize, args[1], args[2], args[3]),
        SYSCALL_READ => flow::syscall_read(args[0], args[1] as *mut u8, args[2]),
        SYSCALL_WRITE => flow::syscall_write(args[0], args[1] as *const u8, args[2]),
        SYSCALL_READV => flow::syscall_readv(args[0], args[1], args[2]),
        SYSCALL_WRITEV => flow::syscall_writev(args[0], args[1], args[2]),
        SYSCALL_PREAD64 => filesystem::syscall_pread64(args[0], args[1], args[2], args[3] as isize),
        SYSCALL_PWRITE64 => {
            filesystem::syscall_pwrite64(args[0], args[1], args[2], args[3] as isize)
        }
        SYSCALL_PREADV => flow::syscall_preadv(args[0], args[1], args[2], args[3] as isize),
        SYSCALL_PWRITEV => flow::syscall_pwritev(args[0], args[1], args[2], args[3] as isize),
        SYSCALL_SENDFILE => filesystem::syscall_sendfile(args[0], args[1], args[2], args[3]),
        SYSCALL_PREADV2 => {
            flow::syscall_preadv2(args[0], args[1], args[2], args[3], args[4], args[5])
        }
        SYSCALL_PWRITEV2 => {
            flow::syscall_pwritev2(args[0], args[1], args[2], args[3], args[4], args[5])
        }
        SYSCALL_PSELECT6 => {
            time_sys::syscall_pselect6(args[0], args[1], args[2], args[3], args[4], args[5])
        }
        SYSCALL_PPOLL => misc::syscall_ppoll(args[0], args[1], args[2], args[3], args[4]),
        SYSCALL_SIGNALFD4 => dummy::syscall_signalfd4(args[0] as isize, args[1], args[2], args[3]),
        SYSCALL_VMSPLICE => filesystem::syscall_vmsplice(args[0], args[1], args[2], args[3]),
        SYSCALL_SPLICE => {
            filesystem::syscall_splice(args[0], args[1], args[2], args[3], args[4], args[5])
        }
        SYSCALL_TEE => filesystem::syscall_tee(args[0], args[1], args[2], args[3]),
        SYSCALL_GETDENTS64 => filesystem::syscall_getdents64(args[0], args[1], args[2]),
        SYSCALL_LSEEK => filesystem::syscall_lseek(args[0], args[1] as isize, args[2]),
        SYSCALL_READLINKAT => {
            filesystem::syscall_readlinkat(args[0] as isize, args[1], args[2], args[3])
        }
        SYSCALL_NEWFSTATAT => {
            filesystem::syscall_newfstatat(args[0] as isize, args[1], args[2], args[3])
        }
        SYSCALL_FSTAT => filesystem::syscall_fstat(args[0], args[1]),
        SYSCALL_TRUNCATE => filesystem::syscall_truncate(args[0], args[1]),
        SYSCALL_STATX => {
            filesystem::syscall_statx(args[0] as isize, args[1], args[2], args[3], args[4])
        }
        SYSCALL_SYNC => filesystem::syscall_sync(),
        SYSCALL_FSYNC => filesystem::syscall_fsync(args[0]),
        SYSCALL_FDATASYNC => filesystem::syscall_fsync(args[0]),
        SYSCALL_SYNC_FILE_RANGE => {
            filesystem::syscall_sync_file_range(args[0], args[1], args[2], args[3])
        }
        SYSCALL_FSTATFS => filesystem::syscall_fstatfs(args[0], args[1]),
        SYSCALL_STATFS => filesystem::syscall_statfs(args[0], args[1]),
        SYSCALL_TIMERFD_CREATE => dummy::syscall_timerfd_create(args[0], args[1]),
        SYSCALL_TIMERFD_SETTIME => {
            dummy::syscall_timerfd_settime(args[0], args[1], args[2], args[3])
        }
        SYSCALL_TIMERFD_GETTIME => dummy::syscall_timerfd_gettime(args[0], args[1]),
        SYSCALL_UTIMENSAT => {
            filesystem::syscall_utimensat(args[0] as isize, args[1], args[2], args[3])
        }
        SYSCALL_ACCT => filesystem::syscall_acct(args[0]),
        SYSCALL_CAPGET => misc::syscall_capget(args[0], args[1]),
        SYSCALL_CAPSET => misc::syscall_capset(args[0], args[1]),
        SYSCALL_PERSONALITY => misc::syscall_personality(args[0]),
        SYSCALL_IOPRIO_SET => misc::syscall_ioprio_set(args[0] as isize, args[1] as isize, args[2]),
        SYSCALL_IOPRIO_GET => misc::syscall_ioprio_get(args[0] as isize, args[1] as isize),
        SYSCALL_PRCTL => misc::syscall_prctl(args[0], args[1], args[2], args[3], args[4]),
        SYSCALL_EXIT => flow::syscall_exit(args[0]),
        SYSCALL_EXIT_GROUP => flow::syscall_exit_group(args[0]),
        SYSCALL_SET_TID_ADDRESS => misc::syscall_set_tid_address(args[0]),
        SYSCALL_UNSHARE => misc::syscall_unshare(args[0]),
        SYSCALL_SETNS => misc::syscall_setns(args[0] as isize, args[1]),
        SYSCALL_FUTEX => futex::syscall_futex(args[0], args[1], args[2], args[3], args[4], args[5]),
        SYSCALL_SET_ROBUST_LIST => misc::syscall_set_robust_list(args[0], args[1]),
        SYSCALL_GET_ROBUST_LIST => misc::syscall_get_robust_list(args[0], args[1], args[2]),
        SYSCALL_NANOSLEEP => time_sys::syscall_nanosleep(args[0], args[1]),
        SYSCALL_GETITIMER => time_sys::syscall_getitimer(args[0], args[1]),
        SYSCALL_SETITIMER => time_sys::syscall_setitimer(args[0], args[1], args[2]),
        SYSCALL_INIT_MODULE => misc::syscall_init_module(args[0], args[1], args[2]),
        SYSCALL_DELETE_MODULE => misc::syscall_delete_module(args[0], args[1]),
        SYSCALL_TIMER_CREATE => time_sys::syscall_timer_create(args[0], args[1], args[2]),
        SYSCALL_TIMER_GETTIME => time_sys::syscall_timer_gettime(args[0] as isize, args[1]),
        SYSCALL_TIMER_GETOVERRUN => time_sys::syscall_timer_getoverrun(args[0] as isize),
        SYSCALL_TIMER_SETTIME => {
            time_sys::syscall_timer_settime(args[0] as isize, args[1], args[2], args[3])
        }
        SYSCALL_TIMER_DELETE => time_sys::syscall_timer_delete(args[0] as isize),
        SYSCALL_ADJTIMEX => time_sys::syscall_adjtimex(args[0]),
        SYSCALL_CLOCK_SETTIME => time_sys::syscall_clock_settime(args[0], args[1]),
        SYSCALL_CLOCK_GETTIME => time_sys::syscall_clock_gettime(args[0], args[1]),
        SYSCALL_CLOCK_GETRES => time_sys::syscall_clock_getres(args[0], args[1]),
        SYSCALL_CLOCK_ADJTIME | SYSCALL_CLOCK_ADJTIME64 => {
            time_sys::syscall_clock_adjtime(args[0], args[1])
        }
        SYSCALL_SYNCFS => filesystem::syscall_syncfs(args[0]),
        SYSCALL_FINIT_MODULE => misc::syscall_finit_module(args[0] as isize, args[1], args[2]),
        SYSCALL_CLOCK_NANOSLEEP => {
            time_sys::syscall_clock_nanosleep(args[0], args[1], args[2], args[3])
        }
        SYSCALL_SYSLOG => misc::syscall_syslog(args[0], args[1], args[2]),
        SYSCALL_PTRACE => process::syscall_ptrace(args[0], args[1], args[2], args[3]),
        SYSCALL_SCHED_SETPARAM => sched::syscall_sched_setparam(args[0], args[1]),
        SYSCALL_SCHED_SETSCHEDULER => sched::syscall_sched_setscheduler(args[0], args[1], args[2]),
        SYSCALL_SCHED_GETSCHEDULER => sched::syscall_sched_getscheduler(args[0]),
        SYSCALL_SCHED_GETPARAM => sched::syscall_sched_getparam(args[0], args[1]),
        SYSCALL_SCHED_SETAFFINITY => sched::syscall_sched_setaffinity(args[0], args[1], args[2]),
        SYSCALL_SCHED_GETAFFINITY => sched::syscall_sched_getaffinity(args[0], args[1], args[2]),
        SYSCALL_YIELD => flow::syscall_yield(),
        SYSCALL_SCHED_GET_PRIORITY_MAX => sched::syscall_sched_get_priority_max(args[0]),
        SYSCALL_SCHED_GET_PRIORITY_MIN => sched::syscall_sched_get_priority_min(args[0]),
        SYSCALL_SCHED_RR_GET_INTERVAL => sched::syscall_sched_rr_get_interval(args[0], args[1]),
        SYSCALL_SCHED_SETATTR => sched::syscall_sched_setattr(args[0], args[1], args[2], args[3]),
        SYSCALL_SCHED_GETATTR => sched::syscall_sched_getattr(args[0], args[1], args[2], args[3]),
        SYSCALL_TIMES => time_sys::syscall_times(args[0]),
        SYSCALL_SETPGID => misc::syscall_setpgid(args[0], args[1]),
        SYSCALL_GETPGID => misc::syscall_getpgid(args[0]),
        SYSCALL_GETSID => misc::syscall_getsid(args[0]),
        SYSCALL_SETSID => misc::syscall_setsid(),
        SYSCALL_GETGROUPS => misc::syscall_getgroups(args[0] as isize, args[1]),
        SYSCALL_SETGROUPS => misc::syscall_setgroups(args[0], args[1]),
        SYSCALL_UNAME => misc::syscall_uname(args[0]),
        SYSCALL_SETHOSTNAME => misc::syscall_sethostname(args[0], args[1]),
        SYSCALL_SETDOMAINNAME => misc::syscall_setdomainname(args[0], args[1]),
        SYSCALL_SETPRIORITY => {
            misc::syscall_setpriority(args[0] as isize, args[1] as isize, args[2] as isize)
        }
        SYSCALL_GETPRIORITY => misc::syscall_getpriority(args[0] as isize, args[1] as isize),
        SYSCALL_UMASK => misc::syscall_umask(args[0]),
        SYSCALL_SETREGID => misc::syscall_setregid(args[0], args[1]),
        SYSCALL_SETGID => misc::syscall_setgid(args[0]),
        SYSCALL_SETREUID => misc::syscall_setreuid(args[0], args[1]),
        SYSCALL_SETUID => misc::syscall_setuid(args[0]),
        SYSCALL_SETRESUID => misc::syscall_setresuid(args[0], args[1], args[2]),
        SYSCALL_GETRESUID => misc::syscall_getresuid(args[0], args[1], args[2]),
        SYSCALL_SETRESGID => misc::syscall_setresgid(args[0], args[1], args[2]),
        SYSCALL_GETRESGID => misc::syscall_getresgid(args[0], args[1], args[2]),
        SYSCALL_SETFSUID => misc::syscall_setfsuid(args[0]),
        SYSCALL_SETFSGID => misc::syscall_setfsgid(args[0]),
        SYSCALL_GETCPU => smp::syscall_getcpu(args[0], args[1], args[2]),
        SYSCALL_SYSINFO => misc::syscall_sysinfo(args[0]),
        SYSCALL_GETTIMEOFDAY => time_sys::syscall_gettimeofday(args[0], args[1]),
        SYSCALL_SETTIMEOFDAY => time_sys::syscall_settimeofday(args[0], args[1]),
        SYSCALL_WAIT4 => process::syscall_wait4(args[0] as isize, args[1], args[2], args[3]),
        SYSCALL_WAITID => process::syscall_waitid(args[0], args[1], args[2], args[3]),
        SYSCALL_EXECVE => process::syscall_execve(args[0], args[1], args[2]),
        SYSCALL_EXECVEAT => {
            process::syscall_execveat(args[0] as isize, args[1], args[2], args[3], args[4])
        }
        SYSCALL_CLONE => process::syscall_clone(args[0], args[1], args[2], args[3], args[4]),
        SYSCALL_CLONE3 => process::syscall_clone3(args[0], args[1]),
        SYSCALL_GETPID => process::syscall_getpid(),
        SYSCALL_GETPPID => misc::syscall_getppid(),
        SYSCALL_GETUID => misc::syscall_getuid(),
        SYSCALL_GETEUID => misc::syscall_geteuid(),
        SYSCALL_GETGID => misc::syscall_getgid(),
        SYSCALL_GETEGID => misc::syscall_getegid(),
        SYSCALL_GETTID_LINUX => misc::syscall_gettid_linux(),
        SYSCALL_MQ_OPEN => posix_mq::syscall_mq_open(args[0], args[1], args[2], args[3]),
        SYSCALL_MQ_UNLINK => posix_mq::syscall_mq_unlink(args[0]),
        SYSCALL_MQ_TIMEDSEND | SYSCALL_MQ_TIMEDSEND_TIME64 => {
            posix_mq::syscall_mq_timedsend(args[0], args[1], args[2], args[3], args[4])
        }
        SYSCALL_MQ_TIMEDRECEIVE | SYSCALL_MQ_TIMEDRECEIVE_TIME64 => {
            posix_mq::syscall_mq_timedreceive(args[0], args[1], args[2], args[3], args[4])
        }
        SYSCALL_MQ_NOTIFY => posix_mq::syscall_mq_notify(args[0], args[1]),
        SYSCALL_MQ_GETSETATTR => posix_mq::syscall_mq_getsetattr(args[0], args[1], args[2]),
        SYSCALL_MSGGET => sysv_ipc::syscall_msgget(args[0], args[1]),
        SYSCALL_MSGCTL => sysv_ipc::syscall_msgctl(args[0], args[1], args[2]),
        SYSCALL_MSGRCV => {
            sysv_ipc::syscall_msgrcv(args[0], args[1], args[2], args[3] as isize, args[4])
        }
        SYSCALL_MSGSND => sysv_ipc::syscall_msgsnd(args[0], args[1], args[2], args[3]),
        SYSCALL_SEMGET => sysv_ipc::syscall_semget(args[0], args[1], args[2]),
        SYSCALL_SEMCTL => sysv_ipc::syscall_semctl(args[0], args[1], args[2], args[3]),
        SYSCALL_SEMTIMEDOP => sysv_ipc::syscall_semtimedop(args[0], args[1], args[2], args[3]),
        SYSCALL_SEMOP => sysv_ipc::syscall_semop(args[0], args[1], args[2]),
        SYSCALL_SHMGET => sysv_shm::syscall_shmget(args[0], args[1], args[2]),
        SYSCALL_SHMCTL => sysv_shm::syscall_shmctl(args[0], args[1], args[2]),
        SYSCALL_SHMAT => sysv_shm::syscall_shmat(args[0], args[1], args[2]),
        SYSCALL_SHMDT => sysv_shm::syscall_shmdt(args[0]),
        SYSCALL_SOCKET => net::syscall_socket(args[0], args[1], args[2]),
        SYSCALL_SOCKETPAIR => socket::syscall_socketpair(args[0], args[1], args[2], args[3]),
        SYSCALL_BIND => net::syscall_bind(args[0], args[1], args[2]),
        SYSCALL_LISTEN => net::syscall_listen(args[0], args[1]),
        SYSCALL_ACCEPT => net::syscall_accept(args[0], args[1], args[2]),
        SYSCALL_ACCEPT4 => net::syscall_accept4(args[0], args[1], args[2], args[3]),
        SYSCALL_CONNECT => net::syscall_connect(args[0], args[1], args[2]),
        SYSCALL_GETSOCKNAME => net::syscall_getsockname(args[0], args[1], args[2]),
        SYSCALL_GETPEERNAME => net::syscall_getpeername(args[0], args[1], args[2]),
        SYSCALL_SENDTO => net::syscall_sendto(args[0], args[1], args[2], args[3], args[4], args[5]),
        SYSCALL_SENDMSG => net::syscall_sendmsg(args[0], args[1], args[2]),
        SYSCALL_RECVFROM => {
            net::syscall_recvfrom(args[0], args[1], args[2], args[3], args[4], args[5])
        }
        SYSCALL_RECVMSG => net::syscall_recvmsg(args[0], args[1], args[2]),
        SYSCALL_RECVMMSG => net::syscall_recvmmsg(args[0], args[1], args[2], args[3], args[4]),
        SYSCALL_SENDMMSG => net::syscall_sendmmsg(args[0], args[1], args[2], args[3]),
        SYSCALL_RECVMMSG_TIME64 => {
            net::syscall_recvmmsg(args[0], args[1], args[2], args[3], args[4])
        }
        SYSCALL_SETSOCKOPT => net::syscall_setsockopt(args[0], args[1], args[2], args[3], args[4]),
        SYSCALL_GETSOCKOPT => net::syscall_getsockopt(args[0], args[1], args[2], args[3], args[4]),
        SYSCALL_SHUTDOWN => net::syscall_shutdown(args[0], args[1]),
        SYSCALL_BRK => memory::syscall_brk(args[0]),
        SYSCALL_MUNMAP => memory::syscall_munmap(args[0], args[1]),
        SYSCALL_MREMAP => memory::syscall_mremap(args[0], args[1], args[2], args[3], args[4]),
        SYSCALL_MMAP => memory::syscall_mmap(
            args[0],
            args[1],
            args[2],
            args[3],
            args[4] as isize,
            args[5],
        ),
        SYSCALL_FADVISE64 => filesystem::syscall_fadvise64(args[0], args[1], args[2], args[3]),
        SYSCALL_MPROTECT => memory::syscall_mprotect(args[0], args[1], args[2]),
        SYSCALL_MSYNC => memory::syscall_msync(args[0], args[1], args[2]),
        SYSCALL_MADVISE => memory::syscall_madvise(args[0], args[1], args[2]),
        SYSCALL_MLOCK => memory::syscall_mlock(args[0], args[1]),
        SYSCALL_MUNLOCK => memory::syscall_munlock(args[0], args[1]),
        SYSCALL_MLOCKALL => memory::syscall_mlockall(args[0]),
        SYSCALL_MUNLOCKALL => memory::syscall_munlockall(),
        SYSCALL_MINCORE => memory::syscall_mincore(args[0], args[1], args[2]),
        SYSCALL_GETRLIMIT => misc::syscall_getrlimit(args[0], args[1]),
        SYSCALL_SETRLIMIT => misc::syscall_setrlimit(args[0], args[1]),
        SYSCALL_GETRUSAGE => misc::syscall_getrusage(args[0] as isize, args[1]),
        SYSCALL_PRLIMIT64 => misc::syscall_prlimit64(args[0], args[1], args[2], args[3]),
        SYSCALL_RENAMEAT2 => filesystem::syscall_renameat2(
            args[0] as isize,
            args[1],
            args[2] as isize,
            args[3],
            args[4],
        ),
        SYSCALL_GETRANDOM => misc::syscall_getrandom(args[0], args[1], args[2] as u32),
        SYSCALL_MEMFD_CREATE => dummy::syscall_memfd_create(args[0], args[1]),
        SYSCALL_BPF => dummy::syscall_bpf(args[0], args[1], args[2]),
        SYSCALL_PIDFD_SEND_SIGNAL => {
            signal::syscall_pidfd_send_signal(args[0], args[1] as i32, args[2], args[3])
        }
        SYSCALL_COPY_FILE_RANGE => filesystem::syscall_copy_file_range(
            args[0], args[1], args[2], args[3], args[4], args[5],
        ),
        SYSCALL_USERFAULTFD => dummy::syscall_userfaultfd(args[0]),
        SYSCALL_PERF_EVENT_OPEN => dummy::syscall_perf_event_open(
            args[0],
            args[1] as isize,
            args[2] as isize,
            args[3] as isize,
            args[4],
        ),
        SYSCALL_FANOTIFY_INIT => filesystem::syscall_fanotify_init(args[0], args[1]),
        SYSCALL_FANOTIFY_MARK => filesystem::syscall_fanotify_mark(
            args[0],
            args[1],
            args[2] as u64,
            args[3] as isize,
            args[4],
        ),
        SYSCALL_CLOSE => filesystem::syscall_close(args[0]),
        SYSCALL_CLOSE_RANGE => filesystem::syscall_close_range(args[0], args[1], args[2]),
        SYSCALL_VFORK => process::syscall_vfork(),
        SYSCALL_PIPE2 => filesystem::syscall_pipe2(args[0], args[1]),
        SYSCALL_IO_URING_SETUP => dummy::syscall_io_uring_setup(args[0], args[1]),
        SYSCALL_OPEN_TREE => filesystem::syscall_open_tree(args[0] as isize, args[1], args[2]),
        SYSCALL_MOVE_MOUNT => filesystem::syscall_move_mount(
            args[0] as isize,
            args[1],
            args[2] as isize,
            args[3],
            args[4],
        ),
        SYSCALL_FSOPEN => filesystem::syscall_fsopen(args[0], args[1]),
        SYSCALL_FSCONFIG => {
            filesystem::syscall_fsconfig(args[0], args[1], args[2], args[3], args[4])
        }
        SYSCALL_FSMOUNT => filesystem::syscall_fsmount(args[0], args[1], args[2]),
        SYSCALL_FSPICK => filesystem::syscall_fspick(args[0] as isize, args[1], args[2]),
        SYSCALL_MOUNT_SETATTR => {
            filesystem::syscall_mount_setattr(args[0] as isize, args[1], args[2], args[3], args[4])
        }
        SYSCALL_PIDFD_OPEN => dummy::syscall_pidfd_open(args[0], args[1]),
        SYSCALL_MEMFD_SECRET => dummy::syscall_memfd_secret(args[0]),
        SYSCALL_REBOOT => misc::syscall_reboot(args[0], args[1], args[2], args[3]),

        SYSCALL_KILL => signal::syscall_kill(args[0], args[1] as i32),
        SYSCALL_TKILL => signal::syscall_tkill(args[0], args[1] as i32),
        SYSCALL_TGKILL => signal::syscall_tgkill(args[0], args[1], args[2] as i32),

        SYSCALL_SIGSUSPEND => signal::syscall_rt_sigsuspend(args[0], args[1]),
        SYSCALL_SIGALTSTACK => signal::syscall_sigaltstack(args[0], args[1]),
        SYSCALL_SIGACTION => signal::syscall_rt_sigaction(args[0], args[1], args[2], args[3]),
        SYSCALL_SIGPROCMASK => signal::syscall_rt_sigprocmask(args[0], args[1], args[2], args[3]),
        SYSCALL_SIGPENDING => signal::syscall_rt_sigpending(args[0], args[1]),
        SYSCALL_SIGTIMEDWAIT => signal::syscall_rt_sigtimedwait(args[0], args[1], args[2], args[3]),
        SYSCALL_SIGRETURN => signal::syscall_rt_sigreturn(),
        SYSCALL_THREAD_CREATE => thread::sys_thread_create(args[0], args[1]),
        SYSCALL_GETTID => thread::sys_gettid(),
        SYSCALL_WAITTID => thread::sys_waittid(args[0] as usize) as isize,

        SYSCALL_MUTEX_CREATE => mutex::sys_mutex_create(args[0] == 1),
        SYSCALL_MUTEX_LOCK => mutex::sys_mutex_lock(args[0]),
        SYSCALL_MUTEX_UNLOCK => mutex::sys_mutex_unlock(args[0]),
        SYSCALL_SEMAPHORE_CREATE => semaphore::sys_semaphore_create(args[0]),
        SYSCALL_SEMAPHORE_UP => semaphore::sys_semaphore_up(args[0]),
        SYSCALL_SEMAPHORE_DOWN => semaphore::sys_semaphore_down(args[0]),
        // condvar
        SYSCALL_CONDVAR_CREATE => condvar::sys_condvar_create(),
        SYSCALL_CONDVAR_SIGNAL => condvar::sys_condvar_signal(args[0]),
        SYSCALL_CONDVAR_WAIT => condvar::sys_condvar_wait(args[0], args[1]),
        SYSCALL_GET_HARTID => smp::sys_get_hartid(),

        // Unknown syscall: Linux returns -ENOSYS.
        _ => {
            static UNKNOWN_LEFT: AtomicUsize = AtomicUsize::new(32);
            if crate::debug_config::DEBUG_SYSCALL {
                let left = UNKNOWN_LEFT.fetch_sub(1, Ordering::Relaxed);
                if left > 0 {
                    let pid = crate::task::processor::current_process().getpid();
                    crate::println!(
                        "[syscall] unknown pid={} id={} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x}",
                        pid,
                        id,
                        args[0],
                        args[1],
                        args[2],
                        args[3],
                        args[4],
                        args[5]
                    );
                }
            }
            -38
        }
    };
    if ret == -95 && crate::debug_config::DEBUG_NET {
        let pid = crate::task::processor::current_process().getpid();
        crate::println!(
            "[syscall] EOPNOTSUPP pid={} id={} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x}",
            pid,
            id,
            args[0],
            args[1],
            args[2],
            args[3],
            args[4],
            args[5]
        );
    }
    ret
}
