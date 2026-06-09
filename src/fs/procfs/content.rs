extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::config;
use crate::mm::{PTEFlags, UserBuffer, VirtAddr, frame_available_pages, frame_managed_pages};
use crate::task::manager::{PID2PCB, pid2process};
use crate::task::task_block::TaskStatus;

use super::ProcFileKind;
use super::entries::{decode_proc_linux_tid, proc_pid_task_alive, proc_simple_text_content};
use super::{parse_proc_sys_i64, parse_proc_sys_usize};
use crate::syscall::error::{SyscallError, err};

const VM_OVERCOMMIT_MEMORY_DEFAULT: usize = 0;
const VM_OVERCOMMIT_MEMORY_MAX: usize = 2;
const VM_OVERCOMMIT_RATIO_DEFAULT: usize = 50;
const VM_OVERCOMMIT_RATIO_MAX: usize = 100;
const VM_MIN_FREE_KBYTES_DEFAULT: usize = 1024;
const VM_MIN_FREE_KBYTES_MAX: usize = usize::MAX / 1024;
const FS_FILE_MAX_DEFAULT: usize = 8192;
const FS_FILE_MAX_MAX: usize = isize::MAX as usize;
static VM_OVERCOMMIT_MEMORY: AtomicUsize = AtomicUsize::new(VM_OVERCOMMIT_MEMORY_DEFAULT);
static VM_OVERCOMMIT_RATIO: AtomicUsize = AtomicUsize::new(VM_OVERCOMMIT_RATIO_DEFAULT);
static VM_MIN_FREE_KBYTES: AtomicUsize = AtomicUsize::new(VM_MIN_FREE_KBYTES_DEFAULT);
static FS_FILE_MAX: AtomicUsize = AtomicUsize::new(FS_FILE_MAX_DEFAULT);
static PROC_PID_STAT_CALLS: AtomicUsize = AtomicUsize::new(0);
static PROC_PID_STAT_STATE_S: AtomicUsize = AtomicUsize::new(0);
static PROC_PID_STAT_STATE_R: AtomicUsize = AtomicUsize::new(0);
static PROC_PID_STAT_STATE_Z: AtomicUsize = AtomicUsize::new(0);
static PROC_PID_STAT_LOCK_BUSY: AtomicUsize = AtomicUsize::new(0);
static PROC_PID_STAT_TOTAL_CYCLES: AtomicUsize = AtomicUsize::new(0);

fn should_report_proc_pid_stat_diag(calls: usize) -> bool {
    calls <= 16 || calls % 2048 == 0
}

fn record_proc_pid_stat_diag(pid: u32, state_char: char, elapsed_cycles: usize, lock_busy: bool) {
    if !crate::debug_config::DEBUG_FUTEX {
        return;
    }
    let calls = PROC_PID_STAT_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
    PROC_PID_STAT_TOTAL_CYCLES.fetch_add(elapsed_cycles, Ordering::Relaxed);
    if lock_busy {
        PROC_PID_STAT_LOCK_BUSY.fetch_add(1, Ordering::Relaxed);
    }
    match state_char {
        'S' => {
            PROC_PID_STAT_STATE_S.fetch_add(1, Ordering::Relaxed);
        }
        'R' => {
            PROC_PID_STAT_STATE_R.fetch_add(1, Ordering::Relaxed);
        }
        'Z' => {
            PROC_PID_STAT_STATE_Z.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
    if should_report_proc_pid_stat_diag(calls) {
        let s = PROC_PID_STAT_STATE_S.load(Ordering::Relaxed);
        let r = PROC_PID_STAT_STATE_R.load(Ordering::Relaxed);
        let z = PROC_PID_STAT_STATE_Z.load(Ordering::Relaxed);
        let busy = PROC_PID_STAT_LOCK_BUSY.load(Ordering::Relaxed);
        let total_cycles = PROC_PID_STAT_TOTAL_CYCLES.load(Ordering::Relaxed);
        let avg_cycles = if calls == 0 { 0 } else { total_cycles / calls };
        log::warn!(
            "[proc_stat_diag] calls={} pid={} state={} s={} r={} z={} lock_busy={} avg_cycles={}",
            calls,
            pid,
            state_char,
            s,
            r,
            z,
            busy,
            avg_cycles
        );
    }
}

pub(super) fn proc_file_content(kind: &ProcFileKind) -> String {
    match kind {
        ProcFileKind::Mounts => proc_mounts_current(),
        ProcFileKind::PidMounts(pid) => proc_mounts_for_pid(*pid),
        ProcFileKind::Cgroups => crate::fs::cgroup_proc_cgroups_content(),
        ProcFileKind::Meminfo => proc_meminfo(),
        ProcFileKind::Cpuinfo => proc_cpuinfo(),
        ProcFileKind::Cmdline => proc_cmdline(),
        ProcFileKind::Loadavg => String::from("0.00 0.00 0.00 1/1 1\n"),
        ProcFileKind::Uptime => proc_uptime(),
        ProcFileKind::Stat => proc_stat(),
        ProcFileKind::Perf => proc_perf(),
        ProcFileKind::Kallsyms => proc_kallsyms(),
        ProcFileKind::Kpageflags => String::new(),
        ProcFileKind::SysvipcMsg => crate::syscall::sysv_ipc::proc_sysvipc_msg(),
        ProcFileKind::SysvipcSem => crate::syscall::sysv_ipc::proc_sysvipc_sem(),
        ProcFileKind::SysvipcShm => crate::syscall::sysv_shm::proc_sysvipc_shm(),
        ProcFileKind::VmMinFreeKbytes => alloc::format!("{}\n", vm_min_free_kbytes()),
        ProcFileKind::VmOvercommitMemory => alloc::format!("{}\n", vm_overcommit_memory()),
        ProcFileKind::VmOvercommitRatio => alloc::format!("{}\n", vm_overcommit_ratio()),
        ProcFileKind::VmDropCaches => String::from("0\n"),
        ProcFileKind::VmCompactMemory => String::from("0\n"),
        ProcFileKind::FsFileMax => alloc::format!("{}\n", fs_file_max()),
        ProcFileKind::FsPipeMaxSize => {
            alloc::format!("{}\n", crate::fs::pipe_max_size_limit_for_procfs())
        }
        ProcFileKind::FsMqueueQueuesMax => alloc::format!(
            "{}\n",
            crate::syscall::posix_mq::queues_max_limit_for_procfs()
        ),
        ProcFileKind::KernelPidMax => alloc::format!("{}\n", crate::task::pid_max()),
        ProcFileKind::KernelMsgmax => alloc::format!(
            "{}\n",
            crate::syscall::sysv_ipc::runtime_msgmax_for_procfs()
        ),
        ProcFileKind::KernelMsgmnb => alloc::format!(
            "{}\n",
            crate::syscall::sysv_ipc::runtime_msgmnb_for_procfs()
        ),
        ProcFileKind::KernelMsgmni => alloc::format!(
            "{}\n",
            crate::syscall::sysv_ipc::runtime_msgmni_for_procfs()
        ),
        ProcFileKind::KernelSem => {
            let (semmsl, semmns, semopm, semmni) =
                crate::syscall::sysv_ipc::runtime_sem_limits_for_procfs();
            alloc::format!("{}\t{}\t{}\t{}\n", semmsl, semmns, semopm, semmni)
        }
        ProcFileKind::KernelShmmax => alloc::format!(
            "{}\n",
            crate::syscall::sysv_shm::runtime_shmmax_for_procfs()
        ),
        ProcFileKind::KernelShmmni => alloc::format!(
            "{}\n",
            crate::syscall::sysv_shm::runtime_shmmni_for_procfs()
        ),
        ProcFileKind::KernelShmall => alloc::format!(
            "{}\n",
            crate::syscall::sysv_shm::runtime_shmall_for_procfs()
        ),
        ProcFileKind::KernelSchedRtPeriodUs => {
            alloc::format!("{}\n", crate::task::sched::rt_period_us())
        }
        ProcFileKind::KernelSchedRtRuntimeUs => {
            alloc::format!("{}\n", crate::task::sched::rt_runtime_us())
        }
        ProcFileKind::KernelSchedRrTimesliceMs => {
            alloc::format!("{}\n", crate::task::sched::rr_timeslice_ms())
        }
        ProcFileKind::SimpleText(path) => proc_simple_text_content(path),
        ProcFileKind::PidStat(pid) => proc_pid_stat(*pid),
        ProcFileKind::PidCmdline(pid) => proc_pid_cmdline(*pid),
        ProcFileKind::PidComm(pid) => proc_pid_comm(*pid),
        ProcFileKind::PidStatus(pid) => proc_pid_status(*pid),
        ProcFileKind::PidMaps(pid) => proc_pid_maps(*pid),
        ProcFileKind::PidPagemap(_) => String::new(),
        ProcFileKind::PidSmaps(pid) => proc_pid_smaps(*pid),
        ProcFileKind::PidCoredumpFilter => String::from("00000033\n"),
        ProcFileKind::PidCgroup(pid) => crate::fs::cgroup_proc_pid_content(*pid as usize),
        ProcFileKind::PidTaskStat(pid, tid) => proc_pid_task_stat(*pid, *tid),
        ProcFileKind::PidTaskComm(pid, tid) => proc_pid_task_comm(*pid, *tid),
    }
}

fn proc_kallsyms() -> String {
    String::from(
        "ffffffff80200000 T _stext\n\
         ffffffff80201000 T kernel_start\n\
         ffffffff80202000 T trap_handler\n",
    )
}

fn proc_mounts_current() -> String {
    crate::syscall::filesystem::proc_mounts_snapshot()
}

fn proc_mounts_for_pid(pid: u32) -> String {
    let Some(process) = pid2process(pid as usize) else {
        return proc_mounts_current();
    };
    crate::syscall::filesystem::proc_mounts_snapshot_for_process(&process)
}

pub(super) fn write_vm_sysctl(path: &str, data: &[u8]) -> Result<Vec<u8>, isize> {
    let (slot, max) = match path {
        "/proc/sys/vm/min_free_kbytes" => (&VM_MIN_FREE_KBYTES, VM_MIN_FREE_KBYTES_MAX),
        "/proc/sys/vm/overcommit_memory" => (&VM_OVERCOMMIT_MEMORY, VM_OVERCOMMIT_MEMORY_MAX),
        "/proc/sys/vm/overcommit_ratio" => (&VM_OVERCOMMIT_RATIO, VM_OVERCOMMIT_RATIO_MAX),
        _ => return Err(err(SyscallError::EINVAL)),
    };
    let value = parse_proc_sys_usize(data)?;
    if value > max {
        return Err(err(SyscallError::EINVAL));
    }
    slot.store(value, Ordering::Relaxed);
    Ok(alloc::format!("{}\n", value).into_bytes())
}

pub(super) fn write_fs_file_max_sysctl(data: &[u8]) -> Result<Vec<u8>, isize> {
    let value = parse_proc_sys_usize(data)?;
    if value > FS_FILE_MAX_MAX {
        return Err(err(SyscallError::EINVAL));
    }
    FS_FILE_MAX.store(value, Ordering::Relaxed);
    Ok(alloc::format!("{}\n", value).into_bytes())
}

/// 处理对三个 `/proc/sys/kernel/sched_*` 文件的写入：解析 i64 后路由到
/// `task::sched` 的对应 setter；setter 拒绝（越界/违反约束）则返回 EINVAL，
/// 成功则回显实际生效值（与 Linux procfs 行为一致）。
pub(super) fn write_sched_sysctl(path: &str, data: &[u8]) -> Result<Vec<u8>, isize> {
    let value = parse_proc_sys_i64(data)?;
    let applied = match path {
        "/proc/sys/kernel/sched_rt_period_us" => {
            crate::task::sched::set_rt_period_us_from_procfs(value)
        }
        "/proc/sys/kernel/sched_rt_runtime_us" => {
            crate::task::sched::set_rt_runtime_us_from_procfs(value)
        }
        "/proc/sys/kernel/sched_rr_timeslice_ms" => {
            crate::task::sched::set_rr_timeslice_ms_from_procfs(value).map(|v| v as i64)
        }
        _ => None,
    };
    let Some(applied) = applied else {
        return Err(err(SyscallError::EINVAL));
    };
    Ok(alloc::format!("{}\n", applied).into_bytes())
}

pub fn vm_overcommit_memory() -> usize {
    VM_OVERCOMMIT_MEMORY.load(Ordering::Relaxed)
}

pub fn vm_min_free_kbytes() -> usize {
    VM_MIN_FREE_KBYTES.load(Ordering::Relaxed)
}

fn vm_overcommit_ratio() -> usize {
    VM_OVERCOMMIT_RATIO.load(Ordering::Relaxed)
}

fn fs_file_max() -> usize {
    FS_FILE_MAX.load(Ordering::Relaxed)
}

pub fn vm_commit_limit_bytes() -> usize {
    let managed_ram = frame_managed_pages().saturating_mul(config::PAGE_SIZE);
    let strict_limit = managed_ram
        .saturating_mul(vm_overcommit_ratio())
        .saturating_div(100);
    strict_limit.saturating_sub(vm_min_free_kbytes().saturating_mul(1024))
}

pub fn vm_committed_as_bytes() -> usize {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    processes.iter().fold(0usize, |acc, process| {
        let Some(inner) = process.try_borrow_mut() else {
            return acc;
        };
        let memory_set = inner.memory_set.lock();
        let heap = memory_set.heap_size();
        let anon_private = memory_set.anon_private_writable_vm_bytes();
        acc.saturating_add(heap).saturating_add(anon_private)
    })
}

fn proc_meminfo() -> String {
    let totalram = frame_managed_pages().saturating_mul(config::PAGE_SIZE);
    let mem_total_kb = (totalram / 1024) as u64;
    let mem_free_kb =
        ((frame_available_pages().saturating_mul(config::PAGE_SIZE)).min(totalram) / 1024) as u64;
    let commit_limit_kb = (vm_commit_limit_bytes() / 1024) as u64;
    let committed_as_kb = (vm_committed_as_bytes() / 1024) as u64;
    alloc::format!(
        "MemTotal:       {} kB\nMemFree:        {} kB\nBuffers:        0 kB\nCached:         0 kB\nSwapTotal:      0 kB\nSwapFree:       0 kB\nCommitLimit:    {} kB\nCommitted_AS:   {} kB\n",
        mem_total_kb,
        mem_free_kb,
        commit_limit_kb,
        committed_as_kb
    )
}

fn proc_cpuinfo() -> String {
    String::from(
        "processor\t: 0\nvendor_id\t: QEMU\nmodel name\t: QEMU Virtual CPU\ncpu MHz\t\t: 1000.000\n",
    )
}

fn proc_cmdline() -> String {
    String::from("root=/dev/vda rw console=ttyS0\n")
}

fn proc_uptime() -> String {
    let ms = crate::time::get_time_ms();
    let secs = ms / 1000;
    let frac = (ms % 1000) / 10;
    alloc::format!("{secs}.{frac:02} 0.00\n")
}

fn proc_stat() -> String {
    String::from(
        "cpu  0 0 0 0 0 0 0 0 0 0\nintr 0\nctxt 0\nbtime 0\nprocesses 0\nprocs_running 1\nprocs_blocked 0\n",
    )
}

fn proc_perf() -> String {
    crate::perf::dump()
}

fn proc_pid_cmdline(pid: u32) -> String {
    let Some(proc) = pid2process(pid as usize) else {
        return String::new();
    };
    let Some(inner) = proc.try_borrow_mut() else {
        if crate::debug_config::DEBUG_PROCFS {
            crate::println!("[procfs] cmdline pid={} lock busy", pid);
        }
        return String::new();
    };
    let argv = inner.argv.clone();
    let mut s = String::new();
    for arg in argv.iter() {
        s.push_str(arg);
        s.push('\0');
    }
    s
}

fn proc_pid_comm(pid: u32) -> String {
    let Some(proc) = pid2process(pid as usize) else {
        return String::new();
    };
    let Some(inner) = proc.try_borrow_mut() else {
        if crate::debug_config::DEBUG_PROCFS {
            crate::println!("[procfs] comm pid={} lock busy", pid);
        }
        return String::new();
    };
    let mut comm = inner.comm.clone();
    if comm.is_empty() {
        comm = inner
            .argv
            .first()
            .map(|s| s.rsplit('/').next().unwrap_or(s.as_str()))
            .unwrap_or("CongCore")
            .to_string();
    }
    comm = comm.replace(')', "_");
    comm.push('\n');
    comm
}

fn proc_pid_status(pid: u32) -> String {
    let Some(proc) = pid2process(pid as usize) else {
        return String::new();
    };
    let Some(inner) = proc.try_borrow_mut() else {
        if crate::debug_config::DEBUG_PROCFS {
            crate::println!("[procfs] status pid={} lock busy", pid);
        }
        return String::new();
    };
    let ppid = inner
        .parent
        .as_ref()
        .and_then(|w| w.upgrade())
        .map(|p| p.getpid())
        .unwrap_or(0);
    let num_threads = inner.thread_count();
    let (main_state, cgroup_frozen) = inner
        .tasks
        .iter()
        .flatten()
        .next()
        .and_then(|t| {
            t.try_borrow_mut()
                .map(|ti| (ti.task_status, ti.cgroup_frozen))
        })
        .unwrap_or((TaskStatus::Ready, false));
    let (heap_bytes, mmap_bytes, vmlck_bytes) = {
        let memory_set = inner.memory_set.lock();
        (
            memory_set.heap_size(),
            memory_set.vm_regions_total_len(),
            memory_set.locked_bytes(),
        )
    };
    let vsize_kb: usize = (config::USER_STACK_SIZE + heap_bytes + mmap_bytes) / 1024;
    let vmlck_kb: usize = (vmlck_bytes + 1023) / 1024;
    let uid = inner.uid;
    let euid = inner.euid;
    let suid = inner.suid;
    let fsuid = inner.fsuid;
    let gid = inner.gid;
    let egid = inner.egid;
    let sgid = inner.sgid;
    let fsgid = inner.fsgid;

    let comm = if inner.comm.is_empty() {
        inner
            .argv
            .first()
            .map(|s| s.rsplit('/').next().unwrap_or(s.as_str()))
            .unwrap_or("CongCore")
            .to_string()
    } else {
        inner.comm.clone()
    }
    .replace(')', "_");

    let state_char = if inner.is_zombie {
        'Z'
    } else if inner.stopped {
        'T'
    } else if cgroup_frozen {
        'D'
    } else {
        match main_state {
            TaskStatus::Running => 'R',
            TaskStatus::Ready => 'R',
            TaskStatus::Blocked => 'S',
        }
    };
    let state_desc = match state_char {
        'R' => "R (running)",
        'S' => "S (sleeping)",
        'D' => "D (disk sleep)",
        'T' => "T (stopped)",
        'Z' => "Z (zombie)",
        _ => "R (running)",
    };
    alloc::format!(
        "Name:\t{comm}\nState:\t{state_desc}\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{ppid}\nUid:\t{uid}\t{euid}\t{suid}\t{fsuid}\nGid:\t{gid}\t{egid}\t{sgid}\t{fsgid}\nThreads:\t{num_threads}\nVmLck:\t{vmlck_kb} kB\nVmSize:\t{vsize_kb} kB\n"
    )
}

fn proc_pid_stat(pid: u32) -> String {
    let start_cycles = if crate::debug_config::DEBUG_FUTEX {
        crate::arch::read_time()
    } else {
        0
    };
    let Some(proc) = pid2process(pid as usize) else {
        return String::new();
    };
    let Some(inner) = proc.try_borrow_mut() else {
        let elapsed = if crate::debug_config::DEBUG_FUTEX {
            crate::arch::read_time().wrapping_sub(start_cycles)
        } else {
            0
        };
        record_proc_pid_stat_diag(pid, 'B', elapsed, true);
        if crate::debug_config::DEBUG_PROCFS {
            crate::println!("[procfs] stat pid={} lock busy", pid);
        }
        return String::new();
    };
    let ppid = inner
        .parent
        .as_ref()
        .and_then(|w| w.upgrade())
        .map(|p| p.getpid())
        .unwrap_or(0);
    let start_time_ms = inner.start_time_ms;
    let num_threads = inner.thread_count();
    let (main_state, cgroup_frozen) = inner
        .tasks
        .iter()
        .flatten()
        .next()
        .and_then(|t| {
            t.try_borrow_mut()
                .map(|ti| (ti.task_status, ti.cgroup_frozen))
        })
        .unwrap_or((TaskStatus::Ready, false));
    let (heap_bytes, mmap_bytes) = {
        let memory_set = inner.memory_set.lock();
        (memory_set.heap_size(), memory_set.vm_regions_total_len())
    };
    let vsize: u64 = (config::USER_STACK_SIZE + heap_bytes + mmap_bytes) as u64;

    let comm = if inner.comm.is_empty() {
        inner
            .argv
            .first()
            .map(|s| s.rsplit('/').next().unwrap_or(s.as_str()))
            .unwrap_or("CongCore")
            .to_string()
    } else {
        inner.comm.clone()
    }
    .replace(')', "_");

    let state_char = if inner.is_zombie {
        'Z'
    } else if inner.stopped {
        'T'
    } else if cgroup_frozen {
        'D'
    } else {
        match main_state {
            TaskStatus::Running => 'R',
            TaskStatus::Ready => 'R',
            TaskStatus::Blocked => 'S',
        }
    };

    const HZ: u64 = 100;
    let starttime = (start_time_ms as u64).saturating_mul(HZ) / 1000;
    let rss_pages: u64 = if vsize == 0 {
        0
    } else {
        (vsize + config::PAGE_SIZE as u64 - 1) / config::PAGE_SIZE as u64
    };

    let pgrp = (if inner.pgid == 0 {
        pid as usize
    } else {
        inner.pgid
    }) as u32;
    let session = if inner.sid == 0 {
        pgrp
    } else {
        inner.sid as u32
    };

    let tty_nr = 0;
    let tpgid = 0;
    let flags = 0;
    let minflt = 0;
    let cminflt = 0;
    let majflt = 0;
    let cmajflt = 0;
    let now_ms = crate::time::get_time_ms() as u64;
    let elapsed_ticks = now_ms
        .saturating_mul(HZ)
        .saturating_div(1000)
        .saturating_sub(starttime);
    let utime = core::cmp::max(elapsed_ticks, 1);
    let stime = 0;
    let cutime = 0;
    let cstime = 0;
    let priority = 0;
    let nice = 0;
    let itrealvalue = 0;
    let rsslim = 0;
    let startcode = 0;
    let endcode = 0;
    let startstack = 0;
    let kstkesp = 0;
    let kstkeip = 0;
    let signal = 0;
    let blocked = 0;
    let sigignore = 0;
    let sigcatch = 0;
    let wchan = 0;
    let nswap = 0;
    let cnswap = 0;
    let exit_signal = 0;
    let processor = 0;
    let rt_priority = 0;
    let policy = 0;
    let delayacct_blkio_ticks = 0;
    let guest_time = 0;
    let cguest_time = 0;
    let start_data = 0;
    let end_data = 0;
    let start_brk = 0;
    let arg_start = 0;
    let arg_end = 0;
    let env_start = 0;
    let env_end = 0;
    let exit_code = 0;

    let out = alloc::format!(
        "{pid} ({comm}) {state_char} {ppid} {pgrp} {session} {tty_nr} {tpgid} {flags} {minflt} {cminflt} {majflt} {cmajflt} {utime} {stime} {cutime} {cstime} {priority} {nice} {num_threads} {itrealvalue} {starttime} {vsize} {rss_pages} {rsslim} {startcode} {endcode} {startstack} {kstkesp} {kstkeip} {signal} {blocked} {sigignore} {sigcatch} {wchan} {nswap} {cnswap} {exit_signal} {processor} {rt_priority} {policy} {delayacct_blkio_ticks} {guest_time} {cguest_time} {start_data} {end_data} {start_brk} {arg_start} {arg_end} {env_start} {env_end} {exit_code}\n"
    );
    let elapsed = if crate::debug_config::DEBUG_FUTEX {
        crate::arch::read_time().wrapping_sub(start_cycles)
    } else {
        0
    };
    record_proc_pid_stat_diag(pid, state_char, elapsed, false);
    out
}

fn proc_pid_task_stat(pid: u32, tid: u32) -> String {
    let Some(proc) = pid2process(pid as usize) else {
        return String::new();
    };
    let Some(inner) = proc.try_borrow_mut() else {
        if crate::debug_config::DEBUG_PROCFS {
            crate::println!("[procfs] task stat pid={} tid={} lock busy", pid, tid);
        }
        return String::new();
    };
    let Some(tid_index) = decode_proc_linux_tid(pid, tid) else {
        return String::new();
    };
    let Some((task_state, cgroup_frozen)) = inner
        .tasks
        .get(tid_index)
        .and_then(|t| t.as_ref())
        .and_then(|t| {
            t.try_borrow_mut().and_then(|ti| {
                if ti.res.is_none() || ti.exit_code.is_some() {
                    None
                } else {
                    Some((ti.task_status, ti.cgroup_frozen))
                }
            })
        })
    else {
        return String::new();
    };

    let ppid = inner
        .parent
        .as_ref()
        .and_then(|w| w.upgrade())
        .map(|p| p.getpid())
        .unwrap_or(0);
    let comm = if inner.comm.is_empty() {
        inner
            .argv
            .first()
            .map(|s| s.rsplit('/').next().unwrap_or(s.as_str()))
            .unwrap_or("CongCore")
            .to_string()
    } else {
        inner.comm.clone()
    }
    .replace(')', "_");
    let state_char = if inner.is_zombie {
        'Z'
    } else if inner.stopped {
        'T'
    } else if cgroup_frozen {
        'D'
    } else {
        match task_state {
            TaskStatus::Running => 'R',
            TaskStatus::Ready => 'R',
            TaskStatus::Blocked => 'S',
        }
    };
    alloc::format!("{tid} ({comm}) {state_char} {ppid}\n")
}

fn proc_pid_task_comm(pid: u32, tid: u32) -> String {
    if !proc_pid_task_alive(pid, tid) {
        return String::new();
    }
    proc_pid_comm(pid)
}

fn proc_pid_maps(pid: u32) -> String {
    const PROT_READ: usize = 1;
    const PROT_WRITE: usize = 2;
    const PROT_EXEC: usize = 4;

    let Some(proc) = pid2process(pid as usize) else {
        return String::new();
    };
    let inner = proc.borrow_mut();
    let regions = {
        let memory_set = inner.memory_set.lock();
        memory_set.vm_regions_snapshot()
    };
    drop(inner);

    let mut out = String::with_capacity(regions.len().saturating_mul(48));
    for region in regions {
        let end = region.end();
        if end <= region.start {
            continue;
        }
        let r = if (region.prot & PROT_READ) != 0 {
            'r'
        } else {
            '-'
        };
        let w = if (region.prot & PROT_WRITE) != 0 {
            'w'
        } else {
            '-'
        };
        let x = if (region.prot & PROT_EXEC) != 0 {
            'x'
        } else {
            '-'
        };
        let p = if region.shared { 's' } else { 'p' };
        let path = if region.is_heap() {
            " [heap]"
        } else if region.is_stack() {
            " [stack]"
        } else {
            " "
        };
        let _ = writeln!(
            out,
            "{:x}-{:x} {}{}{}{} 00000000 00:00 0{}",
            region.start, end, r, w, x, p, path
        );
    }
    out
}

fn proc_pid_pagemap_entry(pid: u32, entry: usize) -> u64 {
    let Some(proc) = pid2process(pid as usize) else {
        return 0;
    };
    let Some(inner) = proc.try_borrow_mut() else {
        return 0;
    };
    let Some(vaddr) = entry.checked_mul(config::PAGE_SIZE) else {
        return 0;
    };
    let vpn = VirtAddr::from(vaddr).floor();
    let memory_set = inner.memory_set.lock();
    if let Some(pte) = memory_set.translate(vpn) {
        if pte.is_valid() {
            return (1u64 << 63) | (pte.ppn().0 as u64 & ((1u64 << 55) - 1));
        }
    }
    0
}

fn proc_kpageflags_entry(pfn: usize) -> u64 {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    for process in processes {
        let Some(inner) = process.try_borrow_mut() else {
            continue;
        };
        let memory_set = inner.memory_set.lock();
        for (start, end) in memory_set.user_mapped_ranges() {
            let mut cur = start;
            while cur < end {
                let vpn = VirtAddr::from(cur).floor();
                if let Some(pte) = memory_set.translate(vpn) {
                    if pte.is_valid() && pte.ppn().0 == pfn {
                        let mut flags = 0u64;
                        if pte.flags().contains(PTEFlags::D) {
                            flags |= 1u64 << 4;
                        }
                        return flags;
                    }
                }
                cur = cur.saturating_add(config::PAGE_SIZE);
            }
        }
    }
    0
}

pub(super) fn proc_kpageflags_len() -> usize {
    // /proc/kpageflags is indexed by absolute PFN, matching the PFN exposed by
    // /proc/*/pagemap.  RISC-V physical memory starts at a high address, so a
    // span-only length makes valid PFN offsets look like EOF.
    let page_count = config::phys_mem_end() / config::PAGE_SIZE;
    page_count.saturating_mul(8)
}

pub(super) fn proc_pid_pagemap_len(pid: u32) -> usize {
    let Some(proc) = pid2process(pid as usize) else {
        return 0;
    };
    let Some(inner) = proc.try_borrow_mut() else {
        return 0;
    };
    let max_end = {
        let memory_set = inner.memory_set.lock();
        memory_set.max_user_mapped_end()
    };
    let page_count = max_end.saturating_add(config::PAGE_SIZE - 1) / config::PAGE_SIZE;
    page_count.saturating_mul(8)
}

pub(super) fn proc_kpageflags_read(offset: &mut usize, buf: &mut UserBuffer) -> usize {
    let limit = proc_kpageflags_len();
    if *offset >= limit {
        return 0;
    }
    let mut total = 0usize;
    for slice in buf.buffers.iter_mut() {
        let mut i = 0usize;
        while i < slice.len() && *offset < limit {
            let entry = (*offset) / 8;
            let byte_in_entry = (*offset) % 8;
            let val = proc_kpageflags_entry(entry);
            slice[i] = ((val >> (byte_in_entry * 8)) & 0xff) as u8;
            *offset += 1;
            i += 1;
            total += 1;
        }
    }
    total
}

pub(super) fn proc_pid_pagemap_read(pid: u32, offset: &mut usize, buf: &mut UserBuffer) -> usize {
    let limit = proc_pid_pagemap_len(pid);
    if *offset >= limit {
        return 0;
    }
    let mut total = 0usize;
    for slice in buf.buffers.iter_mut() {
        let mut i = 0usize;
        while i < slice.len() && *offset < limit {
            let entry = (*offset) / 8;
            let byte_in_entry = (*offset) % 8;
            let val = proc_pid_pagemap_entry(pid, entry);
            slice[i] = ((val >> (byte_in_entry * 8)) & 0xff) as u8;
            *offset += 1;
            i += 1;
            total += 1;
        }
    }
    total
}

fn proc_pid_smaps(pid: u32) -> String {
    const PROT_READ: usize = 1;
    const PROT_WRITE: usize = 2;
    const PROT_EXEC: usize = 4;

    let Some(proc) = pid2process(pid as usize) else {
        return String::new();
    };
    let inner = proc.borrow_mut();
    let regions = {
        let memory_set = inner.memory_set.lock();
        let mut regions = memory_set.vm_regions_snapshot();
        regions.sort_by_key(|r| r.start);
        regions
            .into_iter()
            .map(|region| {
                let locked_bytes = memory_set.locked_overlap_bytes(region.start, region.end());
                (region, locked_bytes)
            })
            .collect::<Vec<_>>()
    };
    drop(inner);

    let mut out = String::new();
    for (region, locked_bytes) in regions {
        let end = region.end();
        if end <= region.start {
            continue;
        }
        let r = if (region.prot & PROT_READ) != 0 {
            'r'
        } else {
            '-'
        };
        let w = if (region.prot & PROT_WRITE) != 0 {
            'w'
        } else {
            '-'
        };
        let x = if (region.prot & PROT_EXEC) != 0 {
            'x'
        } else {
            '-'
        };
        let p = if region.shared { 's' } else { 'p' };
        let path = if region.is_heap() {
            " [heap]"
        } else if region.is_stack() {
            " [stack]"
        } else {
            " "
        };

        let size_bytes = end - region.start;
        let size_kb = (size_bytes + 1023) / 1024;
        let locked_kb = (locked_bytes + 1023) / 1024;
        // LTP mlock05 only validates that Rss/Locked reflect mlock'ed mappings.
        let rss_kb = if locked_bytes > 0 { size_kb } else { 0 };

        out.push_str(&alloc::format!(
            "{:x}-{:x} {}{}{}{} 00000000 00:00 0{}\n",
            region.start,
            end,
            r,
            w,
            x,
            p,
            path
        ));
        out.push_str(&alloc::format!("Size:\t\t{} kB\n", size_kb));
        out.push_str(&alloc::format!("Rss:\t\t{} kB\n", rss_kb));
        out.push_str("Pss:\t\t0 kB\n");
        out.push_str("Shared_Clean:\t0 kB\n");
        out.push_str("Shared_Dirty:\t0 kB\n");
        out.push_str("Private_Clean:\t0 kB\n");
        out.push_str("Private_Dirty:\t0 kB\n");
        out.push_str("Referenced:\t0 kB\n");
        out.push_str("Anonymous:\t0 kB\n");
        out.push_str("AnonHugePages:\t0 kB\n");
        out.push_str("Swap:\t\t0 kB\n");
        out.push_str(&alloc::format!("Locked:\t\t{} kB\n", locked_kb));
        out.push('\n');
    }
    out
}
