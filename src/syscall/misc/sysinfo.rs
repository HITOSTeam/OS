use crate::{
    arch,
    config::{PAGE_SIZE, phys_mem_total},
    mm::{frame_available_pages, try_copy_from_user, try_write_user_value},
    syscall::error::{SyscallError, err},
    task::{manager::PID2PCB, processor::current_process},
    time::get_time_ms,
    trap::get_current_token,
};

pub(crate) const UTS_RELEASE: &str = "5.15.0";
pub(crate) const UTS_VERSION: &str = "CongCore";

/// Linux exposes the same compiled release/version identity through uname(2)
/// and /proc/version. Keep the proc banner derived from these shared values.
pub(crate) fn proc_version_content() -> alloc::string::String {
    alloc::format!("Linux version {} ({}) #1 SMP\n", UTS_RELEASE, UTS_VERSION)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UtsName {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct LinuxSysinfo {
    uptime: isize,
    loads: [usize; 3],
    totalram: usize,
    freeram: usize,
    sharedram: usize,
    bufferram: usize,
    totalswap: usize,
    freeswap: usize,
    procs: u16,
    pad: u16,
    totalhigh: usize,
    freehigh: usize,
    mem_unit: u32,
    _f: [u8; 0],
}

fn write_name_field(dst: &mut [u8; 65], src: &[u8]) {
    dst.fill(0);
    let n = src.len().min(64);
    dst[..n].copy_from_slice(&src[..n]);
}

fn read_name_from_user(name: usize, len: usize) -> Result<[u8; 65], isize> {
    if len > 64 {
        return Err(err(SyscallError::EINVAL));
    }
    let mut field = [0u8; 65];
    if len == 0 {
        return Ok(field);
    }
    let token = get_current_token();
    if try_copy_from_user(token, name as *const u8, &mut field[..len]).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    Ok(field)
}

pub fn syscall_sethostname(name: usize, len: usize) -> isize {
    let process = current_process();
    if process.borrow_mut().euid != 0 {
        return err(SyscallError::EPERM);
    }
    let new_name = match read_name_from_user(name, len) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let uts_ns = process.uts_namespace();
    uts_ns.lock().nodename = new_name;
    0
}

pub fn syscall_setdomainname(name: usize, len: usize) -> isize {
    let process = current_process();
    if process.borrow_mut().euid != 0 {
        return err(SyscallError::EPERM);
    }
    let new_name = match read_name_from_user(name, len) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let uts_ns = process.uts_namespace();
    uts_ns.lock().domainname = new_name;
    0
}

/// Linux `personality(2)`:
/// - `persona == -1UL` queries current personality
/// - otherwise set personality and return previous value
pub fn syscall_personality(persona: usize) -> isize {
    let process = current_process();
    let mut inner = process.borrow_mut();
    let old = inner.personality;
    if persona == usize::MAX {
        return old as isize;
    }
    inner.personality = persona as u32;
    old as isize
}

pub fn syscall_uname(buf: usize) -> isize {
    if buf == 0 {
        return err(SyscallError::EFAULT);
    }
    let mut un = UtsName {
        sysname: [0; 65],
        nodename: [0; 65],
        release: [0; 65],
        version: [0; 65],
        machine: [0; 65],
        domainname: [0; 65],
    };
    write_name_field(&mut un.sysname, b"Linux");
    // glibc/busybox may abort early if the reported kernel release is "too old".
    // Report a modern Linux-like release string for compatibility.
    write_name_field(&mut un.release, UTS_RELEASE.as_bytes());
    write_name_field(&mut un.version, UTS_VERSION.as_bytes());
    let machine = if cfg!(target_arch = "loongarch64") {
        b"loongarch64".as_slice()
    } else {
        b"riscv64".as_slice()
    };
    write_name_field(&mut un.machine, machine);
    {
        let uts_ns = current_process().uts_namespace();
        let cfg = uts_ns.lock();
        un.nodename = cfg.nodename;
        un.domainname = cfg.domainname;
    }

    let token = get_current_token();
    if try_write_user_value(token, buf as *mut UtsName, &un).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

pub fn syscall_sysinfo(info: usize) -> isize {
    if info == 0 {
        return err(SyscallError::EFAULT);
    }

    let totalram = phys_mem_total();
    let freeram = frame_available_pages()
        .saturating_mul(PAGE_SIZE)
        .min(totalram);
    let procs = PID2PCB.lock().len().min(u16::MAX as usize) as u16;
    let sysinfo = LinuxSysinfo {
        uptime: (get_time_ms() / 1000) as isize,
        loads: [0; 3],
        totalram,
        freeram,
        sharedram: 0,
        bufferram: 0,
        totalswap: 0,
        freeswap: 0,
        procs,
        pad: 0,
        totalhigh: 0,
        freehigh: 0,
        mem_unit: 1,
        _f: [],
    };
    let token = get_current_token();
    if try_write_user_value(token, info as *mut LinuxSysinfo, &sysinfo).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

/// Linux-compatible gethostname behavior used by some musl paths:
/// return err(SyscallError::ENAMETOOLONG) if the provided buffer cannot hold the full name.
#[allow(dead_code)]
pub fn syscall_gethostname(name: usize, len: usize) -> isize {
    if name == 0 {
        return err(SyscallError::EFAULT);
    }
    let nodename = {
        let uts_ns = current_process().uts_namespace();
        let cfg = uts_ns.lock();
        cfg.nodename
    };
    let host_len = nodename.iter().position(|&c| c == 0).unwrap_or(64);
    let token = get_current_token();

    if len == 0 {
        return err(SyscallError::ENAMETOOLONG);
    }

    if len <= host_len {
        for i in 0..len {
            if try_write_user_value(token, (name + i) as *mut u8, &nodename[i]).is_err() {
                return err(SyscallError::EFAULT);
            }
        }
        return err(SyscallError::ENAMETOOLONG);
    }

    for i in 0..host_len {
        if try_write_user_value(token, (name + i) as *mut u8, &nodename[i]).is_err() {
            return err(SyscallError::EFAULT);
        }
    }
    let zero: u8 = 0;
    if try_write_user_value(token, (name + host_len) as *mut u8, &zero).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

pub fn syscall_reboot(_magic1: usize, _magic2: usize, _cmd: usize, _arg: usize) -> isize {
    if current_process().borrow_mut().euid != 0 {
        return err(SyscallError::EPERM);
    }
    drain_live_processes_before_shutdown();
    arch::shutdown();
}

fn drain_live_processes_before_shutdown() {
    const SHUTDOWN_DRAIN_TIMEOUT_MS: usize = 10_000;

    // The submit runner calls poweroff immediately after the script prints
    // "ALL TESTS DONE". Background jobs such as hackbench may still be in their
    // signal handler/reap path; give live non-init processes a bounded chance
    // to finish so user-visible output is not truncated by shutdown.
    let start_ms = get_time_ms();
    loop {
        if live_processes_requiring_shutdown_drain() == 0 {
            return;
        }
        if get_time_ms().saturating_sub(start_ms) >= SHUTDOWN_DRAIN_TIMEOUT_MS {
            return;
        }
        crate::task::processor::suspend_current_and_run_next();
    }
}

fn live_processes_requiring_shutdown_drain() -> usize {
    let current_pid = current_process().getpid();
    let map = PID2PCB.lock();
    map.values()
        .filter(|process| {
            let pid = process.getpid();
            // PID 0/1 and the caller itself are part of shutdown machinery, not
            // background test work to drain.
            if pid == 0 || pid == 1 || pid == current_pid {
                return false;
            }
            let Some(inner) = process.try_borrow_mut() else {
                return true;
            };
            !inner.is_zombie
        })
        .count()
}
