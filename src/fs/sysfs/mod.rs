//! sysfs filesystem view.
//!
//! This is a concrete filesystem backend, not part of the VFS object model.
//! The current implementation is the compatibility provider used by the
//! legacy pathname dispatcher.  New work should expose these entries through
//! `VfsFileSystem` and `VfsNode` instead of adding path translations here.

extern crate alloc;

use alloc::{string::String, sync::Arc};
use core::fmt::Write;

use super::{File, pseudo};

fn cpu_list_from_mask(mask: usize) -> String {
    let mut out = String::new();
    let mask = if mask == 0 { 1 } else { mask };
    let mut first = true;
    let mut cpu = 0;
    while cpu < usize::BITS as usize {
        if (mask & (1usize << cpu)) == 0 {
            cpu += 1;
            continue;
        }
        let start = cpu;
        while cpu + 1 < usize::BITS as usize && (mask & (1usize << (cpu + 1))) != 0 {
            cpu += 1;
        }
        if !first {
            out.push(',');
        }
        first = false;
        if start == cpu {
            let _ = write!(out, "{}", start);
        } else {
            let _ = write!(out, "{}-{}", start, cpu);
        }
        cpu += 1;
    }
    out.push('\n');
    out
}

/// Open a sysfs object through the transitional path-based provider.
pub(super) fn open_legacy(path: &str) -> Option<Arc<dyn File + Send + Sync>> {
    if path == "/sys" || path == "/sys/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("devices"),
                ino: 2,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("block"),
                ino: 3,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("dev"),
                ino: 4,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("class"),
                ino: 5,
                dtype: 4,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/sys", entries)));
    }
    if path == "/sys/class" || path == "/sys/class/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("net"),
                ino: 2,
                dtype: 4,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/sys/class", entries)));
    }
    if path == "/sys/class/net" || path == "/sys/class/net/" {
        let mut entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
        ];
        for (idx, (name, dtype)) in crate::syscall::net::netdev::sys_class_net_entries()
            .into_iter()
            .enumerate()
        {
            entries.push(pseudo::PseudoDirent {
                name,
                ino: (10 + idx) as u64,
                dtype,
            });
        }
        return Some(Arc::new(pseudo::PseudoDir::new("/sys/class/net", entries)));
    }
    if let Some(rest) = path.strip_prefix("/sys/class/net/") {
        let trimmed = rest.trim_end_matches('/');
        if !trimmed.is_empty() && !trimmed.contains('/') {
            if crate::syscall::net::netdev::device_snapshot_by_name(trimmed).is_some() {
                let mut entries = alloc::vec![
                    pseudo::PseudoDirent {
                        name: String::from("."),
                        ino: 1,
                        dtype: 4,
                    },
                    pseudo::PseudoDirent {
                        name: String::from(".."),
                        ino: 1,
                        dtype: 4,
                    },
                ];
                for (idx, (name, dtype)) in
                    crate::syscall::net::netdev::sys_class_net_device_entries(trimmed)
                        .into_iter()
                        .enumerate()
                {
                    entries.push(pseudo::PseudoDirent {
                        name: String::from(name),
                        ino: (20 + idx) as u64,
                        dtype,
                    });
                }
                return Some(Arc::new(pseudo::PseudoDir::new(path, entries)));
            }
        }
        if let Some(content) = crate::syscall::net::netdev::sys_class_net_file_content(path) {
            return Some(Arc::new(pseudo::PseudoFile::new_static(&content)));
        }
    }
    if path == "/sys/block" || path == "/sys/block/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("root"),
                ino: 2,
                dtype: 4,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/sys/block", entries)));
    }
    if path == "/sys/block/root" || path == "/sys/block/root/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("queue"),
                ino: 2,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("size"),
                ino: 3,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("stat"),
                ino: 4,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("dev"),
                ino: 5,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("removable"),
                ino: 6,
                dtype: 8,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/sys/block/root", entries)));
    }
    if path == "/sys/block/root/queue" || path == "/sys/block/root/queue/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("logical_block_size"),
                ino: 2,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("physical_block_size"),
                ino: 3,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("minimum_io_size"),
                ino: 4,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("optimal_io_size"),
                ino: 5,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("dma_alignment"),
                ino: 6,
                dtype: 8,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new(
            "/sys/block/root/queue",
            entries,
        )));
    }
    if path == "/sys/block/root/size" {
        return Some(Arc::new(pseudo::PseudoFile::new_static("2097152\n")));
    }
    if path == "/sys/block/root/stat" {
        let stat = pseudo::pseudo_block_stat_snapshot();
        return Some(Arc::new(pseudo::PseudoFile::new_static(&stat)));
    }
    if path == "/sys/block/root/dev" {
        return Some(Arc::new(pseudo::PseudoFile::new_static("1:0\n")));
    }
    if path == "/sys/block/root/removable" {
        return Some(Arc::new(pseudo::PseudoFile::new_static("0\n")));
    }
    if path == "/sys/block/root/queue/logical_block_size" {
        return Some(Arc::new(pseudo::PseudoFile::new_static("512\n")));
    }
    if path == "/sys/block/root/queue/physical_block_size" {
        return Some(Arc::new(pseudo::PseudoFile::new_static("4096\n")));
    }
    if path == "/sys/block/root/queue/minimum_io_size" {
        return Some(Arc::new(pseudo::PseudoFile::new_static("512\n")));
    }
    if path == "/sys/block/root/queue/optimal_io_size" {
        return Some(Arc::new(pseudo::PseudoFile::new_static("0\n")));
    }
    if path == "/sys/block/root/queue/dma_alignment" {
        return Some(Arc::new(pseudo::PseudoFile::new_static("0\n")));
    }
    if path == "/sys/dev" || path == "/sys/dev/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("block"),
                ino: 2,
                dtype: 4,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/sys/dev", entries)));
    }
    if path == "/sys/dev/block" || path == "/sys/dev/block/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("1:0"),
                ino: 2,
                dtype: 4,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/sys/dev/block", entries)));
    }
    if path == "/sys/dev/block/1:0" || path == "/sys/dev/block/1:0/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("uevent"),
                ino: 2,
                dtype: 8,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new(
            "/sys/dev/block/1:0",
            entries,
        )));
    }
    if path == "/sys/dev/block/1:0/uevent" {
        return Some(Arc::new(pseudo::PseudoFile::new_static(
            "MAJOR=1\nMINOR=0\nDEVNAME=root\nDEVTYPE=disk\n",
        )));
    }
    if path == "/sys/devices/system/cpu/possible"
        || path == "/sys/devices/system/cpu/present"
        || path == "/sys/devices/system/cpu/online"
    {
        let s = cpu_list_from_mask(crate::task::manager::online_hart_mask());
        return Some(Arc::new(pseudo::PseudoFile::new_static(&s)));
    }
    if path == "/sys/devices/system/cpu/kernel_max" {
        let n = crate::config::MAX_HARTS;
        let s = if n == 0 {
            String::from("0\n")
        } else {
            alloc::format!("{}\n", n - 1)
        };
        return Some(Arc::new(pseudo::PseudoFile::new_static(&s)));
    }
    if path == "/sys/devices/system/node/online" || path == "/sys/devices/system/node/possible" {
        return Some(Arc::new(pseudo::PseudoFile::new_static("0\n")));
    }
    None
}
