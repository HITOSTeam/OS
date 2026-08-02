//! devtmpfs filesystem view.
//!
//! This is a concrete filesystem backend.  [`vfs`] exposes component-based
//! nodes and pinned device opens; `open_legacy` remains the driver-facing
//! object constructor while pathname users migrate to the common VFS.

pub(crate) mod vfs;

extern crate alloc;

use alloc::{string::String, sync::Arc};

use super::{File, pseudo, tty};

/// Open a devtmpfs object through the transitional path-based provider.
pub(super) fn open_legacy(path: &str) -> Option<Arc<dyn File + Send + Sync>> {
    if path == "/dev" || path == "/dev/" {
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
            pseudo::PseudoDirent {
                name: String::from("root"),
                ino: 6,
                dtype: 6,
            },
            pseudo::PseudoDirent {
                name: String::from("vda"),
                ino: 7,
                dtype: 6,
            },
            pseudo::PseudoDirent {
                name: String::from("vdb"),
                ino: 8,
                dtype: 6,
            },
            pseudo::PseudoDirent {
                name: String::from("vdc"),
                ino: 12,
                dtype: 6,
            },
            pseudo::PseudoDirent {
                name: String::from("ptmx"),
                ino: 9,
                dtype: 2,
            },
            pseudo::PseudoDirent {
                name: String::from("tty"),
                ino: 10,
                dtype: 2,
            },
            pseudo::PseudoDirent {
                name: String::from("pts"),
                ino: 11,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("shm"),
                ino: 8,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("cgroup"),
                ino: 12,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("null"),
                ino: 2,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("zero"),
                ino: 3,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("urandom"),
                ino: 4,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("random"),
                ino: 5,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("misc"),
                ino: 7,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("net"),
                ino: 13,
                dtype: 4,
            },
        ];
        entries.extend(pseudo::pseudo_dev_dir_entries());
        return Some(Arc::new(pseudo::PseudoDir::new("/dev", entries)));
    }
    if path == "/dev/net" || path == "/dev/net/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 13,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("tun"),
                ino: 14,
                dtype: 2,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/dev/net", entries)));
    }
    if path == "/dev/cgroup" || path == "/dev/cgroup/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 12,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/dev/cgroup", entries)));
    }
    if path == "/dev/pts" || path == "/dev/pts/" {
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
        for idx in tty::list_dev_pts() {
            entries.push(pseudo::PseudoDirent {
                name: alloc::format!("{}", idx),
                ino: 2000 + idx as u64,
                dtype: 2,
            });
        }
        return Some(Arc::new(pseudo::PseudoDir::new("/dev/pts", entries)));
    }
    if let Some(rest) = path.strip_prefix("/dev/pts/") {
        if !rest.is_empty() && !rest.contains('/') && rest.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(idx) = rest.parse::<u32>() {
                if let Some(node) = tty::open_dev_pts(idx) {
                    return Some(node);
                }
            }
        }
    }
    if path == "/dev/shm" || path == "/dev/shm/" {
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
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/dev/shm", entries)));
    }
    if path == "/dev/misc" || path == "/dev/misc/" {
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
                name: String::from("rtc"),
                ino: 2,
                dtype: 8,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/dev/misc", entries)));
    }
    if path == "/dev/ptmx" {
        return Some(tty::open_dev_ptmx());
    }
    if path == "/dev/tty" {
        return Some(tty::open_dev_tty());
    }
    if matches!(path, "/dev/root" | "/dev/vda" | "/dev/vdb" | "/dev/vdc") {
        return Some(Arc::new(pseudo::PseudoBlock::new()));
    }
    if path == "/dev/null" {
        return Some(Arc::new(pseudo::PseudoFile::new_null()));
    }
    if path == "/dev/zero" {
        return Some(Arc::new(pseudo::PseudoFile::new_zero()));
    }
    if path == "/dev/urandom" || path == "/dev/random" {
        let seed =
            (crate::time::get_time() as u64) ^ ((crate::task::processor::hart_id() as u64) << 32);
        return Some(Arc::new(pseudo::PseudoFile::new_urandom(seed)));
    }
    if path == "/dev/misc/rtc" {
        return Some(Arc::new(pseudo::RtcFile::new()));
    }
    if path == "/dev/net/tun" {
        return Some(Arc::new(pseudo::TunTapFile::new()));
    }
    if let Some(node) = pseudo::open_pseudo_dev_dir(path) {
        return Some(node);
    }
    None
}
