use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::fs::{File, Stdin, Stdout};

const FD_CLOEXEC: u32 = 1;

/// Linux-style per-process file table.
///
/// `FilesStruct` is intentionally independent of `ProcessControlBlockInner`:
/// regular fork snapshots it into a private table, while `clone(CLONE_FILES)`
/// shares the same `Arc<SpinMutex<FilesStruct>>`.  Resource limits stay in the
/// PCB because they are process attributes rather than file-table state.
pub struct FilesStruct {
    fd_table: Vec<Option<Arc<dyn File + Send + Sync>>>,
    fd_flags: Vec<u32>,
    next_fd_hint: usize,
}

impl FilesStruct {
    /// Create an empty file table.  Used when an exiting process drops its table
    /// without mutating a table that may still be shared by CLONE_FILES users.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create the initial table with standard input/output/error installed.
    pub fn with_stdio() -> Self {
        Self {
            fd_table: vec![
                Some(Arc::new(Stdin)),
                Some(Arc::new(Stdout)),
                Some(Arc::new(Stdout)),
            ],
            fd_flags: vec![0; 3],
            next_fd_hint: 3,
        }
    }

    pub fn clone_private(&self) -> Self {
        let (fd_table, fd_flags) = self.snapshot_fd_state();
        let next_fd_hint = self.next_fd_hint.min(fd_table.len());
        Self {
            fd_table,
            fd_flags,
            next_fd_hint,
        }
    }

    fn effective_len(&self) -> usize {
        let mut len = self.fd_table.len();
        while len > 0 {
            let idx = len - 1;
            let has_file = self.fd_table[idx].is_some();
            let has_flag = self.fd_flags.get(idx).copied().unwrap_or(0) != 0;
            if has_file || has_flag {
                break;
            }
            len -= 1;
        }
        len
    }

    fn trim(&mut self) {
        let len = self.effective_len();
        self.fd_table.truncate(len);
        self.fd_flags.truncate(len);
        if self.next_fd_hint > len {
            self.next_fd_hint = len;
        }
    }

    fn ensure_flags_len(&mut self) {
        if self.fd_flags.len() < self.fd_table.len() {
            self.fd_flags.resize(self.fd_table.len(), 0);
        }
    }

    pub fn snapshot_fd_state(&self) -> (Vec<Option<Arc<dyn File + Send + Sync>>>, Vec<u32>) {
        let len = self.effective_len();
        let fd_table = self
            .fd_table
            .iter()
            .take(len)
            .map(|fd| fd.as_ref().map(Arc::clone))
            .collect::<Vec<_>>();
        let mut fd_flags = self.fd_flags.iter().take(len).copied().collect::<Vec<_>>();
        if fd_flags.len() < fd_table.len() {
            fd_flags.resize(fd_table.len(), 0);
        }
        (fd_table, fd_flags)
    }

    pub fn iter_files_snapshot(&self) -> Vec<(usize, Arc<dyn File + Send + Sync>)> {
        self.fd_table
            .iter()
            .enumerate()
            .filter_map(|(fd, file)| file.as_ref().map(|file| (fd, Arc::clone(file))))
            .collect()
    }

    pub fn get_file(&self, fd: usize) -> Option<Arc<dyn File + Send + Sync>> {
        self.fd_table
            .get(fd)
            .and_then(|file| file.as_ref().cloned())
    }

    pub fn get_file_and_flags(&self, fd: usize) -> Option<(Arc<dyn File + Send + Sync>, u32)> {
        let file = self.get_file(fd)?;
        Some((file, self.get_flags(fd)))
    }

    pub fn is_fd_open(&self, fd: usize) -> bool {
        self.fd_table.get(fd).is_some_and(Option::is_some)
    }

    /// Return the allocated descriptor table length, including trailing empty
    /// slots that have not yet been trimmed.
    pub fn len(&self) -> usize {
        self.fd_table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fd_table.is_empty()
    }

    pub fn alloc_fd(&mut self, limit: usize) -> Option<usize> {
        let start = self.next_fd_hint.min(self.fd_table.len());
        if let Some(fd) = (start..self.fd_table.len()).find(|fd| self.fd_table[*fd].is_none()) {
            if fd >= limit {
                return None;
            }
            self.ensure_flags_len();
            self.fd_flags[fd] = 0;
            self.next_fd_hint = fd + 1;
            Some(fd)
        } else {
            if self.fd_table.len() >= limit {
                return None;
            }
            self.fd_table.push(None);
            self.fd_flags.push(0);
            let fd = self.fd_table.len() - 1;
            self.next_fd_hint = fd + 1;
            Some(fd)
        }
    }

    pub fn install_fd(
        &mut self,
        file: Arc<dyn File + Send + Sync>,
        flags: u32,
        limit: usize,
    ) -> Option<usize> {
        let fd = self.alloc_fd(limit)?;
        self.fd_table[fd] = Some(file);
        self.fd_flags[fd] = flags;
        Some(fd)
    }

    pub fn install_fd_at(
        &mut self,
        fd: usize,
        file: Arc<dyn File + Send + Sync>,
        flags: u32,
        limit: usize,
    ) -> bool {
        if fd >= limit {
            return false;
        }
        if self.fd_table.len() <= fd {
            self.fd_table.resize(fd + 1, None);
            self.fd_flags.resize(fd + 1, 0);
        } else {
            self.ensure_flags_len();
        }
        self.fd_table[fd] = Some(file);
        self.fd_flags[fd] = flags;
        if fd == self.next_fd_hint {
            while self
                .fd_table
                .get(self.next_fd_hint)
                .is_some_and(Option::is_some)
            {
                self.next_fd_hint += 1;
            }
        }
        true
    }

    pub fn clear_fd(&mut self, fd: usize) -> Option<Arc<dyn File + Send + Sync>> {
        if fd >= self.fd_table.len() {
            return None;
        }
        let file = self.fd_table[fd].take();
        self.ensure_flags_len();
        self.fd_flags[fd] = 0;
        if file.is_some() {
            self.next_fd_hint = self.next_fd_hint.min(fd);
        }
        self.trim();
        file
    }

    pub fn get_flags(&self, fd: usize) -> u32 {
        self.fd_flags.get(fd).copied().unwrap_or(0)
    }

    pub fn set_flags(&mut self, fd: usize, flags: u32) -> bool {
        if !self.is_fd_open(fd) {
            return false;
        }
        self.ensure_flags_len();
        self.fd_flags[fd] = flags;
        true
    }

    pub fn close_cloexec_fds(&mut self) {
        self.ensure_flags_len();
        for (idx, flags) in self.fd_flags.iter_mut().enumerate() {
            if (*flags & FD_CLOEXEC) != 0 {
                // fd flags and file slots are disjoint fields; closing and
                // clearing the CLOEXEC bit in one pass keeps exec cleanup simple.
                self.fd_table[idx] = None;
                *flags = 0;
                self.next_fd_hint = self.next_fd_hint.min(idx);
            }
        }
        self.trim();
    }
}

impl Default for FilesStruct {
    fn default() -> Self {
        Self {
            fd_table: Vec::new(),
            fd_flags: Vec::new(),
            next_fd_hint: 0,
        }
    }
}
