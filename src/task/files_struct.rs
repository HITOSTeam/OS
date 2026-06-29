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
    close_cursor: Option<usize>,
    fd_refs_closed: bool,
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
            close_cursor: None,
            fd_refs_closed: false,
        }
    }

    /// fork 时使用：对当前 fd 表做深拷贝，子进程获得独立副本。
    /// Arc 本身是浅拷贝（共享同一 File 对象），但 fd 槽位和 flags 向量是独立的，
    /// 子进程关闭/重定向 fd 不会影响父进程。
    /// 也就是 表独立，而不是底层资源独立
    pub fn clone_private(&self) -> Self {
        let (fd_table, fd_flags) = self.snapshot_fd_state();
        for file in fd_table.iter().flatten() {
            file.on_fd_install();
        }
        let next_fd_hint = self.next_fd_hint.min(fd_table.len());
        Self {
            fd_table,
            fd_flags,
            next_fd_hint,
            close_cursor: None,
            fd_refs_closed: false,
        }
    }

    /// 计算表的有效长度：从尾部跳过所有既无文件又无 flag 的空槽，
    /// 返回最后一个有意义条目之后的位置。用于 trim 和 snapshot。
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

    /// 去掉尾部所有空槽，减少内存占用。每次 clear_fd 后调用。
    fn trim(&mut self) {
        let len = self.effective_len();
        self.fd_table.truncate(len);
        self.fd_flags.truncate(len);
        if self.next_fd_hint > len {
            self.next_fd_hint = len;
        }
    }

    /// 确保 fd_flags 向量长度与 fd_table 对齐。
    /// 两个向量分开增长时可能出现 fd_flags 偏短，访问前需先调用此函数。
    fn ensure_flags_len(&mut self) {
        if self.fd_flags.len() < self.fd_table.len() {
            self.fd_flags.resize(self.fd_table.len(), 0);
        }
    }

    /// 快照当前 fd 表状态，返回 (fd_table 副本, fd_flags 副本)。
    /// 用于 fork（clone_private）以及需要在持锁外遍历 fd 的场景。
    /// Arc::clone 只增加引用计数，不复制底层 File 数据。
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

    /// 返回所有已打开 fd 的 (fd编号, File引用) 列表（快照，不持锁）。
    /// 常用于进程退出时批量关闭、或 /proc/fd 枚举。
    pub fn iter_files_snapshot(&self) -> Vec<(usize, Arc<dyn File + Send + Sync>)> {
        self.fd_table
            .iter()
            .enumerate()
            .filter_map(|(fd, file)| file.as_ref().map(|file| (fd, Arc::clone(file))))
            .collect()
    }

    /// Detach up to `limit` files while tearing down an exited process' file table.
    ///
    /// Linux `close_files()` advances one descriptor at a time and calls
    /// `cond_resched()` after each close.  Keeping a close cursor gives our idle
    /// cleanup path the same shape: make progress on the old descriptor table,
    /// then return to the scheduler before draining the next batch.
    pub fn take_file_close_batch(&mut self, limit: usize) -> Vec<Arc<dyn File + Send + Sync>> {
        let mut files = Vec::new();
        if limit == 0 {
            return files;
        }

        let mut cursor = self.close_cursor.unwrap_or(0);
        while cursor < self.fd_table.len() && files.len() < limit {
            if let Some(file) = self.fd_table[cursor].take() {
                if !self.fd_refs_closed {
                    file.on_fd_close();
                }
                files.push(file);
            }
            if let Some(flag) = self.fd_flags.get_mut(cursor) {
                *flag = 0;
            }
            cursor += 1;
        }

        if cursor >= self.fd_table.len() {
            self.fd_table.clear();
            self.fd_flags.clear();
            self.next_fd_hint = 0;
            self.close_cursor = None;
        } else {
            self.close_cursor = Some(cursor);
        }

        files
    }

    /// Mark all descriptor references as semantically closed without dropping
    /// the underlying file objects yet.  Exit uses this before deferring heavy
    /// object destruction, matching Linux's "close fd table before wait is
    /// visible" semantics for lightweight per-file accounting.
    pub fn close_all_fd_refs(&mut self) {
        if self.fd_refs_closed {
            return;
        }
        for file in self.fd_table.iter().flatten() {
            file.on_fd_close();
        }
        self.fd_refs_closed = true;
    }

    /// 按 fd 编号取出 File 引用；fd 不存在或已关闭返回 None。
    pub fn get_file(&self, fd: usize) -> Option<Arc<dyn File + Send + Sync>> {
        self.fd_table
            .get(fd)
            .and_then(|file| file.as_ref().cloned())
    }

    /// 同时返回 File 引用和该 fd 的描述符 flags（FD_CLOEXEC / O_NONBLOCK 等）。
    /// syscall 层需要 flags 时用此方法，避免两次查表。
    pub fn get_file_and_flags(&self, fd: usize) -> Option<(Arc<dyn File + Send + Sync>, u32)> {
        let file = self.get_file(fd)?;
        Some((file, self.get_flags(fd)))
    }

    /// 判断 fd 是否已打开（表内存在且非 None）。
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

    /// 分配一个空闲 fd 编号（最小可用，符合 POSIX 语义），不安装文件。
    /// 超出 `limit`（nofile 软限制）时返回 None。
    /// 优先复用表中已关闭的槽位；没有空槽时才扩展向量。
    ///
    /// 小优化： 搜索 使用 next_fd 避免重复搜索 已经被占用的fd
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

    /// 分配 fd 并安装文件，原子完成（alloc + 写槽位 + 写 flags）。
    /// 返回分配的 fd 编号；超出 nofile 限制时返回 None。
    pub fn install_fd(
        &mut self,
        file: Arc<dyn File + Send + Sync>,
        flags: u32,
        limit: usize,
    ) -> Option<usize> {
        self.close_cursor = None;
        let fd = self.alloc_fd(limit)?;
        file.on_fd_install();
        self.fd_table[fd] = Some(file);
        self.fd_flags[fd] = flags;
        Some(fd)
    }

    /// 在指定 fd 编号上安装文件（dup2 / F_DUPFD_CLOEXEC 等需要固定编号的场景）。
    /// 若 fd >= limit 返回 false；若该槽已有文件则静默替换（旧 File 的 Arc 引用计数递减）。
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
        self.close_cursor = None;
        if self.fd_table.len() <= fd {
            self.fd_table.resize(fd + 1, None);
            self.fd_flags.resize(fd + 1, 0);
        } else {
            self.ensure_flags_len();
        }
        if let Some(old_file) = self.fd_table[fd].take() {
            if !self.fd_refs_closed {
                old_file.on_fd_close();
            }
        }
        file.on_fd_install();
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

    /// 关闭并移除指定 fd，返回被移除的 File Arc（调用方可按需 drop 或等待引用归零）。
    /// fd 不在范围内返回 None。关闭后调用 trim() 回收尾部空槽。
    pub fn clear_fd(&mut self, fd: usize) -> Option<Arc<dyn File + Send + Sync>> {
        if fd >= self.fd_table.len() {
            return None;
        }
        let file = self.fd_table[fd].take();
        if let Some(file) = file.as_ref() {
            if !self.fd_refs_closed {
                file.on_fd_close();
            }
        }
        self.ensure_flags_len();
        self.fd_flags[fd] = 0;
        self.close_cursor = None;
        if file.is_some() {
            self.next_fd_hint = self.next_fd_hint.min(fd);
        }
        self.trim();
        file
    }

    /// 读取 fd 的描述符 flags（FD_CLOEXEC / O_NONBLOCK 等）；fd 不存在返回 0。
    pub fn get_flags(&self, fd: usize) -> u32 {
        self.fd_flags.get(fd).copied().unwrap_or(0)
    }

    /// 设置 fd 的描述符 flags（fcntl F_SETFD）；fd 未打开返回 false。
    pub fn set_flags(&mut self, fd: usize, flags: u32) -> bool {
        if !self.is_fd_open(fd) {
            return false;
        }
        self.ensure_flags_len();
        self.fd_flags[fd] = flags;
        true
    }

    /// exec 时关闭所有带 FD_CLOEXEC 标志的 fd（POSIX exec 语义）。
    /// 一次遍历完成关闭和清 flag，最后 trim() 回收尾部空槽。
    pub fn close_cloexec_fds(&mut self) {
        self.ensure_flags_len();
        for (idx, flags) in self.fd_flags.iter_mut().enumerate() {
            if (*flags & FD_CLOEXEC) != 0 {
                // fd flags and file slots are disjoint fields; closing and
                // clearing the CLOEXEC bit in one pass keeps exec cleanup simple.
                if let Some(file) = self.fd_table[idx].take() {
                    if !self.fd_refs_closed {
                        file.on_fd_close();
                    }
                }
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
            close_cursor: None,
            fd_refs_closed: false,
        }
    }
}

impl Drop for FilesStruct {
    fn drop(&mut self) {
        self.close_all_fd_refs();
    }
}
