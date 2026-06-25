use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::any::Any;
use spin::Mutex;

use crate::{
    config::PAGE_SIZE,
    fs::File,
    mm::UserBuffer,
    syscall::error::SyscallError::{E2BIG, EACCES, EEXIST, EINVAL, ENOENT, EOPNOTSUPP},
};

use super::{
    BpfResult,
    uapi::{BPF_ANY, BPF_EXIST, BPF_NOEXIST},
};

/// BPF map 的内部类型，决定键值存储语义。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BpfMapKind {
    Hash,    // 任意键哈希表，键值均为定长字节数组
    Array,   // 以 u32 下标为键的定长数组，创建时预填充零值
    RingBuf, // 环形缓冲区（当前仅允许创建，不支持元素读写）
}

/// BPF map 的可变内部状态，由 Mutex 保护以支持并发访问。
struct BpfMapInner {
    storage: BpfMapStorage,
}

enum BpfMapStorage {
    /// Hash map：任意定长字节 key 到定长字节 value。
    Hash(BTreeMap<Vec<u8>, Vec<u8>>),
    /// Array map：Linux 要求 key_size == 4，key 是 little-endian u32 index。
    Array(Vec<Vec<u8>>),
    /// Ring buffer map：普通 lookup/update 不支持，后续应由 ringbuf helpers 操作。
    RingBuf,
}

/// BPF map 文件对象，实现 `File` trait 以复用内核文件描述符机制。
pub(super) struct BpfMapFile {
    pub(super) key_size: u32,
    pub(super) value_size: u32,
    max_entries: u32,
    inner: Mutex<BpfMapInner>,
}

impl BpfMapFile {
    /// 创建新的 BPF map。Array 类型会预填充 `max_entries` 个零值条目。
    pub(super) fn new(
        kind: BpfMapKind,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    ) -> BpfResult<Self> {
        if max_entries == 0 {
            return Err(EINVAL);
        }
        let storage = match kind {
            BpfMapKind::Hash => {
                if key_size == 0 || value_size == 0 {
                    return Err(EINVAL);
                }
                BpfMapStorage::Hash(BTreeMap::new())
            }
            BpfMapKind::Array => {
                if key_size != 4 || value_size == 0 {
                    return Err(EINVAL);
                }
                let mut values = Vec::with_capacity(max_entries as usize);
                for _ in 0..max_entries {
                    values.push(vec![0u8; value_size as usize]);
                }
                BpfMapStorage::Array(values)
            }
            BpfMapKind::RingBuf => {
                if key_size != 0
                    || value_size != 0
                    || !max_entries.is_power_of_two()
                    || (max_entries as usize % PAGE_SIZE) != 0
                {
                    return Err(EINVAL);
                }
                BpfMapStorage::RingBuf
            }
        };
        Ok(Self {
            key_size,
            value_size,
            max_entries,
            inner: Mutex::new(BpfMapInner { storage }),
        })
    }

    /// 检查 key 长度是否与 map 声明的 key_size 一致。
    fn validate_key(&self, key: &[u8]) -> bool {
        key.len() == self.key_size as usize
    }

    fn array_index(&self, key: &[u8]) -> BpfResult<usize> {
        if key.len() != 4 {
            return Err(EINVAL);
        }
        let index = u32::from_le_bytes([key[0], key[1], key[2], key[3]]) as usize;
        Ok(index)
    }

    /// 查找 key 对应的 value，返回其克隆；不存在或越界返回 None。
    pub(super) fn lookup(&self, key: &[u8]) -> BpfResult<Option<Vec<u8>>> {
        let inner = self.inner.lock();
        match &inner.storage {
            BpfMapStorage::Hash(entries) => {
                if !self.validate_key(key) {
                    return Ok(None);
                }
                Ok(entries.get(key).cloned())
            }
            BpfMapStorage::Array(values) => {
                let index = self.array_index(key)?;
                Ok(values.get(index).cloned())
            }
            // TODO
            BpfMapStorage::RingBuf => Err(EOPNOTSUPP),
        }
    }

    /// 按 `flags` 语义（ANY/NOEXIST/EXIST）更新或插入条目。
    pub(super) fn update(&self, key: &[u8], value: &[u8], flags: u64) -> BpfResult<()> {
        if !self.validate_key(key) || value.len() != self.value_size as usize {
            return Err(EINVAL);
        }
        let mut inner = self.inner.lock();
        match &mut inner.storage {
            BpfMapStorage::Hash(entries) => {
                let exists = entries.contains_key(key);
                match flags {
                    BPF_ANY => {}
                    BPF_NOEXIST if exists => return Err(EEXIST),
                    BPF_NOEXIST => {}
                    BPF_EXIST if !exists => return Err(ENOENT),
                    BPF_EXIST => {}
                    _ => return Err(EINVAL),
                }
                if !exists && entries.len() >= self.max_entries as usize {
                    return Err(E2BIG);
                }
                entries.insert(key.to_vec(), value.to_vec());
                Ok(())
            }
            BpfMapStorage::Array(values) => {
                let index = self.array_index(key)?;
                if flags != BPF_ANY && flags != BPF_NOEXIST && flags != BPF_EXIST {
                    return Err(EINVAL);
                }
                if index >= self.max_entries as usize {
                    return Err(E2BIG);
                }
                if flags == BPF_NOEXIST {
                    return Err(EEXIST);
                }
                values[index].copy_from_slice(value);
                Ok(())
            }
            BpfMapStorage::RingBuf => Err(EOPNOTSUPP),
        }
    }

    /// 向已有条目的 value 中写入原始字节（BPF 程序内部使用）。
    pub(super) fn store_bytes(&self, key: &[u8], offset: usize, data: &[u8]) -> BpfResult<()> {
        let mut inner = self.inner.lock();
        let value = match &mut inner.storage {
            BpfMapStorage::Hash(entries) => {
                if !self.validate_key(key) {
                    return Err(EINVAL);
                }
                entries.get_mut(key).ok_or(ENOENT)?
            }
            BpfMapStorage::Array(values) => {
                let index = self.array_index(key)?;
                values.get_mut(index).ok_or(ENOENT)?
            }
            BpfMapStorage::RingBuf => return Err(EOPNOTSUPP),
        };
        let end = offset.checked_add(data.len()).ok_or(EINVAL)?;
        if end > value.len() {
            return Err(EACCES);
        }
        value[offset..end].copy_from_slice(data);
        Ok(())
    }
}

// BpfMapFile 不支持普通文件读写；通过专用 bpf() 系统调用操作。
impl File for BpfMapFile {
    fn readable(&self) -> bool {
        false
    }
    fn writable(&self) -> bool {
        false
    }
    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }
    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
