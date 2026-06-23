use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::any::Any;

use crate::{
    fs::File,
    mm::UserBuffer,
    syscall::error::SyscallError::{EACCES, EBADF, EINVAL, ENOENT},
};

use super::{BpfResult, map::BpfMapFile, runtime, uapi::BpfInsn};

/// BPF 程序文件对象，持有已验证的指令序列及其引用的所有 map。
#[derive(Clone)]
pub struct BpfProgFile {
    pub(super) insns: Vec<BpfInsn>,
    /// 程序中 ldimm64 伪指令引用的 map fd → File 映射
    pub(super) maps: BTreeMap<u32, Arc<dyn File + Send + Sync>>,
}

impl BpfProgFile {
    pub(super) fn new(
        insns: Vec<BpfInsn>,
        maps: BTreeMap<u32, Arc<dyn File + Send + Sync>>,
    ) -> Self {
        Self { insns, maps }
    }

    /// 对 `packet` 运行 socket filter 程序，返回应保留的字节数。
    /// 返回 None 表示丢包，Some(n) 表示保留前 n 字节。
    pub fn filter_len(&self, packet: &[u8]) -> Option<usize> {
        let len = runtime::execute(self, packet).ok()? as usize;
        (len != 0).then_some(len.min(packet.len()))
    }

    /// 通过 fd 找到对应的 BpfMapFile 并执行闭包，fd 无效或类型不匹配则返回 None。
    pub(super) fn with_map<R>(&self, fd: u32, f: impl FnOnce(&BpfMapFile) -> R) -> Option<R> {
        let file = self.maps.get(&fd)?;
        let map = file.as_any().downcast_ref::<BpfMapFile>()?;
        Some(f(map))
    }

    /// 返回指定 map 的 key_size（字节数），用于从栈上读取 key。
    pub(super) fn map_key_size(&self, fd: u32) -> BpfResult<usize> {
        self.with_map(fd, |map| map.key_size as usize).ok_or(EBADF)
    }

    /// 查找 map 中 key 对应的 value，返回克隆；不存在返回 None。
    pub(super) fn map_lookup_bytes(&self, fd: u32, key: &[u8]) -> BpfResult<Option<Vec<u8>>> {
        self.with_map(fd, |map| map.lookup(key)).ok_or(EBADF)?
    }

    /// 从 map value 中读取 [offset, offset+len) 范围的字节。
    pub(super) fn map_load_bytes(
        &self,
        fd: u32,
        key: &[u8],
        offset: usize,
        len: usize,
    ) -> BpfResult<Vec<u8>> {
        let value = self.map_lookup_bytes(fd, key)?.ok_or(ENOENT)?;
        let end = offset.checked_add(len).ok_or(EINVAL)?;
        if end > value.len() {
            return Err(EACCES);
        }
        Ok(value[offset..end].to_vec())
    }

    /// 向 map value 的 [offset, offset+data.len()) 范围写入字节。
    pub(super) fn map_store_bytes(
        &self,
        fd: u32,
        key: &[u8],
        offset: usize,
        data: &[u8],
    ) -> BpfResult<()> {
        self.with_map(fd, |map| map.store_bytes(key, offset, data))
            .ok_or(EBADF)?
    }
}

impl File for BpfProgFile {
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
