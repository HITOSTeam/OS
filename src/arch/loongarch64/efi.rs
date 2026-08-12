//! LoongArch EFI 启动参数解析。
//!
//! 启动协议通过 `a2` 传入 EFI system table 的物理地址。分页前 DMW0 提供
//! 物理地址恒等映射，因此可以从 configuration table 找到 DTB 的真实地址。

const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249;
const EFI_DEVICE_TREE_GUID: [u8; 16] = [
    0xd5, 0x21, 0xb6, 0xb1, 0x9c, 0xf1, 0xa5, 0x41, 0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0,
];

#[repr(C)]
struct EfiTableHeader {
    signature: u64,
    _revision: u32,
    _header_size: u32,
    _crc32: u32,
    _reserved: u32,
}

#[repr(C)]
struct EfiConfigurationTable {
    vendor_guid: [u8; 16],
    vendor_table: usize,
}

#[repr(C)]
struct EfiSystemTable {
    header: EfiTableHeader,
    _firmware_vendor: usize,
    _firmware_revision: u32,
    _firmware_revision_padding: u32,
    _console_in_handle: usize,
    _console_in: usize,
    _console_out_handle: usize,
    _console_out: usize,
    _stderr_handle: usize,
    _stderr: usize,
    _runtime_services: usize,
    _boot_services: usize,
    number_of_table_entries: usize,
    configuration_table: *const EfiConfigurationTable,
}

/// 从 LoongArch EFI system table 的 configuration table 中查找 DTB 物理地址。
pub fn dtb_address(efi_system_table_pa: usize) -> Option<usize> {
    if efi_system_table_pa == 0 {
        return None;
    }
    // SAFETY: 启动协议保证 a2 指向可访问的 EFI system table；调用方仅在
    // 分页初始化前调用，DMW0 仍映射启动期物理地址。
    let system_table = unsafe { &*(efi_system_table_pa as *const EfiSystemTable) };
    if system_table.header.signature != EFI_SYSTEM_TABLE_SIGNATURE
        || system_table.configuration_table.is_null()
    {
        return None;
    }
    for index in 0..system_table.number_of_table_entries {
        // SAFETY: configuration_table 指向启动协议提供的连续表项数组。
        let entry = unsafe { &*system_table.configuration_table.add(index) };
        if entry.vendor_guid == EFI_DEVICE_TREE_GUID && entry.vendor_table != 0 {
            return Some(entry.vendor_table);
        }
    }
    None
}
