make[1]: Entering directory '/mnt/OS_Workspace/os'
warning: `/root/.cargo/config` is deprecated in favor of `config.toml`
note: if you need to support cargo 1.38 or earlier, you can symlink `config` to `config.toml`
warning: profiles for the non root package will be ignored, specify profiles at the workspace root:
package:   /mnt/OS_Workspace/os/Cargo.toml
workspace: /mnt/OS_Workspace/Cargo.toml
warning: profiles for the non root package will be ignored, specify profiles at the workspace root:
package:   /mnt/OS_Workspace/vendor/smoltcp/Cargo.toml
workspace: /mnt/OS_Workspace/Cargo.toml
warning: profiles for the non root package will be ignored, specify profiles at the workspace root:
package:   /mnt/OS_Workspace/easy-fs/Cargo.toml
workspace: /mnt/OS_Workspace/Cargo.toml
warning: virtual workspace defaulting to `resolver = "1"` despite one or more workspace members being on edition 2024 which implies `resolver = "3"`
note: to keep the current resolver, specify `workspace.resolver = "1"` in the workspace root's manifest
note: to use the edition 2024 resolver, specify `workspace.resolver = "3"` in the workspace root's manifest
note: for more details see https://doc.rust-lang.org/cargo/reference/resolver.html#resolver-versions
warning: unnecessary parentheses around `match` scrutinee expression
  --> user/src/syscall/thread.rs:29:15
   |
29 |         match (sys_waittid(tid)) {
   |               ^                ^
   |
   = note: `#[warn(unused_parens)]` on by default
help: remove these parentheses
   |
29 -         match (sys_waittid(tid)) {
29 +         match sys_waittid(tid) {
   |

warning: unused variable: `argc`
  --> user/src/lib.rs:57:26
   |
57 | pub extern "C" fn _start(argc: usize, argv: usize) {
   |                          ^^^^ help: if this is intentional, prefix it with an underscore: `_argc`
   |
   = note: `#[warn(unused_variables)]` on by default

warning: constant `STDIN` is never used
 --> user/src/console/mod.rs:4:7
  |
4 | const STDIN: usize = 0;
  |       ^^^^^
  |
  = note: `#[warn(dead_code)]` on by default

warning: constant `STDOUT` is never used
 --> user/src/console/mod.rs:5:7
  |
5 | const STDOUT: usize = 1;
  |       ^^^^^^

warning: constant `SYSCALL_FORK` is never used
  --> user/src/syscall/mod.rs:11:7
   |
11 | const SYSCALL_FORK: usize = 220;
   |       ^^^^^^^^^^^^

warning: constant `SYSCALL_MUTEX_CREATE` is never used
 --> user/src/syscall/thread.rs:8:7
  |
8 | const SYSCALL_MUTEX_CREATE: usize = 1010;
  |       ^^^^^^^^^^^^^^^^^^^^

warning: constant `SYSCALL_MUTEX_LOCK` is never used
 --> user/src/syscall/thread.rs:9:7
  |
9 | const SYSCALL_MUTEX_LOCK: usize = 1011;
  |       ^^^^^^^^^^^^^^^^^^

warning: constant `SYSCALL_MUTEX_UNLOCK` is never used
  --> user/src/syscall/thread.rs:10:7
   |
10 | const SYSCALL_MUTEX_UNLOCK: usize = 1012;
   |       ^^^^^^^^^^^^^^^^^^^^

warning: constant `SYSCALL_SEMAPHORE_CREATE` is never used
  --> user/src/syscall/thread.rs:11:7
   |
11 | const SYSCALL_SEMAPHORE_CREATE: usize = 1020;
   |       ^^^^^^^^^^^^^^^^^^^^^^^^

warning: constant `SYSCALL_SEMAPHORE_UP` is never used
  --> user/src/syscall/thread.rs:12:7
   |
12 | const SYSCALL_SEMAPHORE_UP: usize = 1021;
   |       ^^^^^^^^^^^^^^^^^^^^

warning: constant `SYSCALL_SEMAPHORE_DOWN` is never used
  --> user/src/syscall/thread.rs:13:7
   |
13 | const SYSCALL_SEMAPHORE_DOWN: usize = 1022;
   |       ^^^^^^^^^^^^^^^^^^^^^^

warning: constant `SYSCALL_CONDVAR_CREATE` is never used
  --> user/src/syscall/thread.rs:14:7
   |
14 | const SYSCALL_CONDVAR_CREATE: usize = 1030;
   |       ^^^^^^^^^^^^^^^^^^^^^^

warning: constant `SYSCALL_CONDVAR_SIGNAL` is never used
  --> user/src/syscall/thread.rs:15:7
   |
15 | const SYSCALL_CONDVAR_SIGNAL: usize = 1031;
   |       ^^^^^^^^^^^^^^^^^^^^^^

warning: constant `SYSCALL_CONDVAR_WAIT` is never used
  --> user/src/syscall/thread.rs:16:7
   |
16 | const SYSCALL_CONDVAR_WAIT: usize = 1032;
   |       ^^^^^^^^^^^^^^^^^^^^

warning: `user` (lib) generated 14 warnings (run `cargo fix --lib -p user` to apply 1 suggestion)
warning: unused imports: `run_non_riscv_ltp_groups_in_dir` and `run_riscv_ltp_groups_in_dir`
 --> user/src/bin/ltp_dependence/mod.rs:6:23
  |
6 | pub use submit_plan::{run_non_riscv_ltp_groups_in_dir, run_riscv_ltp_groups_in_dir};
  |                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` on by default

warning: constant `FOCUS_READINESS_SMOKES` is never used
  --> user/src/bin/submit_script.rs:46:7
   |
46 | const FOCUS_READINESS_SMOKES: bool = false;
   |       ^^^^^^^^^^^^^^^^^^^^^^
   |
   = note: `#[warn(dead_code)]` on by default

warning: constant `READINESS_SMOKES` is never used
  --> user/src/bin/submit_script.rs:48:7
   |
48 | const READINESS_SMOKES: [&str; 14] = [
   |       ^^^^^^^^^^^^^^^^

warning: constant `RISCV_LTP_GROUPS` is never used
 --> user/src/bin/ltp_dependence/submit_plan.rs:7:7
  |
7 | const RISCV_LTP_GROUPS: &[LtpGroup] = &[
  |       ^^^^^^^^^^^^^^^^

warning: constant `RISCV_LTP_GLIBC_ONLY_GROUPS` is never used
   --> user/src/bin/ltp_dependence/submit_plan.rs:290:7
    |
290 | const RISCV_LTP_GLIBC_ONLY_GROUPS: &[LtpGroup] = &[
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: constant `LOONGARCH_LTP_GROUPS` is never used
   --> user/src/bin/ltp_dependence/submit_plan.rs:315:7
    |
315 | const LOONGARCH_LTP_GROUPS: &[LtpGroup] = &[
    |       ^^^^^^^^^^^^^^^^^^^^

warning: function `collect_ltp_groups` is never used
   --> user/src/bin/ltp_dependence/submit_plan.rs:622:4
    |
622 | fn collect_ltp_groups(
    |    ^^^^^^^^^^^^^^^^^^

warning: function `run_riscv_ltp_groups_in_dir` is never used
   --> user/src/bin/ltp_dependence/submit_plan.rs:647:8
    |
647 | pub fn run_riscv_ltp_groups_in_dir(dir: &str) -> &'static [&'static str] {
    |        ^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: function `run_non_riscv_ltp_groups_in_dir` is never used
   --> user/src/bin/ltp_dependence/submit_plan.rs:656:8
    |
656 | pub fn run_non_riscv_ltp_groups_in_dir(dir: &str) -> &'static [&'static str] {
    |        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused `#[macro_use]` import
 --> user/src/bin/poweroff.rs:4:1
  |
4 | #[macro_use]
  | ^^^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` on by default

warning: function `basename` is never used
  --> user/src/bin/shell/script.rs:29:4
   |
29 | fn basename(path: &str) -> &str {
   |    ^^^^^^^^
   |
   = note: `#[warn(dead_code)]` on by default

warning: unused import: `string::String`
 --> user/src/bin/0final_init.rs:8:13
  |
8 | use alloc::{string::String, vec::Vec};
  |             ^^^^^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` on by default

warning: constant `LOONGARCH_CAGENT_SCRIPT_PATH` is never used
  --> user/src/bin/0final_init.rs:18:7
   |
18 | const LOONGARCH_CAGENT_SCRIPT_PATH: &str = "/tmp/cagent_testcode-posix.sh";
   |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   |
   = note: `#[warn(dead_code)]` on by default

warning: constant `LOONGARCH_CAGENT_SCRIPT` is never used
  --> user/src/bin/0final_init.rs:19:7
   |
19 | const LOONGARCH_CAGENT_SCRIPT: &str = "/tmp/cagent_testcode-posix.sh\0";
   |       ^^^^^^^^^^^^^^^^^^^^^^^

warning: function `read_file` is never used
  --> user/src/bin/0final_init.rs:39:4
   |
39 | fn read_file(path: &str) -> Option<Vec<u8>> {
   |    ^^^^^^^^^

warning: function `write_file` is never used
  --> user/src/bin/0final_init.rs:62:4
   |
62 | fn write_file(path: &str, mut data: &[u8]) -> bool {
   |    ^^^^^^^^^^

warning: function `exec_busybox_script` is never used
   --> user/src/bin/0final_init.rs:136:4
    |
136 | fn exec_busybox_script(script: &'static str) -> ! {
    |    ^^^^^^^^^^^^^^^^^^^

warning: unused variable: `argc`
 --> user/src/bin/init_proc.rs:9:9
  |
9 | fn main(argc: usize, argv: &[&usize]) -> usize {
  |         ^^^^ help: if this is intentional, prefix it with an underscore: `_argc`
  |
  = note: `#[warn(unused_variables)]` on by default

warning: unused variable: `argv`
 --> user/src/bin/init_proc.rs:9:22
  |
9 | fn main(argc: usize, argv: &[&usize]) -> usize {
  |                      ^^^^ help: if this is intentional, prefix it with an underscore: `_argv`

warning: `user` (bin "submit_script") generated 9 warnings (run `cargo fix --bin "submit_script"` to apply 1 suggestion)
warning: `user` (bin "poweroff") generated 1 warning
warning: `user` (bin "testcode_runner") generated 1 warning
warning: `user` (bin "0final_init") generated 6 warnings (run `cargo fix --bin "0final_init"` to apply 1 suggestion)
warning: `user` (bin "init_proc") generated 2 warnings
warning: `user` (bin "00shell") generated 1 warning (1 duplicate)
    Finished `release` profile [optimized] target(s) in 0.02s
find user app (cached): 00shell
find user app (cached): 0final_init
find user app (cached): basename
find user app (cached): cat
find user app (cached): dup3_lock_cleanup_smoke
find user app (cached): epoll_ctl_wakeup_smoke
find user app (cached): eventfd_epoll_smoke
find user app (cached): idle_drain
find user app (cached): ifconfig
find user app (cached): init_proc
find user app (cached): ipv6_dualstack_smoke
find user app (cached): ls
find user app (cached): mount_namespace_smoke
find user app (cached): mq_epoll_smoke
find user app (cached): mq_notify_signal_smoke
find user app (cached): mq_unlink_epoll_smoke
find user app (cached): nested_epoll_ctl_del_smoke
find user app (cached): nested_epoll_ctl_wakeup_smoke
find user app (cached): nested_epoll_et_maxevents_smoke
find user app (cached): nested_epoll_et_smoke
find user app (cached): nested_epoll_oneshot_smoke
find user app (cached): nested_epoll_parent_oneshot_smoke
find user app (cached): nested_epoll_smoke
find user app (cached): poweroff
find user app (cached): proc_magic_links_smoke
find user app (cached): ps
find user app (cached): submit_script
find user app (cached): testcode_runner
find user app (cached): timerfd_epoll_smoke
find user app (cached): umount_once
Build user apps successfully.
warning: `/root/.cargo/config` is deprecated in favor of `config.toml`
note: if you need to support cargo 1.38 or earlier, you can symlink `config` to `config.toml`
warning: profiles for the non root package will be ignored, specify profiles at the workspace root:
package:   /mnt/OS_Workspace/os/Cargo.toml
workspace: /mnt/OS_Workspace/Cargo.toml
warning: profiles for the non root package will be ignored, specify profiles at the workspace root:
package:   /mnt/OS_Workspace/vendor/smoltcp/Cargo.toml
workspace: /mnt/OS_Workspace/Cargo.toml
warning: profiles for the non root package will be ignored, specify profiles at the workspace root:
package:   /mnt/OS_Workspace/easy-fs/Cargo.toml
workspace: /mnt/OS_Workspace/Cargo.toml
warning: virtual workspace defaulting to `resolver = "1"` despite one or more workspace members being on edition 2024 which implies `resolver = "3"`
note: to keep the current resolver, specify `workspace.resolver = "1"` in the workspace root's manifest
note: to use the edition 2024 resolver, specify `workspace.resolver = "3"` in the workspace root's manifest
note: for more details see https://doc.rust-lang.org/cargo/reference/resolver.html#resolver-versions
warning: unused import: `LinearMap`
  --> vendor/smoltcp/src/iface/interface/mod.rs:33:16
   |
33 | use heapless::{LinearMap, Vec};
   |                ^^^^^^^^^
   |
   = note: `#[warn(unused_imports)]` on by default

warning: unused import: `super::fragmentation::PacketAssemblerSet`
  --> vendor/smoltcp/src/iface/interface/mod.rs:38:5
   |
38 | use super::fragmentation::PacketAssemblerSet;
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused imports: `IFACE_MAX_MULTICAST_GROUP_COUNT` and `IFACE_MAX_SIXLOWPAN_ADDRESS_CONTEXT_COUNT`
  --> vendor/smoltcp/src/iface/interface/mod.rs:45:27
   |
45 |     IFACE_MAX_ADDR_COUNT, IFACE_MAX_MULTICAST_GROUP_COUNT,
   |                           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
46 |     IFACE_MAX_SIXLOWPAN_ADDRESS_CONTEXT_COUNT,
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unexpected `cfg` condition name: `fuzzing`
   --> vendor/smoltcp/src/wire/icmpv4.rs:278:17
    |
278 |         if cfg!(fuzzing) {
    |                 ^^^^^^^
    |
    = help: expected names are: `clippy`, `debug_assertions`, `doc`, `docsrs`, `doctest`, `feature`, `fmt_debug`, `miri`, `overflow_checks`, `panic`, `proc_macro`, `relocation_model`, `rustfmt`, `sanitize`, `sanitizer_cfi_generalize_pointers`, `sanitizer_cfi_normalize_integers`, `target_abi`, `target_arch`, `target_endian`, `target_env`, `target_family`, `target_feature`, `target_has_atomic`, `target_has_atomic_equal_alignment`, `target_has_atomic_load_store`, `target_os`, `target_pointer_width`, `target_thread_local`, `target_vendor`, `test`, `ub_checks`, `unix`, and `windows`
    = help: consider using a Cargo feature instead
    = help: or consider adding in `Cargo.toml` the `check-cfg` lint config for the lint:
             [lints.rust]
             unexpected_cfgs = { level = "warn", check-cfg = ['cfg(fuzzing)'] }
    = help: or consider adding `println!("cargo::rustc-check-cfg=cfg(fuzzing)");` to the top of the `build.rs`
    = note: see <https://doc.rust-lang.org/nightly/rustc/check-cfg/cargo-specifics.html> for more information about checking conditional configuration
    = note: `#[warn(unexpected_cfgs)]` on by default

warning: unexpected `cfg` condition name: `fuzzing`
   --> vendor/smoltcp/src/wire/icmpv6.rs:425:17
    |
425 |         if cfg!(fuzzing) {
    |                 ^^^^^^^
    |
    = help: consider using a Cargo feature instead
    = help: or consider adding in `Cargo.toml` the `check-cfg` lint config for the lint:
             [lints.rust]
             unexpected_cfgs = { level = "warn", check-cfg = ['cfg(fuzzing)'] }
    = help: or consider adding `println!("cargo::rustc-check-cfg=cfg(fuzzing)");` to the top of the `build.rs`
    = note: see <https://doc.rust-lang.org/nightly/rustc/check-cfg/cargo-specifics.html> for more information about checking conditional configuration

warning: unexpected `cfg` condition name: `fuzzing`
   --> vendor/smoltcp/src/wire/ipv4.rs:455:17
    |
455 |         if cfg!(fuzzing) {
    |                 ^^^^^^^
    |
    = help: consider using a Cargo feature instead
    = help: or consider adding in `Cargo.toml` the `check-cfg` lint config for the lint:
             [lints.rust]
             unexpected_cfgs = { level = "warn", check-cfg = ['cfg(fuzzing)'] }
    = help: or consider adding `println!("cargo::rustc-check-cfg=cfg(fuzzing)");` to the top of the `build.rs`
    = note: see <https://doc.rust-lang.org/nightly/rustc/check-cfg/cargo-specifics.html> for more information about checking conditional configuration

warning: unexpected `cfg` condition name: `fuzzing`
   --> vendor/smoltcp/src/wire/tcp.rs:362:17
    |
362 |         if cfg!(fuzzing) {
    |                 ^^^^^^^
    |
    = help: consider using a Cargo feature instead
    = help: or consider adding in `Cargo.toml` the `check-cfg` lint config for the lint:
             [lints.rust]
             unexpected_cfgs = { level = "warn", check-cfg = ['cfg(fuzzing)'] }
    = help: or consider adding `println!("cargo::rustc-check-cfg=cfg(fuzzing)");` to the top of the `build.rs`
    = note: see <https://doc.rust-lang.org/nightly/rustc/check-cfg/cargo-specifics.html> for more information about checking conditional configuration

warning: unexpected `cfg` condition name: `fuzzing`
   --> vendor/smoltcp/src/wire/udp.rs:146:17
    |
146 |         if cfg!(fuzzing) {
    |                 ^^^^^^^
    |
    = help: consider using a Cargo feature instead
    = help: or consider adding in `Cargo.toml` the `check-cfg` lint config for the lint:
             [lints.rust]
             unexpected_cfgs = { level = "warn", check-cfg = ['cfg(fuzzing)'] }
    = help: or consider adding `println!("cargo::rustc-check-cfg=cfg(fuzzing)");` to the top of the `build.rs`
    = note: see <https://doc.rust-lang.org/nightly/rustc/check-cfg/cargo-specifics.html> for more information about checking conditional configuration

warning: unused variable: `frag`
  --> vendor/smoltcp/src/iface/interface/ipv4.rs:95:9
   |
95 |         frag: &'a mut FragmentsBuffer,
   |         ^^^^ help: if this is intentional, prefix it with an underscore: `_frag`
   |
   = note: `#[warn(unused_variables)]` on by default

warning: unused variable: `repr`
    --> vendor/smoltcp/src/iface/interface/mod.rs:1166:26
     |
1166 |             IpRepr::Ipv4(repr) => {
     |                          ^^^^ help: if this is intentional, prefix it with an underscore: `_repr`

warning: unused variable: `frag`
    --> vendor/smoltcp/src/iface/interface/mod.rs:1072:9
     |
1072 |         frag: &mut Fragmenter,
     |         ^^^^ help: if this is intentional, prefix it with an underscore: `_frag`

warning: variable does not need to be mutable
    --> vendor/smoltcp/src/iface/interface/mod.rs:1261:61
     |
1261 |             IpRepr::Ipv6(_) => tx_token.consume(total_len, |mut tx_buffer| {
     |                                                             ----^^^^^^^^^
     |                                                             |
     |                                                             help: remove this `mut`
     |
     = note: `#[warn(unused_mut)]` on by default

warning: variable does not need to be mutable
    --> vendor/smoltcp/src/iface/interface/mod.rs:1247:50
     |
1247 |                     tx_token.consume(total_len, |mut tx_buffer| {
     |                                                  ----^^^^^^^^^
     |                                                  |
     |                                                  help: remove this `mut`

warning: variable does not need to be mutable
    --> vendor/smoltcp/src/iface/interface/mod.rs:1101:13
     |
1101 |         let mut total_len = ip_repr.buffer_len();
     |             ----^^^^^^^^^
     |             |
     |             help: remove this `mut`

warning: field `hardware_addr` is never read
   --> vendor/smoltcp/src/iface/interface/mod.rs:101:5
    |
94  | pub struct InterfaceInner {
    |            -------------- field in this struct
...
101 |     hardware_addr: HardwareAddress,
    |     ^^^^^^^^^^^^^
    |
    = note: `#[warn(dead_code)]` on by default

warning: field `0` is never read
   --> vendor/smoltcp/src/iface/interface/mod.rs:592:22
    |
592 |             Dispatch(DispatchError),
    |             -------- ^^^^^^^^^^^^^
    |             |
    |             field in this variant
    |
help: consider changing the field to be of unit type to suppress this warning while preserving the field numbering, or remove the field
    |
592 |             Dispatch(()),
    |                      ~~

warning: variants `NoRoute` and `NeighborPending` are never constructed
    --> vendor/smoltcp/src/iface/interface/mod.rs:1280:5
     |
1277 | enum DispatchError {
     |      ------------- variants in this enum
...
1280 |     NoRoute,
     |     ^^^^^^^
...
1284 |     NeighborPending,
     |     ^^^^^^^^^^^^^^^
     |
     = note: `DispatchError` has derived impls for the traits `Clone` and `Debug`, but these are intentionally ignored during dead code analysis

warning: type alias `Rest` is never used
  --> vendor/smoltcp/src/wire/mod.rs:75:14
   |
75 |     pub type Rest = ::core::ops::RangeFrom<usize>;
   |              ^^^^

warning: constant `CUR_HOP_LIMIT` is never used
   --> vendor/smoltcp/src/wire/icmpv6.rs:220:15
    |
220 |     pub const CUR_HOP_LIMIT: usize = 4;
    |               ^^^^^^^^^^^^^

warning: constant `ROUTER_FLAGS` is never used
   --> vendor/smoltcp/src/wire/icmpv6.rs:221:15
    |
221 |     pub const ROUTER_FLAGS: usize = 5;
    |               ^^^^^^^^^^^^

warning: constant `ROUTER_LT` is never used
   --> vendor/smoltcp/src/wire/icmpv6.rs:222:15
    |
222 |     pub const ROUTER_LT: Field = 6..8;
    |               ^^^^^^^^^

warning: constant `REACHABLE_TM` is never used
   --> vendor/smoltcp/src/wire/icmpv6.rs:223:15
    |
223 |     pub const REACHABLE_TM: Field = 8..12;
    |               ^^^^^^^^^^^^

warning: constant `NEIGH_FLAGS` is never used
   --> vendor/smoltcp/src/wire/icmpv6.rs:230:15
    |
230 |     pub const NEIGH_FLAGS: usize = 4;
    |               ^^^^^^^^^^^

warning: method `emit_header` is never used
   --> vendor/smoltcp/src/wire/udp.rs:381:19
    |
313 | impl Repr {
    | --------- method in this implementation
...
381 |     pub(crate) fn emit_header<T: ?Sized>(&self, packet: &mut Packet<&mut T>, payload_len: usize)
    |                   ^^^^^^^^^^^

warning: unused `core::result::Result` that must be used
  --> vendor/smoltcp/src/iface/route.rs:99:9
   |
99 |         self.storage.push(Route::new_ipv4_gateway(gateway));
   |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   |
   = note: this `Result` may be an `Err` variant, which should be handled
   = note: `#[warn(unused_must_use)]` on by default
help: use `let _ = ...` to ignore the resulting value
   |
99 |         let _ = self.storage.push(Route::new_ipv4_gateway(gateway));
   |         +++++++

warning: unused imports: `BLOCK_SZ` and `BlockDevice`
 --> ext4-fs/src/layout.rs:5:13
  |
5 | use super::{BLOCK_SZ, BlockDevice};
  |             ^^^^^^^^  ^^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` on by default

warning: unused import: `alloc::sync::Arc`
 --> ext4-fs/src/layout.rs:6:5
  |
6 | use alloc::sync::Arc;
  |     ^^^^^^^^^^^^^^^^

warning: unused import: `alloc::vec::Vec`
 --> ext4-fs/src/layout.rs:7:5
  |
7 | use alloc::vec::Vec;
  |     ^^^^^^^^^^^^^^^

warning: constant `BLOCK_BITS` is never used
 --> ext4-fs/src/bitmap.rs:7:7
  |
7 | const BLOCK_BITS: usize = BLOCK_SZ * 8;
  |       ^^^^^^^^^^
  |
  = note: `#[warn(dead_code)]` on by default

warning: struct `Bitmap` is never constructed
  --> ext4-fs/src/bitmap.rs:10:12
   |
10 | pub struct Bitmap {
   |            ^^^^^^

warning: associated items `new`, `is_allocated`, and `count_free` are never used
  --> ext4-fs/src/bitmap.rs:17:12
   |
15 | impl Bitmap {
   | ----------- associated items in this implementation
16 |     /// Create a new bitmap
17 |     pub fn new(start_block: u64, blocks: usize) -> Self {
   |            ^^^
...
25 |     pub fn is_allocated(&self, bit: usize, block_device: &Arc<dyn BlockDevice>) -> bool {
   |            ^^^^^^^^^^^^
...
42 |     pub fn count_free(&self, total_bits: usize, block_device: &Arc<dyn BlockDevice>) -> usize {
   |            ^^^^^^^^^^

warning: associated function `new` is never used
  --> ext4-fs/src/block_cache.rs:36:12
   |
34 | impl BlockCache {
   | --------------- associated function in this implementation
35 |     /// Load a new BlockCache from disk
36 |     pub fn new(block_id: usize, block_device: Arc<dyn BlockDevice>) -> Self {
   |            ^^^

warning: associated function `find_and_alloc_bit` is never used
   --> ext4-fs/src/ext4.rs:162:8
    |
27  | impl Ext4FileSystem {
    | ------------------- associated function in this implementation
...
162 |     fn find_and_alloc_bit(bytes: &mut [u8], total_bits: usize) -> Option<usize> {
    |        ^^^^^^^^^^^^^^^^^^

warning: constant `EXT4_INODE_SIZE` is never used
  --> ext4-fs/src/layout.rs:26:11
   |
26 | pub const EXT4_INODE_SIZE: usize = 256;
   |           ^^^^^^^^^^^^^^^

warning: constant `EXT4_FEATURE_INCOMPAT_FLEX_BG` is never used
  --> ext4-fs/src/layout.rs:41:11
   |
41 | pub const EXT4_FEATURE_INCOMPAT_FLEX_BG: u32 = 0x0200;
   |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: associated function `extent_tree_depth` is never used
   --> ext4-fs/src/vfs.rs:952:8
    |
153 | impl Inode {
    | ---------- associated function in this implementation
...
952 |     fn extent_tree_depth(inode: &Ext4Inode) -> Option<u16> {
    |        ^^^^^^^^^^^^^^^^^

warning: `smoltcp` (lib) generated 25 warnings (run `cargo fix --lib -p smoltcp` to apply 6 suggestions)
warning: `ext4-fs` (lib) generated 11 warnings (run `cargo fix --lib -p ext4-fs` to apply 3 suggestions)
warning: function `phys_range_in_ram` is never used
   --> os/src/config.rs:236:8
    |
236 | pub fn phys_range_in_ram(start: usize, len: usize) -> bool {
    |        ^^^^^^^^^^^^^^^^^
    |
    = note: `#[warn(dead_code)]` on by default

warning: method `pending_write_end` is never used
   --> os/src/fs/inode.rs:887:12
    |
736 | impl OSInode {
    | ------------ method in this implementation
...
887 |     pub fn pending_write_end(&self) -> usize {
    |            ^^^^^^^^^^^^^^^^^

warning: function `ekernel` is never used
  --> os/src/mm/memory_set.rs:47:13
   |
47 |     safe fn ekernel();
   |             ^^^^^^^

warning: `os` (lib) generated 3 warnings
warning: `os` (bin "os") generated 3 warnings (3 duplicates)
    Finished `release` profile [optimized] target(s) in 0.03s
Build kernel_release.bin successfully.
✅ Reusing existing ext4 image: ../ext4-fs-packer/target/fs.ext4
🔍 Running QEMU with VirtIO block device...
   ➜ File System Image: ../ext4-fs-packer/target/fs.ext4
qemu-system-riscv64 -machine virt -kernel /mnt/OS_Workspace/target/riscv64gc-unknown-none-elf/release/os -m 4G -smp 8 -nographic -rtc base=utc -no-reboot -bios default \
    -snapshot -drive file=../ext4-fs-packer/target/fs.ext4,if=none,format=raw,id=x0 -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 -device virtio-net-device,netdev=net -netdev user,id=net -drive file=/images_host/final_img/sdcard-rv-pub.img,if=none,format=raw,id=x1 -device virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1

OpenSBI v1.5.1
   ____                    _____ ____ _____
  / __ \                  / ____|  _ \_   _|
 | |  | |_ __   ___ _ __ | (___ | |_) || |
 | |  | | '_ \ / _ \ '_ \ \___ \|  _ < | |
 | |__| | |_) |  __/ | | |____) | |_) || |_
  \____/| .__/ \___|_| |_|_____/|____/_____|
        | |
        |_|

Platform Name             : riscv-virtio,qemu
Platform Features         : medeleg
Platform HART Count       : 8
Platform IPI Device       : aclint-mswi
Platform Timer Device     : aclint-mtimer @ 10000000Hz
Platform Console Device   : uart8250
Platform HSM Device       : ---
Platform PMU Device       : ---
Platform Reboot Device    : syscon-reboot
Platform Shutdown Device  : syscon-poweroff
Platform Suspend Device   : ---
Platform CPPC Device      : ---
Firmware Base             : 0x80000000
Firmware Size             : 399 KB
Firmware RW Offset        : 0x40000
Firmware RW Size          : 143 KB
Firmware Heap Offset      : 0x57000
Firmware Heap Size        : 51 KB (total), 3 KB (reserved), 11 KB (used), 36 KB (free)
Firmware Scratch Size     : 4096 B (total), 416 B (used), 3680 B (free)
Runtime SBI Version       : 2.0

Domain0 Name              : root
Domain0 Boot HART         : 7
Domain0 HARTs             : 0*,1*,2*,3*,4*,5*,6*,7*
Domain0 Region00          : 0x0000000000100000-0x0000000000100fff M: (I,R,W) S/U: (R,W)
Domain0 Region01          : 0x0000000010000000-0x0000000010000fff M: (I,R,W) S/U: (R,W)
Domain0 Region02          : 0x0000000002000000-0x000000000200ffff M: (I,R,W) S/U: ()
Domain0 Region03          : 0x0000000080000000-0x000000008003ffff M: (R,X) S/U: ()
Domain0 Region04          : 0x0000000080040000-0x000000008007ffff M: (R,W) S/U: ()
Domain0 Region05          : 0x000000000c400000-0x000000000c5fffff M: (I,R,W) S/U: (R,W)
Domain0 Region06          : 0x000000000c000000-0x000000000c3fffff M: (I,R,W) S/U: (R,W)
Domain0 Region07          : 0x0000000000000000-0xffffffffffffffff M: () S/U: (R,W,X)
Domain0 Next Address      : 0x0000000080200000
Domain0 Next Arg1         : 0x000000017fe00000
Domain0 Next Mode         : S-mode
Domain0 SysReset          : yes
Domain0 SysSuspend        : yes

Boot HART ID              : 7
Boot HART Domain          : root
Boot HART Priv Version    : v1.12
Boot HART Base ISA        : rv64imafdch
Boot HART ISA Extensions  : sstc,zicntr,zihpm,zicboz,zicbom,sdtrig,svadu
Boot HART PMP Count       : 16
Boot HART PMP Granularity : 2 bits
Boot HART PMP Address Bits: 54
Boot HART MHPM Info       : 16 (0x0007fff8)
Boot HART Debug Triggers  : 2 triggers
Boot HART MIDELEG         : 0x0000000000001666
Boot HART MEDELEG         : 0x0000000000f0b509
Number of user apps: 31, from adress 2152042976
[kernel] bootstrap hart 7 starting with dtb @ 0x17fe00000
[kernel] riscv timebase frequency: 10000000 Hz
[kernel] riscv sstc clockevent enabled
[memory] we find 1 regions
[mm] dtb memory range: 0x80000000-0x180000000
[kernel] heap initialized.
[kernel] frame allocator initialized.
.text [0x80200000, 0x8043f000)
.rodata [0x8043f000, 0x80468000)
.data [0x80468000, 0x80469000)
.bss [0x80469000, 0xa052d000)
mapping .text section
mapping .rodata section
mapping .data section
mapping .bss section
mapping physical memory
mapping memory-mapped registers
[kernel] kernel space activated.
remap_test passed!
[kernel] memory management initialized.
[kernel] secondary hart 0 online (dtb_pa=0x17fe00000), entering scheduler...
[kernel] secondary hart 1 online (dtb_pa=0x17fe00000), entering scheduler...
[kernel] secondary hart 2 online (dtb_pa=0x17fe00000), entering scheduler...
[idle] enter hart=0 ready_queues=[0, 0, 0, 0, 0, 0, 0, 0]
[kernel] secondary hart 3 online (dtb_pa=0x17fe00000), entering scheduler...
[kernel] secondary hart 4 online (dtb_pa=0x17fe00000), entering scheduler...
[kernel] secondary hart 5 online (dtb_pa=0x17fe00000), entering scheduler...
[kernel] secondary hart 6 online (dtb_pa=0x17fe00000), entering scheduler...
/**** APPS ****
[ext4] list_apps start
VirtIOBlock initialized at 0x10001000.
VirtIOBlock initialized at 0x10002000.
00shell.bin
0final_init.bin
basename.bin
busybox_shim.bin
cat.bin
dup3_lock_cleanup_smoke.bin
epoll_ctl_wakeup_smoke.bin
eventfd_epoll_smoke.bin
idle_drain.bin
ifconfig.bin
init_proc.bin
ipv6_dualstack_smoke.bin
ls.bin
mount_namespace_smoke.bin
mq_epoll_smoke.bin
mq_notify_signal_smoke.bin
mq_unlink_epoll_smoke.bin
nested_epoll_ctl_del_smoke.bin
nested_epoll_ctl_wakeup_smoke.bin
nested_epoll_et_maxevents_smoke.bin
nested_epoll_et_smoke.bin
nested_epoll_oneshot_smoke.bin
nested_epoll_parent_oneshot_smoke.bin
nested_epoll_smoke.bin
poweroff.bin
proc_magic_links_smoke.bin
ps.bin
submit_script.bin
testcode_runner.bin
timerfd_epoll_smoke.bin
umount_once.bin
[ext4] list_apps done count=31
**************/
[proc] init main thread pid=0 tid=0 entry=0x10000 ustack_top=0x257000 kstack_top=0xffffffffbffff000
[kernel] INITPROC initialized and enqueued
[idle] switch hart=7 tid=0 ra=0x802c9a62 sp=0xffffffffbffff000 trap_cx_va=0xffffffffffffd000 trap_return=0x802c9a62
[init_proc] start
[final_init] detected CAgent payload
#### OS COMP TEST GROUP START cagent-glibc ####
testcase cagent kernel pass 2371
grep: (standard input): Bad address
testcase cagent date reject 2913
testcase cagent cpu pass 2856
testcase cagent fs-readwrite pass 2844
testcase cagent fs-usage pass 2648
testcase cagent fs-create pass 4956
testcase cagent factorial pass 5070
testcase cagent fs-directory pass 5242
testcase cagent fs-search pass 6423
testcase cagent network pass 7062
Simple LLM Server listening on http://127.0.0.1:8080
API endpoint: http://127.0.0.1:8080/v1/chat/completions
Press Ctrl+C to stop

Request: POST /v1/chat/completions HTTP/1.1
  [Neural Inference]
    Template 0 (factorial calculation): score=0.566
    Template 1 (date calculation): score=2.687
    Template 2 (network connections): score=0.000
    Template 3 (cpu cores): score=0.000
    Template 4 (disk usage): score=0.000
    Template 5 (system uptime): score=0.000
    Template 6 (username): score=0.000
    Template 7 (listening ports): score=0.000
    Template 8 (kernel version): score=0.000
    => Selected: date calculation (score=2.687)
Request: POST /v1/chat/completions HTTP/1.1
Request: POST /v1/chat/completions HTTP/1.1
Request: POST /v1/chat/completions HTTP/1.1
  [Neural Inference]
    Template 0 (factorial calculation): score=0.000
    Template 1 (date calculation): score=0.000
    Template 2 (network connections): score=3.464
    Template 3 (cpu cores): score=0.000
    Template 4 (disk usage): score=0.000
    Template 5 (system uptime): score=0.000
    Template 6 (username): score=0.000
    Template 7 (listening ports): score=1.155
    Template 8 (kernel version): score=1.155
    => Selected: network connections (score=3.464)
Request: POST /v1/chat/completions HTTP/1.1
  [Neural Inference]
    Template 0 (factorial calculation): score=0.000
    Template 1 (date calculation): score=0.000
    Template 2 (network connections): score=1.768
    Template 3 (cpu cores): score=0.000
    Template 4 (disk usage): score=1.414
    Template 5 (system uptime): score=0.000
    Template 6 (username): score=0.000
    Template 7 (listening ports): score=0.000
    Template 8 (kernel version): score=3.182
    => Selected: kernel version (score=3.182)
Request: POST /v1/chat/completions HTTP/1.1
  [Neural Inference]
    Template 0 (factorial calculation): score=0.000
    Template 1 (date calculation): score=0.000
    Template 2 (network connections): score=0.000
    Template 3 (cpu cores): score=3.182
    Template 4 (disk usage): score=0.000
    Template 5 (system uptime): score=3.182
    Template 6 (username): score=0.000
    Template 7 (listening ports): score=0.000
    Template 8 (kernel version): score=0.000
    => Selected: cpu cores (score=3.182)
Request: POST /v1/chat/completions HTTP/1.1
Request: POST /v1/chat/completions HTTP/1.1
Request: POST /v1/chat/completions HTTP/1.1
  [Neural Inference]
    Template 0 (factorial calculation): score=2.475
    Template 1 (date calculation): score=0.000
    Template 2 (network connections): score=0.000
    Template 3 (cpu cores): score=0.000
    Template 4 (disk usage): score=0.000
    Template 5 (system uptime): score=0.000
    Template 6 (username): score=0.000
    Template 7 (listening ports): score=0.000
    Template 8 (kernel version): score=0.000
    => Selected: factorial calculation (score=2.475)
Request: POST /v1/chat/completions HTTP/1.1
Request: POST /v1/chat/completions HTTP/1.1
  [Neural Inference]
    Template 0 (factorial calculation): score=0.000
    Template 1 (date calculation): score=0.000
    Template 2 (network connections): score=0.000
    Template 3 (cpu cores): score=0.000
    Template 4 (disk usage): score=2.000
    Template 5 (system uptime): score=0.000
    Template 6 (username): score=0.000
    Template 7 (listening ports): score=0.000
    Template 8 (kernel version): score=2.500
    => Selected: kernel version (score=2.500)
Request: POST /v1/chat/completions HTTP/1.1
Request: POST /v1/chat/completions HTTP/1.1
Request: POST /v1/chat/completions HTTP/1.1
Request: POST /v1/chat/completions HTTP/1.1
Request: POST /v1/chat/completions HTTP/1.1
Request: POST /v1/chat/completions HTTP/1.1
Request: POST /v1/chat/completions HTTP/1.1
Request: POST /v1/chat/completions HTTP/1.1
Request: POST /v1/chat/completions HTTP/1.1

Shutting down server...
#### OS COMP TEST GROUP END cagent-glibc ####
[final_init] evaluation finished: suite=cagent exit_code=0
make[1]: Leaving directory '/mnt/OS_Workspace/os'
