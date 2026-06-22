//! WireGuard Noise 与数据包加密的内部基础件。
//!
//! 这些 helper 对照 Linux `drivers/net/wireguard/noise.c/messages.h`，只提供后续
//! 握手和 UDP 隧道会用到的密码学原语；当前不会单独让 WireGuard 驱动对外宣称可用。

#![allow(dead_code)]

use alloc::vec::Vec;

use blake2::{Blake2s256, Blake2sMac, Digest, digest::consts::U16};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce, Tag,
    aead::{AeadInPlace, KeyInit},
};
use core::sync::atomic::{AtomicU64, Ordering};
use x25519_dalek::{PublicKey, StaticSecret};

// WireGuard/Noise 固定长度。
pub(super) const NOISE_PUBLIC_KEY_LEN: usize = 32;
pub(super) const NOISE_SYMMETRIC_KEY_LEN: usize = 32;
/// WireGuard 使用 TAI64N 时间戳防止 handshake initiation 重放。
pub(super) const NOISE_TIMESTAMP_LEN: usize = 12;
pub(super) const NOISE_AUTHTAG_LEN: usize = 16;
pub(super) const NOISE_HASH_LEN: usize = 32;
pub(super) const WIREGUARD_MAC_LEN: usize = 16;
/// WireGuard data message 明文按 16 字节对齐填充。
pub(super) const MESSAGE_PADDING_MULTIPLE: usize = 16;
pub(super) const MESSAGE_DATA_HEADER_LEN: usize = 16;
pub(super) const MESSAGE_DATA_MIN_LEN: usize = MESSAGE_DATA_HEADER_LEN + NOISE_AUTHTAG_LEN;
pub(super) const MESSAGE_HANDSHAKE_INITIATION_LEN: usize = 4
    + 4
    + NOISE_PUBLIC_KEY_LEN
    + encrypted_len_const(NOISE_PUBLIC_KEY_LEN)
    + encrypted_len_const(NOISE_TIMESTAMP_LEN)
    + 32;
pub(super) const MESSAGE_HANDSHAKE_RESPONSE_LEN: usize =
    4 + 4 + 4 + NOISE_PUBLIC_KEY_LEN + encrypted_len_const(0) + 32;
pub(super) const MESSAGE_HANDSHAKE_COOKIE_LEN: usize = 4 + 4 + 24 + encrypted_len_const(16);
/// 到达这个发送计数后应该发起 rekey；当前调用侧只暴露判断，不自动重协商。
pub(super) const REKEY_AFTER_MESSAGES: u64 = 1 << 60;

const BLAKE2S_BLOCK_SIZE: usize = 64;
// WireGuard replay window：用 8192 bit 滑动窗口记录已经见过的 counter。
const COUNTER_BITS_TOTAL: usize = 8192;
const COUNTER_WORD_BITS: usize = u64::BITS as usize;
const COUNTER_WORDS: usize = COUNTER_BITS_TOTAL / COUNTER_WORD_BITS;
const COUNTER_WINDOW_SIZE: u64 = (COUNTER_BITS_TOTAL - COUNTER_WORD_BITS) as u64;
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - COUNTER_WINDOW_SIZE - 1;

// Noise 协议名和 WireGuard 标识符必须逐字节匹配协议规范。
const HANDSHAKE_NAME: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s\0";
const IDENTIFIER_NAME: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com\0";
const MAC1_KEY_LABEL: &[u8; 8] = b"mac1----";
const COOKIE_KEY_LABEL: &[u8; 8] = b"cookie--";

// WireGuard message type。
const MESSAGE_HANDSHAKE_INITIATION: u32 = 1;
const MESSAGE_HANDSHAKE_RESPONSE: u32 = 2;
const MESSAGE_HANDSHAKE_COOKIE: u32 = 3;
const MESSAGE_DATA: u32 = 4;

// 各种握手消息字段在 wire format 中的固定偏移。
const INITIATION_SENDER_INDEX: usize = 4;
const INITIATION_EPHEMERAL: usize = 8;
const INITIATION_ENCRYPTED_STATIC: usize = 40;
const INITIATION_ENCRYPTED_TIMESTAMP: usize = 88;
const INITIATION_MAC1: usize = 116;
const INITIATION_MAC2: usize = 132;
const RESPONSE_SENDER_INDEX: usize = 4;
const RESPONSE_RECEIVER_INDEX: usize = 8;
const RESPONSE_EPHEMERAL: usize = 12;
const RESPONSE_ENCRYPTED_NOTHING: usize = 44;
const RESPONSE_MAC1: usize = 60;
const RESPONSE_MAC2: usize = 76;
const COOKIE_RECEIVER_INDEX: usize = 4;
const COOKIE_NONCE: usize = 8;
const COOKIE_ENCRYPTED_COOKIE: usize = 32;
const COOKIE_NONCE_LEN: usize = 24;

// TAI64N 相对 Unix epoch 的秒偏移。
const TAI64_EPOCH_OFFSET: u64 = 0x4000_0000_0000_000a;

// 这里用轻量伪随机数只为 LTP 内部握手生成临时 key/nonce；不是安全 RNG。
static WG_RNG_STATE: AtomicU64 = AtomicU64::new(0x6d5a_56da_1b2c_3d4e);
type Blake2sMac128 = Blake2sMac<U16>;

const fn encrypted_len_const(plain_len: usize) -> usize {
    plain_len + NOISE_AUTHTAG_LEN
}

/// Noise 握手滚动状态：`chaining_key` 负责派生后续密钥，`hash` 绑定 transcript。
#[derive(Clone, Debug)]
pub(super) struct NoiseHandshakeState {
    pub(super) chaining_key: [u8; NOISE_HASH_LEN],
    pub(super) hash: [u8; NOISE_HASH_LEN],
}

/// 被动端成功消费 initiation 后得到的中间结果。
#[derive(Clone, Debug)]
pub(super) struct ConsumedInitiation {
    pub(super) state: NoiseHandshakeState,
    /// 解密出来的对端静态公钥。
    pub(super) remote_static: [u8; NOISE_PUBLIC_KEY_LEN],
    /// 对端临时公钥。
    pub(super) remote_ephemeral: [u8; NOISE_PUBLIC_KEY_LEN],
    /// 对端 sender index，response 需要作为 receiver index 回填。
    pub(super) remote_index: u32,
    /// initiation 中的 TAI64N timestamp，用于拒绝旧握手。
    pub(super) timestamp: [u8; NOISE_TIMESTAMP_LEN],
}

/// 主动端成功消费 response 后得到的中间结果。
#[derive(Clone, Debug)]
pub(super) struct ConsumedResponse {
    pub(super) state: NoiseHandshakeState,
    pub(super) remote_ephemeral: [u8; NOISE_PUBLIC_KEY_LEN],
    /// 对端 sender index，后续 data message 要填到 key_idx。
    pub(super) remote_index: u32,
}

/// 一把方向性对称密钥。
#[derive(Clone, Debug)]
pub(super) struct NoiseSymmetricKey {
    pub(super) key: [u8; NOISE_SYMMETRIC_KEY_LEN],
    /// 生成时间；后续实现时间型 rekey 时会用到。
    pub(super) birth_ms: usize,
    pub(super) is_valid: bool,
}

/// WireGuard data message 的接收侧重放窗口。
#[derive(Clone, Debug)]
pub(super) struct NoiseReplayCounter {
    /// 已接受的最大 counter 加一。
    counter: u64,
    /// 环形 bitmap，记录窗口内哪些 counter 已经出现过。
    backtrack: [u64; COUNTER_WORDS],
}

impl Default for NoiseReplayCounter {
    fn default() -> Self {
        Self {
            counter: 0,
            backtrack: [0; COUNTER_WORDS],
        }
    }
}

impl NoiseReplayCounter {
    /// 校验入站 data message counter 是否未重放且仍在窗口内。
    pub(super) fn validate(&mut self, their_counter: u64) -> bool {
        if their_counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        let Some(nonce) = their_counter.checked_add(1) else {
            return false;
        };
        if COUNTER_WINDOW_SIZE.saturating_add(nonce) < self.counter {
            return false;
        }
        let index = (nonce / COUNTER_WORD_BITS as u64) as usize;
        if nonce > self.counter {
            // 新 counter 推进窗口时，把新跨过的 bitmap word 清零。
            let index_current = (self.counter / COUNTER_WORD_BITS as u64) as usize;
            let word_delta = index.saturating_sub(index_current);
            if word_delta >= COUNTER_WORDS {
                self.backtrack.fill(0);
            } else {
                for word in (index_current + 1)..=index {
                    self.backtrack[word & (COUNTER_WORDS - 1)] = 0;
                }
            }
            self.counter = nonce;
        }
        let word = index & (COUNTER_WORDS - 1);
        let bit = nonce & (COUNTER_WORD_BITS as u64 - 1);
        let mask = 1u64 << bit;
        if (self.backtrack[word] & mask) != 0 {
            return false;
        }
        // 首次见到该 counter，标记为已接收。
        self.backtrack[word] |= mask;
        true
    }
}

/// 完成握手后的双向密钥组。
#[derive(Clone, Debug)]
pub(super) struct NoiseKeypair {
    /// 本端发送时使用的 key。
    pub(super) sending: NoiseSymmetricKey,
    /// 本端接收时使用的 key。
    pub(super) receiving: NoiseSymmetricKey,
    pub(super) sending_counter: u64,
    pub(super) receiving_counter: NoiseReplayCounter,
    /// 对端 sender index；本端发送 data message 时填入 key_idx。
    pub(super) remote_index: u32,
    pub(super) i_am_the_initiator: bool,
}

impl NoiseKeypair {
    /// 分配下一个发送 counter。超过协议上限后要求重新握手。
    pub(super) fn next_sending_counter(&mut self) -> Option<u64> {
        if !self.sending.is_valid || self.sending_counter >= REJECT_AFTER_MESSAGES {
            return None;
        }
        let counter = self.sending_counter;
        self.sending_counter = self.sending_counter.saturating_add(1);
        Some(counter)
    }

    /// 是否应该主动 rekey。
    pub(super) fn needs_rekey(&self) -> bool {
        self.sending_counter > REKEY_AFTER_MESSAGES
    }
}

/// WireGuard UDP payload 的四类消息。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WireguardMessageType {
    HandshakeInitiation,
    HandshakeResponse,
    HandshakeCookie,
    Data,
}

/// 已解析的 data message 视图；payload 仍借用原始 packet。
#[derive(Clone, Copy, Debug)]
pub(super) struct WireguardDataPacket<'a> {
    pub(super) key_idx: u32,
    pub(super) counter: u64,
    pub(super) encrypted_payload: &'a [u8],
}

/// WireGuard handshake initiation 的 wire-format 字段。
#[derive(Clone, Debug)]
pub(super) struct HandshakeInitiation {
    pub(super) sender_index: u32,
    pub(super) unencrypted_ephemeral: [u8; NOISE_PUBLIC_KEY_LEN],
    pub(super) encrypted_static: [u8; encrypted_len_const(NOISE_PUBLIC_KEY_LEN)],
    pub(super) encrypted_timestamp: [u8; encrypted_len_const(NOISE_TIMESTAMP_LEN)],
    pub(super) mac1: [u8; WIREGUARD_MAC_LEN],
    pub(super) mac2: [u8; WIREGUARD_MAC_LEN],
}

/// WireGuard handshake response 的 wire-format 字段。
#[derive(Clone, Debug)]
pub(super) struct HandshakeResponse {
    pub(super) sender_index: u32,
    pub(super) receiver_index: u32,
    pub(super) unencrypted_ephemeral: [u8; NOISE_PUBLIC_KEY_LEN],
    pub(super) encrypted_nothing: [u8; encrypted_len_const(0)],
    pub(super) mac1: [u8; WIREGUARD_MAC_LEN],
    pub(super) mac2: [u8; WIREGUARD_MAC_LEN],
}

/// WireGuard cookie reply。当前数据面只识别类型，cookie 机制尚未真正接入。
#[derive(Clone, Debug)]
pub(super) struct HandshakeCookie {
    pub(super) receiver_index: u32,
    pub(super) nonce: [u8; COOKIE_NONCE_LEN],
    pub(super) encrypted_cookie: [u8; encrypted_len_const(WIREGUARD_MAC_LEN)],
}

/// 根据 message type 和长度识别 WireGuard payload 类型。
pub(super) fn message_type(packet: &[u8]) -> Option<WireguardMessageType> {
    if packet.len() < 4 {
        return None;
    }
    match u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]) {
        MESSAGE_HANDSHAKE_INITIATION if packet.len() == MESSAGE_HANDSHAKE_INITIATION_LEN => {
            Some(WireguardMessageType::HandshakeInitiation)
        }
        MESSAGE_HANDSHAKE_RESPONSE if packet.len() == MESSAGE_HANDSHAKE_RESPONSE_LEN => {
            Some(WireguardMessageType::HandshakeResponse)
        }
        MESSAGE_HANDSHAKE_COOKIE if packet.len() == MESSAGE_HANDSHAKE_COOKIE_LEN => {
            Some(WireguardMessageType::HandshakeCookie)
        }
        MESSAGE_DATA if packet.len() >= MESSAGE_DATA_MIN_LEN => Some(WireguardMessageType::Data),
        _ => None,
    }
}

/// 解析 handshake initiation。长度和类型不匹配时返回 None。
pub(super) fn parse_handshake_initiation(packet: &[u8]) -> Option<HandshakeInitiation> {
    if message_type(packet) != Some(WireguardMessageType::HandshakeInitiation) {
        return None;
    }
    Some(HandshakeInitiation {
        sender_index: u32::from_le_bytes(read_array(packet, INITIATION_SENDER_INDEX)?),
        unencrypted_ephemeral: read_array(packet, INITIATION_EPHEMERAL)?,
        encrypted_static: read_array(packet, INITIATION_ENCRYPTED_STATIC)?,
        encrypted_timestamp: read_array(packet, INITIATION_ENCRYPTED_TIMESTAMP)?,
        mac1: read_array(packet, INITIATION_MAC1)?,
        mac2: read_array(packet, INITIATION_MAC2)?,
    })
}

/// 按 WireGuard wire format 构造 handshake initiation。
pub(super) fn build_handshake_initiation(msg: &HandshakeInitiation) -> Vec<u8> {
    let mut packet = Vec::with_capacity(MESSAGE_HANDSHAKE_INITIATION_LEN);
    packet.extend_from_slice(&MESSAGE_HANDSHAKE_INITIATION.to_le_bytes());
    packet.extend_from_slice(&msg.sender_index.to_le_bytes());
    packet.extend_from_slice(&msg.unencrypted_ephemeral);
    packet.extend_from_slice(&msg.encrypted_static);
    packet.extend_from_slice(&msg.encrypted_timestamp);
    packet.extend_from_slice(&msg.mac1);
    packet.extend_from_slice(&msg.mac2);
    packet
}

/// 解析 handshake response。
pub(super) fn parse_handshake_response(packet: &[u8]) -> Option<HandshakeResponse> {
    if message_type(packet) != Some(WireguardMessageType::HandshakeResponse) {
        return None;
    }
    Some(HandshakeResponse {
        sender_index: u32::from_le_bytes(read_array(packet, RESPONSE_SENDER_INDEX)?),
        receiver_index: u32::from_le_bytes(read_array(packet, RESPONSE_RECEIVER_INDEX)?),
        unencrypted_ephemeral: read_array(packet, RESPONSE_EPHEMERAL)?,
        encrypted_nothing: read_array(packet, RESPONSE_ENCRYPTED_NOTHING)?,
        mac1: read_array(packet, RESPONSE_MAC1)?,
        mac2: read_array(packet, RESPONSE_MAC2)?,
    })
}

/// 按 WireGuard wire format 构造 handshake response。
pub(super) fn build_handshake_response(msg: &HandshakeResponse) -> Vec<u8> {
    let mut packet = Vec::with_capacity(MESSAGE_HANDSHAKE_RESPONSE_LEN);
    packet.extend_from_slice(&MESSAGE_HANDSHAKE_RESPONSE.to_le_bytes());
    packet.extend_from_slice(&msg.sender_index.to_le_bytes());
    packet.extend_from_slice(&msg.receiver_index.to_le_bytes());
    packet.extend_from_slice(&msg.unencrypted_ephemeral);
    packet.extend_from_slice(&msg.encrypted_nothing);
    packet.extend_from_slice(&msg.mac1);
    packet.extend_from_slice(&msg.mac2);
    packet
}

/// 解析 cookie reply；当前主要用于完整识别消息类型。
pub(super) fn parse_handshake_cookie(packet: &[u8]) -> Option<HandshakeCookie> {
    if message_type(packet) != Some(WireguardMessageType::HandshakeCookie) {
        return None;
    }
    Some(HandshakeCookie {
        receiver_index: u32::from_le_bytes(read_array(packet, COOKIE_RECEIVER_INDEX)?),
        nonce: read_array(packet, COOKIE_NONCE)?,
        encrypted_cookie: read_array(packet, COOKIE_ENCRYPTED_COOKIE)?,
    })
}

/// 构造 cookie reply。
pub(super) fn build_handshake_cookie(msg: &HandshakeCookie) -> Vec<u8> {
    let mut packet = Vec::with_capacity(MESSAGE_HANDSHAKE_COOKIE_LEN);
    packet.extend_from_slice(&MESSAGE_HANDSHAKE_COOKIE.to_le_bytes());
    packet.extend_from_slice(&msg.receiver_index.to_le_bytes());
    packet.extend_from_slice(&msg.nonce);
    packet.extend_from_slice(&msg.encrypted_cookie);
    packet
}

/// 根据 peer public key 派生 mac1 key。
pub(super) fn message_mac1_key(public_key: &[u8; NOISE_PUBLIC_KEY_LEN]) -> [u8; NOISE_HASH_LEN] {
    blake2s_hash(&[MAC1_KEY_LABEL, public_key])
}

/// 根据 peer public key 派生 cookie 加密 key。
pub(super) fn cookie_encryption_key(
    public_key: &[u8; NOISE_PUBLIC_KEY_LEN],
) -> [u8; NOISE_HASH_LEN] {
    blake2s_hash(&[COOKIE_KEY_LABEL, public_key])
}

/// 计算握手包的 mac1。
///
/// mac1 覆盖握手包开头到 mac1 字段之前的内容；mac1/mac2 字段本身不参与。
pub(super) fn compute_mac1(
    packet: &[u8],
    mac1_key: &[u8; NOISE_SYMMETRIC_KEY_LEN],
) -> Option<[u8; WIREGUARD_MAC_LEN]> {
    let (mac1_offset, _) = handshake_mac_offsets(packet)?;
    Some(blake2s_keyed_128(mac1_key, packet.get(..mac1_offset)?))
}

/// 常量时间比较握手包中的 mac1 是否正确。
pub(super) fn validate_mac1(packet: &[u8], mac1_key: &[u8; NOISE_SYMMETRIC_KEY_LEN]) -> bool {
    let Some((mac1_offset, _)) = handshake_mac_offsets(packet) else {
        return false;
    };
    let Some(expected) = compute_mac1(packet, mac1_key) else {
        return false;
    };
    let Some(actual) = packet.get(mac1_offset..mac1_offset + WIREGUARD_MAC_LEN) else {
        return false;
    };
    constant_time_eq(&expected, actual)
}

/// 先清空 mac1/mac2，再写入正确的 mac1。
pub(super) fn apply_mac1(
    packet: &mut [u8],
    mac1_key: &[u8; NOISE_SYMMETRIC_KEY_LEN],
) -> Option<[u8; WIREGUARD_MAC_LEN]> {
    let (mac1_offset, mac2_offset) = handshake_mac_offsets(packet)?;
    for byte in packet.get_mut(mac1_offset..mac2_offset + WIREGUARD_MAC_LEN)? {
        *byte = 0;
    }
    let mac1 = compute_mac1(packet, mac1_key)?;
    packet
        .get_mut(mac1_offset..mac1_offset + WIREGUARD_MAC_LEN)?
        .copy_from_slice(&mac1);
    Some(mac1)
}

/// 解析 data message 头部，返回 key_idx、counter 和加密负载。
pub(super) fn parse_data_packet(packet: &[u8]) -> Option<WireguardDataPacket<'_>> {
    if message_type(packet) != Some(WireguardMessageType::Data) {
        return None;
    }
    Some(WireguardDataPacket {
        key_idx: u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]),
        counter: u64::from_le_bytes([
            packet[8], packet[9], packet[10], packet[11], packet[12], packet[13], packet[14],
            packet[15],
        ]),
        encrypted_payload: &packet[MESSAGE_DATA_HEADER_LEN..],
    })
}

/// 构造 data message。`encrypted_payload` 已包含 ChaCha20-Poly1305 tag。
pub(super) fn build_data_packet(key_idx: u32, counter: u64, encrypted_payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(MESSAGE_DATA_HEADER_LEN + encrypted_payload.len());
    packet.extend_from_slice(&MESSAGE_DATA.to_le_bytes());
    packet.extend_from_slice(&key_idx.to_le_bytes());
    packet.extend_from_slice(&counter.to_le_bytes());
    packet.extend_from_slice(encrypted_payload);
    packet
}

/// 把内层 IP 包按 WireGuard data message 要求补零到 16 字节边界。
pub(super) fn pad_data_plaintext(plaintext: &[u8]) -> Vec<u8> {
    let mut padded = plaintext.to_vec();
    padded.resize(padded_data_len(plaintext.len()), 0);
    padded
}

/// 生成 WireGuard initiation 使用的 TAI64N timestamp。
pub(super) fn tai64n_now() -> [u8; NOISE_TIMESTAMP_LEN] {
    let (sec, nsec) = crate::syscall::time_sys::realtime_now_timespec();
    let tai_seconds = TAI64_EPOCH_OFFSET.saturating_add(sec.max(0) as u64);
    let mut out = [0u8; NOISE_TIMESTAMP_LEN];
    out[..8].copy_from_slice(&tai_seconds.to_be_bytes());
    out[8..].copy_from_slice(&(nsec.max(0) as u32).to_be_bytes());
    out
}

/// 从 X25519 private key 推导 public key。全 0 私钥视为无效/清空身份。
pub(super) fn public_key_from_private(
    private_key: [u8; NOISE_PUBLIC_KEY_LEN],
) -> Option<[u8; NOISE_PUBLIC_KEY_LEN]> {
    if private_key.iter().all(|byte| *byte == 0) {
        return None;
    }
    let secret = StaticSecret::from(private_key);
    Some(PublicKey::from(&secret).to_bytes())
}

/// 执行 X25519 DH；全 0 shared secret 表示非法公钥，按协议拒绝。
pub(super) fn x25519_shared_secret(
    private_key: [u8; NOISE_PUBLIC_KEY_LEN],
    public_key: [u8; NOISE_PUBLIC_KEY_LEN],
) -> Option<[u8; NOISE_PUBLIC_KEY_LEN]> {
    let secret = StaticSecret::from(private_key);
    let public = PublicKey::from(public_key);
    let shared = secret.diffie_hellman(&public).to_bytes();
    if shared.iter().all(|byte| *byte == 0) {
        None
    } else {
        Some(shared)
    }
}

/// 生成可用的临时私钥。
pub(super) fn random_private_key() -> [u8; NOISE_PUBLIC_KEY_LEN] {
    loop {
        let key = random_bytes();
        if public_key_from_private(key).is_some() {
            return key;
        }
    }
}

/// 主动端创建 handshake initiation。
///
/// 返回 wire-format 消息、后续消费 response 所需的 Noise 状态，以及本次临时私钥。
pub(super) fn create_handshake_initiation(
    local_public: [u8; NOISE_PUBLIC_KEY_LEN],
    remote_public: [u8; NOISE_PUBLIC_KEY_LEN],
    precomputed_static_static: [u8; NOISE_PUBLIC_KEY_LEN],
    sender_index: u32,
) -> Option<(
    HandshakeInitiation,
    NoiseHandshakeState,
    [u8; NOISE_PUBLIC_KEY_LEN],
)> {
    let mut state = initial_handshake_state(&remote_public);
    let ephemeral_private = random_private_key();
    let ephemeral_public = public_key_from_private(ephemeral_private)?;
    mix_hash(&mut state.hash, &ephemeral_public);
    let _ = mix_key(&mut state.chaining_key, &ephemeral_public);

    // Noise IK 第一段：e, es, s, ss。
    let es = x25519_shared_secret(ephemeral_private, remote_public)?;
    let key = mix_key(&mut state.chaining_key, &es);
    let encrypted_static: [u8; encrypted_len_const(NOISE_PUBLIC_KEY_LEN)] = vec_to_array(
        message_encrypt_and_hash(&local_public, &key, &mut state.hash),
    )?;

    if precomputed_static_static.iter().all(|byte| *byte == 0) {
        return None;
    }
    let key = mix_key(&mut state.chaining_key, &precomputed_static_static);
    let encrypted_timestamp: [u8; encrypted_len_const(NOISE_TIMESTAMP_LEN)] = vec_to_array(
        message_encrypt_and_hash(&tai64n_now(), &key, &mut state.hash),
    )?;

    Some((
        HandshakeInitiation {
            sender_index,
            unencrypted_ephemeral: ephemeral_public,
            encrypted_static,
            encrypted_timestamp,
            mac1: [0; WIREGUARD_MAC_LEN],
            mac2: [0; WIREGUARD_MAC_LEN],
        },
        state,
        ephemeral_private,
    ))
}

/// 被动端尝试用某个已配置 peer 消费 initiation。
///
/// initiation 中的静态公钥是加密的，所以调用方会对每个 peer 逐个尝试；
/// 成功时返回确认过身份和 timestamp 的中间状态。
pub(super) fn consume_handshake_initiation_for_peer(
    msg: &HandshakeInitiation,
    local_private: [u8; NOISE_PUBLIC_KEY_LEN],
    local_public: [u8; NOISE_PUBLIC_KEY_LEN],
    expected_peer_public: [u8; NOISE_PUBLIC_KEY_LEN],
    precomputed_static_static: [u8; NOISE_PUBLIC_KEY_LEN],
    latest_timestamp: &[u8; NOISE_TIMESTAMP_LEN],
) -> Option<ConsumedInitiation> {
    let mut state = initial_handshake_state(&local_public);
    let remote_ephemeral = msg.unencrypted_ephemeral;
    mix_hash(&mut state.hash, &remote_ephemeral);
    let _ = mix_key(&mut state.chaining_key, &remote_ephemeral);

    // 解出对端静态公钥，并确认它就是当前尝试的 peer。
    let es = x25519_shared_secret(local_private, remote_ephemeral)?;
    let key = mix_key(&mut state.chaining_key, &es);
    let peer_static = vec_to_array(message_decrypt_and_hash(
        &msg.encrypted_static,
        &key,
        &mut state.hash,
    )?)?;
    if peer_static != expected_peer_public {
        return None;
    }

    if precomputed_static_static.iter().all(|byte| *byte == 0) {
        return None;
    }
    // timestamp 必须递增，避免旧 initiation 被重放。
    let key = mix_key(&mut state.chaining_key, &precomputed_static_static);
    let timestamp: [u8; NOISE_TIMESTAMP_LEN] = vec_to_array(message_decrypt_and_hash(
        &msg.encrypted_timestamp,
        &key,
        &mut state.hash,
    )?)?;
    if timestamp <= *latest_timestamp {
        return None;
    }

    Some(ConsumedInitiation {
        state,
        remote_static: peer_static,
        remote_ephemeral,
        remote_index: msg.sender_index,
        timestamp,
    })
}

/// 被动端创建 handshake response。
pub(super) fn create_handshake_response(
    initiation: &ConsumedInitiation,
    preshared_key: [u8; NOISE_SYMMETRIC_KEY_LEN],
    sender_index: u32,
) -> Option<(
    HandshakeResponse,
    NoiseHandshakeState,
    [u8; NOISE_PUBLIC_KEY_LEN],
)> {
    let mut state = initiation.state.clone();
    let ephemeral_private = random_private_key();
    let ephemeral_public = public_key_from_private(ephemeral_private)?;
    mix_hash(&mut state.hash, &ephemeral_public);
    let _ = mix_key(&mut state.chaining_key, &ephemeral_public);

    // response 继续执行 ee、se 和可选 PSK，把空明文加密进 transcript。
    let ee = x25519_shared_secret(ephemeral_private, initiation.remote_ephemeral)?;
    let _ = mix_key(&mut state.chaining_key, &ee);
    let se = x25519_shared_secret(ephemeral_private, initiation.remote_static)?;
    let _ = mix_key(&mut state.chaining_key, &se);
    let key = mix_psk(&mut state.chaining_key, &mut state.hash, &preshared_key);
    let encrypted_nothing: [u8; encrypted_len_const(0)] =
        vec_to_array(message_encrypt_and_hash(&[], &key, &mut state.hash))?;

    Some((
        HandshakeResponse {
            sender_index,
            receiver_index: initiation.remote_index,
            unencrypted_ephemeral: ephemeral_public,
            encrypted_nothing,
            mac1: [0; WIREGUARD_MAC_LEN],
            mac2: [0; WIREGUARD_MAC_LEN],
        },
        state,
        ephemeral_private,
    ))
}

/// 主动端消费 handshake response。
pub(super) fn consume_handshake_response(
    msg: &HandshakeResponse,
    mut state: NoiseHandshakeState,
    local_private: [u8; NOISE_PUBLIC_KEY_LEN],
    ephemeral_private: [u8; NOISE_PUBLIC_KEY_LEN],
    preshared_key: [u8; NOISE_SYMMETRIC_KEY_LEN],
) -> Option<ConsumedResponse> {
    let remote_ephemeral = msg.unencrypted_ephemeral;
    mix_hash(&mut state.hash, &remote_ephemeral);
    let _ = mix_key(&mut state.chaining_key, &remote_ephemeral);

    // 主动端用发 initiation 时保存的临时私钥完成 ee/se。
    let ee = x25519_shared_secret(ephemeral_private, remote_ephemeral)?;
    let _ = mix_key(&mut state.chaining_key, &ee);
    let se = x25519_shared_secret(local_private, remote_ephemeral)?;
    let _ = mix_key(&mut state.chaining_key, &se);
    let key = mix_psk(&mut state.chaining_key, &mut state.hash, &preshared_key);
    let decrypted = message_decrypt_and_hash(&msg.encrypted_nothing, &key, &mut state.hash)?;
    if !decrypted.is_empty() {
        return None;
    }

    Some(ConsumedResponse {
        state,
        remote_ephemeral,
        remote_index: msg.sender_index,
    })
}

/// 初始化 Noise transcript。
///
/// initiator 传入 remote static，responder 传入 local static；这和 WireGuard Noise IK
/// 的 transcript 初始化规则一致。
pub(super) fn initial_handshake_state(
    remote_static: &[u8; NOISE_PUBLIC_KEY_LEN],
) -> NoiseHandshakeState {
    let chaining_key = blake2s_hash(&[HANDSHAKE_NAME]);
    let mut hash = blake2s_hash(&[&chaining_key, IDENTIFIER_NAME]);
    mix_hash(&mut hash, remote_static);
    NoiseHandshakeState { chaining_key, hash }
}

/// 从握手 chaining key 派生方向性 data message keypair。
pub(super) fn derive_keypair(
    chaining_key: &[u8; NOISE_HASH_LEN],
    remote_index: u32,
    i_am_the_initiator: bool,
) -> NoiseKeypair {
    let [first, second, _] = kdf(chaining_key, &[], 2);
    let birth_ms = crate::time::get_time_ms();
    let first_key = NoiseSymmetricKey {
        key: first,
        birth_ms,
        is_valid: true,
    };
    let second_key = NoiseSymmetricKey {
        key: second,
        birth_ms,
        is_valid: true,
    };
    let (sending, receiving) = if i_am_the_initiator {
        // initiator 的发送 key 是第一把；responder 方向相反。
        (first_key, second_key)
    } else {
        (second_key, first_key)
    };
    NoiseKeypair {
        sending,
        receiving,
        sending_counter: 0,
        receiving_counter: NoiseReplayCounter::default(),
        remote_index,
        i_am_the_initiator,
    }
}

/// BLAKE2s-256 hash，支持多个连续输入片段。
pub(super) fn blake2s_hash(chunks: &[&[u8]]) -> [u8; NOISE_HASH_LEN] {
    let mut hasher = Blake2s256::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

/// WireGuard 使用的 HMAC-BLAKE2s。
pub(super) fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; NOISE_HASH_LEN] {
    // Linux WireGuard 手写了基于 BLAKE2s-256 的 HMAC；这里保持相同展开方式，
    // 避免依赖 BLAKE2s crate 没有直接暴露的 trait 组合。
    let mut x_key = [0u8; BLAKE2S_BLOCK_SIZE];
    if key.len() > BLAKE2S_BLOCK_SIZE {
        x_key[..NOISE_HASH_LEN].copy_from_slice(&blake2s_hash(&[key]));
    } else {
        x_key[..key.len()].copy_from_slice(key);
    }
    for byte in &mut x_key {
        *byte ^= 0x36;
    }
    let inner_hash = blake2s_hash(&[&x_key, data]);
    for byte in &mut x_key {
        *byte ^= 0x36 ^ 0x5c;
    }
    blake2s_hash(&[&x_key, &inner_hash])
}

/// Noise KDF，最多返回三个 32 字节输出。
pub(super) fn kdf(
    chaining_key: &[u8; NOISE_HASH_LEN],
    input: &[u8],
    outputs: usize,
) -> [[u8; NOISE_HASH_LEN]; 3] {
    debug_assert!((1..=3).contains(&outputs));
    let secret = hmac_blake2s(chaining_key, input);
    let first = hmac_blake2s(&secret, &[1]);
    let second = if outputs >= 2 {
        let mut data = Vec::with_capacity(NOISE_HASH_LEN + 1);
        data.extend_from_slice(&first);
        data.push(2);
        hmac_blake2s(&secret, &data)
    } else {
        [0; NOISE_HASH_LEN]
    };
    let third = if outputs >= 3 {
        let mut data = Vec::with_capacity(NOISE_HASH_LEN + 1);
        data.extend_from_slice(&second);
        data.push(3);
        hmac_blake2s(&secret, &data)
    } else {
        [0; NOISE_HASH_LEN]
    };
    [first, second, third]
}

/// 把新数据混入 transcript hash。
pub(super) fn mix_hash(hash: &mut [u8; NOISE_HASH_LEN], data: &[u8]) {
    *hash = blake2s_hash(&[hash, data]);
}

/// 把 DH 输出混入 chaining key，并派生一把临时 AEAD key。
pub(super) fn mix_key(
    chaining_key: &mut [u8; NOISE_HASH_LEN],
    input: &[u8],
) -> [u8; NOISE_SYMMETRIC_KEY_LEN] {
    let [new_chaining_key, key, _] = kdf(chaining_key, input, 2);
    *chaining_key = new_chaining_key;
    key
}

/// 混入 preshared key，同时更新 chaining key 和 transcript hash。
pub(super) fn mix_psk(
    chaining_key: &mut [u8; NOISE_HASH_LEN],
    hash: &mut [u8; NOISE_HASH_LEN],
    psk: &[u8; NOISE_SYMMETRIC_KEY_LEN],
) -> [u8; NOISE_SYMMETRIC_KEY_LEN] {
    let [new_chaining_key, temp_hash, key] = kdf(chaining_key, psk, 3);
    *chaining_key = new_chaining_key;
    mix_hash(hash, &temp_hash);
    key
}

/// 握手阶段的 AEAD 加密：associated data 是当前 transcript hash，密文再混入 hash。
pub(super) fn message_encrypt_and_hash(
    plaintext: &[u8],
    key: &[u8; NOISE_SYMMETRIC_KEY_LEN],
    hash: &mut [u8; NOISE_HASH_LEN],
) -> Vec<u8> {
    let ciphertext = aead_encrypt(plaintext, hash, 0, key);
    mix_hash(hash, &ciphertext);
    ciphertext
}

/// 握手阶段的 AEAD 解密，成功后把密文混入 transcript hash。
pub(super) fn message_decrypt_and_hash(
    ciphertext: &[u8],
    key: &[u8; NOISE_SYMMETRIC_KEY_LEN],
    hash: &mut [u8; NOISE_HASH_LEN],
) -> Option<Vec<u8>> {
    let plaintext = aead_decrypt(ciphertext, hash, 0, key)?;
    mix_hash(hash, ciphertext);
    Some(plaintext)
}

/// ChaCha20-Poly1305 加密，返回 ciphertext || tag。
pub(super) fn aead_encrypt(
    plaintext: &[u8],
    associated_data: &[u8],
    counter: u64,
    key: &[u8; NOISE_SYMMETRIC_KEY_LEN],
) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut out = plaintext.to_vec();
    let nonce = nonce_from_counter(counter);
    let Ok(tag) =
        cipher.encrypt_in_place_detached(Nonce::from_slice(&nonce), associated_data, &mut out)
    else {
        return Vec::new();
    };
    out.extend_from_slice(&tag);
    out
}

/// ChaCha20-Poly1305 解密，输入格式为 ciphertext || tag。
pub(super) fn aead_decrypt(
    ciphertext: &[u8],
    associated_data: &[u8],
    counter: u64,
    key: &[u8; NOISE_SYMMETRIC_KEY_LEN],
) -> Option<Vec<u8>> {
    if ciphertext.len() < NOISE_AUTHTAG_LEN {
        return None;
    }
    let text_len = ciphertext.len() - NOISE_AUTHTAG_LEN;
    let (text, tag) = ciphertext.split_at(text_len);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = nonce_from_counter(counter);
    let mut out = text.to_vec();
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            associated_data,
            &mut out,
            Tag::from_slice(tag),
        )
        .ok()?;
    Some(out)
}

/// 明文长度加认证 tag 后的密文长度。
pub(super) fn encrypted_len(plain_len: usize) -> usize {
    plain_len.saturating_add(NOISE_AUTHTAG_LEN)
}

/// WireGuard data message 明文补零后的长度。
pub(super) fn padded_data_len(plain_len: usize) -> usize {
    plain_len.div_ceil(MESSAGE_PADDING_MULTIPLE) * MESSAGE_PADDING_MULTIPLE
}

/// data message 总长度：头部 + 加密后的 padded plaintext。
pub(super) fn message_data_len(plain_len: usize) -> usize {
    MESSAGE_DATA_HEADER_LEN.saturating_add(encrypted_len(plain_len))
}

/// WireGuard nonce 前 4 字节为 0，后 8 字节为 little-endian counter。
fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// 从固定偏移读取定长数组。
fn read_array<const N: usize>(packet: &[u8], start: usize) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    out.copy_from_slice(packet.get(start..start.checked_add(N)?)?);
    Some(out)
}

/// Vec 转定长数组，长度不匹配时失败。
fn vec_to_array<const N: usize>(data: Vec<u8>) -> Option<[u8; N]> {
    if data.len() != N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&data);
    Some(out)
}

/// 简单伪随机字节生成器。
///
/// 只用于测试环境里的 WireGuard 临时 key；真实内核不能用这种 RNG。
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut seed = WG_RNG_STATE.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed)
        ^ crate::time::get_time_ns();
    let mut out = [0u8; N];
    for byte in &mut out {
        seed ^= seed >> 12;
        seed ^= seed << 25;
        seed ^= seed >> 27;
        seed = seed.wrapping_mul(0x2545_f491_4f6c_dd1d);
        *byte = seed as u8;
    }
    WG_RNG_STATE.store(seed, Ordering::Relaxed);
    out
}

/// 返回握手包中 mac1/mac2 字段偏移。
fn handshake_mac_offsets(packet: &[u8]) -> Option<(usize, usize)> {
    match message_type(packet)? {
        WireguardMessageType::HandshakeInitiation => Some((INITIATION_MAC1, INITIATION_MAC2)),
        WireguardMessageType::HandshakeResponse => Some((RESPONSE_MAC1, RESPONSE_MAC2)),
        _ => None,
    }
}

/// BLAKE2s keyed MAC 截断到 16 字节，用于 WireGuard mac1/mac2。
fn blake2s_keyed_128(key: &[u8; NOISE_SYMMETRIC_KEY_LEN], data: &[u8]) -> [u8; WIREGUARD_MAC_LEN] {
    let mut mac = Blake2sMac128::new_from_slice(key).unwrap();
    blake2::digest::Update::update(&mut mac, data);
    let digest = blake2::digest::FixedOutput::finalize_fixed(mac);
    let mut out = [0u8; WIREGUARD_MAC_LEN];
    out.copy_from_slice(&digest);
    out
}

/// 常量时间比较，避免 MAC 比较被短路时序泄漏。
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}
