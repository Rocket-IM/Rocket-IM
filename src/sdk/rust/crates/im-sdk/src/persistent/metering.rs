//! 生产序列化及既有硬限额的单一来源；诊断与有限预留复用原预算。
use super::{data::Saved, types::*};

pub(super) const MAX_REQUESTS: usize = 1024;
pub(super) const MAX_MESSAGES: usize = 256;
pub(super) const MAX_EVENTS: usize = 512;
pub(super) const MAX_ROUNDS: usize = 16;
pub(super) const MAX_CRYPTO: usize = 4 * 1024 * 1024;
pub(super) const RECOVERY_GROWTH: usize = 8 * 1024 * 1024;
pub(super) const MIN_GROWTH: usize = 1024 * 1024;

pub(super) struct EncodedSaved {
    pub data: Vec<u8>,
    pub meta: Vec<u8>,
    pub crypto: usize,
}
impl EncodedSaved {
    pub fn new(saved: &Saved) -> Result<Self> {
        Ok(Self {
            data: encode(&saved.data)?,
            meta: encode(&saved.meta)?,
            crypto: saved.crypto.len(),
        })
    }
    pub fn data_preflight_exceeded(&self, growth: usize) -> bool {
        self.data.len().saturating_add(growth) > super::data::MAX_DATA
    }
    pub fn meta_preflight_exceeded(&self, growth: usize) -> bool {
        // 保留原准入公式。候选真实数组编码另在诊断包含项中计量，不能偷换原门限。
        self.meta
            .len()
            .saturating_add(self.data.len())
            .saturating_add(self.crypto)
            .saturating_add(growth)
            > super::store::MAX_META
    }
}

pub(super) fn growth(action: &Action) -> Result<usize> {
    Ok(encode(action)?.len().saturating_mul(6).max(MIN_GROWTH))
}

/// 顺序固定，诊断、预留和写入共用同一预算与编码。
pub(super) const RESOURCES: [(&str, &str, usize); 9] = [
    ("requests", "items", MAX_REQUESTS),
    ("ordinary_messages", "items", MAX_MESSAGES),
    ("events", "items", MAX_EVENTS),
    ("data_bytes", "bytes", super::data::MAX_DATA),
    ("crypto_bytes", "bytes", MAX_CRYPTO),
    ("meta_bytes", "bytes", super::store::MAX_META),
    ("history", "items", MAX_ROUNDS),
    ("archives", "items", MAX_ROUNDS),
    ("transitions", "items", MAX_ROUNDS),
];
pub(super) fn usage(s: &Saved) -> Result<[usize; 9]> {
    let e = EncodedSaved::new(s)?;
    Ok([
        s.data.requests.len(),
        s.data.messages.len(),
        super::network::capacity(s, &e)?.events,
        e.data.len(),
        e.crypto,
        e.meta.len(),
        s.meta.history.len(),
        s.meta.archives.len(),
        s.data.transitions.len(),
    ])
}
