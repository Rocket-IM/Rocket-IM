//! 原 UTF-8 是摘要/签名对象；先拒绝所有层级重键，再做严格类型解析。
use super::*;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::{collections::BTreeSet, fmt};

struct UniqueJson;
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("无重键 JSON")
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                while a.next_element::<UniqueJson>()?.is_some() {}
                Ok(UniqueJson)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut keys = BTreeSet::new();
                while let Some(key) = a.next_key::<String>()? {
                    if !keys.insert(key) {
                        return Err(de::Error::custom("重复 JSON 字段"));
                    }
                    a.next_value::<UniqueJson>()?;
                }
                Ok(UniqueJson)
            }
        }
        d.deserialize_any(UniqueVisitor)
    }
}
pub fn parse_bytes<T: DeserializeOwned>(bytes: &[u8], max: usize) -> Result<T, PermissionError> {
    require(
        !bytes.is_empty() && bytes.len() <= max,
        "resource_exhausted",
    )?;
    let invalid = |_| PermissionError::new("recovery_invalid", "原 JSON 编码或严格结构无效");
    serde_json::from_slice::<UniqueJson>(bytes).map_err(invalid)?;
    serde_json::from_slice(bytes).map_err(invalid)
}
pub fn decode<T: DeserializeOwned>(encoded: &str, max: usize) -> Result<T, PermissionError> {
    parse_bytes(&scalar::bytes(encoded, max)?, max)
}
/// 入站封装必须为固定字段顺序紧凑 JSON；预算按完整 UTF-8 字节计。
pub fn parse_signed_wire(bytes: &[u8], max: usize) -> Result<SignedRecord, PermissionError> {
    let record: SignedRecord = parse_bytes(bytes, max)?;
    require(
        serde_json::to_vec(&record)
            .map_err(|_| PermissionError::new("recovery_invalid", "封装无效"))?
            == bytes,
        "recovery_invalid",
    )?;
    signed_budget(&record, max)?;
    Ok(record)
}
pub(super) fn signed_budget(record: &SignedRecord, max: usize) -> Result<(), PermissionError> {
    scalar::bytes(&record.statement_bytes, 16384)?;
    require(
        scalar::bytes(&record.signature_bytes, 64)?.len() == 64,
        "recovery_invalid",
    )?;
    let bytes = serde_json::to_vec(record)
        .map_err(|_| PermissionError::new("recovery_invalid", "封装无效"))?;
    require(bytes.len() <= max, "resource_exhausted")
}
