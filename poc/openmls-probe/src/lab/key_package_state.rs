//! 与原加密快照共同保存的材料、请求和候选目录；没有迁移推测库存。
use super::{checked, codec, ensure, state::DeviceState, LabError};
use crate::{
    key_package::{self as protocol, material::Material},
    permission::receipts::SignedRecord,
};
use openmls::prelude::{tls_codec::Serialize as TlsSerialize, *};
use openmls_traits::{storage::StorageProvider, OpenMlsProvider};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Package {
    pub encoded: String,
    pub material: Material,
    pub consumed: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    pub proof: SignedRecord,
    pub source_key: String,
    pub receipt: Option<SignedRecord>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Directory {
    pub snapshots: Vec<String>,
    pub conflict: bool,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub source_key: Option<String>,
    pub packages: BTreeMap<String, Package>,
    pub requests: BTreeMap<String, Intent>,
    pub directories: BTreeMap<String, Directory>,
}
pub(super) fn own(state: &DeviceState) -> crate::permission::Member {
    crate::permission::Member {
        account_id: state.context.account.clone(),
        device_id: state.context.device.clone(),
        signature_key: codec::encode(&state.own_signature_key),
    }
}
pub(super) fn budget(state: &State) -> Result<(), LabError> {
    ensure(
        state.packages.len() <= 32
            && state.requests.len() <= 64
            && state.directories.len() <= 16
            && checked("key_package_encoding", serde_json::to_vec(state))?.len() <= 2 * 1024 * 1024,
        "resource_exhausted",
        "生命周期账本已满",
    )
}
pub(super) fn validate(state: &DeviceState, provider: bool) -> Result<(), LabError> {
    let Some(pool) = &state.key_packages else {
        return Ok(());
    };
    budget(pool)?;
    for (id, intent) in &pool.requests {
        let request = protocol::parse(&intent.proof)?;
        ensure(
            request.request_id == *id
                && request.actor == own(state)
                && request.service_id == state.context.service,
            "key_package_state",
            "请求归属不符",
        )?;
        crate::permission::receipts::validate_key(&intent.source_key)?;
        ensure(
            pool.source_key.as_ref() == Some(&intent.source_key),
            "key_package_source",
            "固定来源不符",
        )?;
        if let Some(receipt) = &intent.receipt {
            let receipt = protocol::verify_receipt(&intent.source_key, receipt)?;
            ensure(
                receipt.request_sha256 == protocol::digest(&intent.proof)?
                    && receipt.service_id == state.context.service,
                "key_package_state",
                "结果绑定不符",
            )?;
        }
    }
    for (hash, package) in &pool.packages {
        ensure(
            *hash == crate::permission::commit_digest(&codec::decode(&package.encoded)?)
                && *hash == package.material.key_package_sha256,
            "key_package_state",
            "材料摘要损坏",
        )?;
        if provider {
            let reference = openmls::ciphersuite::hash_ref::make_key_package_ref(
                &codec::decode(&package.encoded)?,
                codec::CIPHERSUITE,
                state.provider.crypto(),
            )
            .map_err(|_| LabError::new("key_package_state", "引用错误"))?;
            let bundle: Option<KeyPackageBundle> = checked(
                "key_package_storage",
                state.provider.storage().key_package(&reference),
            )?;
            if package.consumed {
                ensure(
                    bundle.is_none(),
                    "key_package_state",
                    "消费后的bundle仍在活动存储",
                )?;
            } else {
                let bundle = bundle.ok_or_else(|| {
                    LabError::new("key_package_missing", "未消费材料缺少私有bundle")
                })?;
                ensure(
                    checked(
                        "key_package_encoding",
                        bundle.key_package().tls_serialize_detached(),
                    )? == codec::decode(&package.encoded)?
                        && protocol::material::metadata(bundle.key_package())? == package.material
                        && bundle.key_package().leaf_node().signature_key().as_slice()
                            == state.own_signature_key,
                    "key_package_state",
                    "bundle与持久原件不一致",
                )?;
            }
        }
    }
    for (account, directory) in &pool.directories {
        let mut previous: Option<(crate::key_package::directory::Snapshot, String)> = None;
        for encoded in &directory.snapshots {
            let current = protocol::directory::parse(encoded)?;
            ensure(
                current.service_id == state.context.service && current.account_id == *account,
                "directory_invalid",
                "目录归属不符",
            )?;
            if let Some((ref old, ref old_encoded)) = previous {
                protocol::directory::successor(old, &current)?;
                ensure(
                    current.previous_sha256 == protocol::directory::hash(old_encoded)?,
                    "directory_gap",
                    "目录链断裂",
                )?;
            } else {
                ensure(
                    current.version == "1" && current.previous_sha256 == "0".repeat(64),
                    "directory_gap",
                    "目录缺少起点",
                )?;
            }
            previous = Some((current, encoded.clone()));
        }
        ensure(previous.is_some(), "directory_invalid", "空目录链")?;
    }
    Ok(())
}
