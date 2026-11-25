//! 默认关闭的私有材料损坏夹具；只修改当前未安装 R0 的一个 bundle 存储值。
//! 不输出秘密，不改公开材料或正常入口；随后必须用正常程序重载和 Apply。
use super::{
    checked, codec, ensure, join_recovery_state as stored, permission_state, state::DeviceState,
    store::LockedDevice, Context, CrashPoint, LabError,
};
use openmls::prelude::{tls_codec::Serialize as TlsSerialize, KeyPackageBundle};
use openmls_traits::{storage::CURRENT_VERSION, OpenMlsProvider};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    CorruptEncoding,
    CorruptInitKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    directory: PathBuf,
    context: Context,
    key_package_sha256: String,
    mode: Mode,
}

fn hash(value: &[u8]) -> String {
    crate::permission::commit_digest(value)
}

fn metadata(state: &DeviceState) -> Result<String, LabError> {
    let mut value = checked("probe", serde_json::to_value(state))?;
    value
        .as_object_mut()
        .ok_or_else(|| LabError::new("probe", "缺少快照对象"))?
        .remove("provider_entries");
    Ok(hash(&checked("probe", serde_json::to_vec(&value))?))
}

fn absent(path: &Path) -> Result<(), LabError> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LabError::new("probe", error.to_string())),
        Ok(_) => Err(LabError::new("probe", "夹具不能改写已绑定独立锚的目录")),
    }
}

fn unanchored(input: &Input) -> Result<(), LabError> {
    ensure(input.directory.is_absolute(), "probe", "需要绝对夹具目录")?;
    for name in ["state.enc", "device.key"] {
        let file = checked(
            "probe",
            std::fs::symlink_metadata(input.directory.join(name)),
        )?;
        ensure(file.is_file(), "probe", "只允许已存在的私有快照和设备密钥")?;
    }
    for name in [
        "RIM_ROLLBACK_ANCHOR_CONFIG",
        "RIM_TRUSTED_STARTUP_CONFIG",
        "RIM_TRUSTED_STARTUP_REQUIRED",
    ] {
        ensure(
            std::env::var_os(name).is_none(),
            "probe",
            "必须使用未绑定锚或可信启动器的隔离夹具",
        )?;
    }
    for name in ["anchor-gate.enc", "anchor-journal.enc"] {
        absent(&input.directory.join(name))?;
    }
    let parent = input
        .directory
        .parent()
        .ok_or_else(|| LabError::new("probe", "缺少夹具父目录"))?;
    // 联合装置的锚配置在设备目录之外；不得仅清除环境变量后改写原设备。
    for prefix in ["trusted-", "authority-"] {
        absent(&parent.join(format!("{prefix}{}", input.context.device)))?;
    }
    Ok(())
}

fn selected_package(state: &DeviceState, wanted: &str) -> Result<String, LabError> {
    ensure(
        state.group_id.is_none()
            && state.permissions.checkpoint.is_none()
            && state.permissions.admission.joined_record.is_none(),
        "probe",
        "只允许尚未安装群的目标设备",
    )?;
    let mut selected = None;
    for accepted in stored::get(state)?.records.values() {
        let intent = crate::join_recovery::parse_intent(&accepted.record.public().bundle.intent)?;
        if intent.key_package_sha256 == wanted {
            ensure(
                selected.is_none() && !accepted.installed && accepted.record.full().is_some(),
                "probe",
                "需要唯一未安装的完整 R0",
            )?;
            selected = Some(&accepted.record);
        }
    }
    let record = selected.ok_or_else(|| LabError::new("probe", "指定材料没有已观察 R0"))?;
    let ready = super::join_recovery_preflight::check(state, record)?
        .ok_or_else(|| LabError::new("probe", "R0 已安装"))?;
    ensure(
        ready.own_target && ready.statement.action.key_package_sha256 == wanted,
        "probe",
        "只能损坏本机当前恢复的新材料",
    )?;
    let package = state
        .key_packages
        .as_ref()
        .and_then(|pool| pool.packages.get(wanted))
        .ok_or_else(|| LabError::new("probe", "缺少指定私有材料"))?;
    ensure(!package.consumed, "probe", "不能损坏已消费材料")?;
    Ok(package.encoded.clone())
}

fn corrupt(raw: &[u8], mode: Mode, public: &[u8]) -> Result<Vec<u8>, LabError> {
    let bundle: KeyPackageBundle = checked("probe", serde_json::from_slice(raw))?;
    ensure(
        checked("probe", bundle.key_package().tls_serialize_detached())? == public,
        "probe",
        "存储键没有指向准确公开材料",
    )?;
    let mut value = checked("probe", serde_json::to_value(&bundle))?;
    let original_public = value["key_package"].clone();
    let original_encryption = value["private_encryption_key"].clone();
    match mode {
        Mode::CorruptEncoding => {
            value["private_init_key"] = json!("synthetic-invalid-private-key-encoding");
        }
        Mode::CorruptInitKey => {
            // 锁定 serde 链：HpkePrivateKey → SecretVLBytes → VLBytes { vec }。
            // 改 X25519 中间字节；首尾 clamping 丢弃位不能构成有效负例。
            let bytes = value["private_init_key"]["vec"]
                .as_array_mut()
                .ok_or_else(|| LabError::new("probe", "私钥编码结构不匹配锁定库"))?;
            ensure(bytes.len() == 32, "probe", "需要准确 X25519 私钥长度")?;
            let byte = bytes[16]
                .as_u64()
                .filter(|v| *v <= 255)
                .ok_or_else(|| LabError::new("probe", "私钥字节编码错误"))?;
            bytes[16] = json!(byte ^ 1);
        }
    }
    ensure(
        value["key_package"] == original_public
            && value["private_encryption_key"] == original_encryption,
        "probe",
        "夹具越界修改公开材料或另一私钥",
    )?;
    let changed = checked("probe", serde_json::to_vec(&value))?;
    let decoded = serde_json::from_slice::<KeyPackageBundle>(&changed);
    ensure(
        match mode {
            Mode::CorruptEncoding => decoded.is_err(),
            Mode::CorruptInitKey => decoded.is_ok(),
        },
        "probe",
        "损坏模式未命中指定序列化边界",
    )?;
    Ok(changed)
}

/// 仅接收有界合成夹具请求；成功输出只含摘要、计数和公开材料标识。
pub fn seed(input: &str) -> Result<Value, LabError> {
    ensure(input.len() <= 16384, "probe", "夹具输入过大")?;
    let input: Input = checked("probe", serde_json::from_str(input))?;
    codec::identity_context(&input.context)?;
    unanchored(&input)?;
    let locked = LockedDevice::open(&input.directory)?;
    let mut state = locked
        .load(&input.context)?
        .ok_or_else(|| LabError::new("probe", "缺少既有快照"))?;
    let public = codec::decode(&selected_package(&state, &input.key_package_sha256)?)?;
    let reference = checked(
        "probe",
        openmls::ciphersuite::hash_ref::make_key_package_ref(
            &public,
            codec::CIPHERSUITE,
            state.provider.crypto(),
        ),
    )?;
    // 锁定 MemoryStorage::build_key_from_vec：label + JSON(ref) + u16版本。
    let mut key = b"KeyPackage".to_vec();
    key.extend(checked("probe", serde_json::to_vec(&reference))?);
    key.extend(CURRENT_VERSION.to_be_bytes());
    let before = permission_state::entries(&state.provider)?;
    let entry_before = before
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
        .ok_or_else(|| LabError::new("probe", "精确 bundle 存储行缺失"))?;
    let entry_after = corrupt(entry_before, input.mode, &public)?;
    let metadata_before = metadata(&state)?;
    {
        let mut values = state
            .provider
            .storage()
            .values
            .write()
            .map_err(|_| LabError::new("probe", "存储锁失效"))?;
        ensure(
            values.get(&key) == Some(entry_before),
            "probe",
            "存储行已变化",
        )?;
        values.insert(key.clone(), entry_after.clone());
    }
    let after = permission_state::entries(&state.provider)?;
    let others = |entries: &[(Vec<u8>, Vec<u8>)]| {
        let retained: Vec<_> = entries.iter().filter(|(k, _)| *k != key).collect();
        checked("probe", serde_json::to_vec(&retained)).map(|raw| hash(&raw))
    };
    let other_before = others(&before)?;
    let other_after = others(&after)?;
    let changed_entries = before.iter().zip(&after).filter(|(a, b)| a != b).count();
    let metadata_after = metadata(&state)?;
    ensure(
        before.len() == after.len()
            && changed_entries == 1
            && other_before == other_after
            && metadata_before == metadata_after,
        "probe",
        "损坏超出唯一 bundle 存储值",
    )?;
    if matches!(input.mode, Mode::CorruptInitKey) {
        super::key_package_state::validate(&state, true)?;
    }
    locked.save(&mut state, CrashPoint::None)?;
    Ok(json!({"synthetic":true,"mode":input.mode,
        "key_package_sha256":input.key_package_sha256,"changed_entries":changed_entries,
        "metadata_before_sha256":metadata_before,"metadata_after_sha256":metadata_after,
        "other_entries_before_sha256":other_before,"other_entries_after_sha256":other_after,
        "entry_before_sha256":hash(entry_before),"entry_after_sha256":hash(&entry_after),
        "provider_entry_count":before.len(),"public_package_unchanged":true}))
}
