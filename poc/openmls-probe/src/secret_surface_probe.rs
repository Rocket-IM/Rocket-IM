//! 只读加载隔离合成快照；所有秘密仅留在观察进程内存，报告不包含原值。
#[path = "secret_surface_probe_scan.rs"]
mod scan;
#[cfg(test)]
#[path = "secret_surface_probe_tests.rs"]
mod tests;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

pub const MAX_INPUT_BYTES: usize = 256 * 1024;
const MAX_FILE_BYTES: usize = 32 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 128 * 1024 * 1024;
type Result<T> = std::result::Result<T, &'static str>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    root: PathBuf,
    devices: Vec<Device>,
    files: Vec<Surface>,
    plaintexts: Vec<String>,
    #[serde(default)]
    markers: Vec<Marker>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    name: String,
    base64: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Device {
    name: String,
    directory: PathBuf,
    context: Context,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Context {
    service: String,
    account: String,
    device: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Surface {
    label: String,
    path: PathBuf,
}

pub fn run(input: &[u8]) -> Result<Value> {
    if input.len() > MAX_INPUT_BYTES {
        return Err("input_limit");
    }
    let request: Request = serde_json::from_slice(input).map_err(|_| "input_schema")?;
    if request.devices.is_empty()
        || request.devices.len() > 16
        || request.files.len() > 256
        || request.plaintexts.len() > 16
        || request.markers.len() > 32
    {
        return Err("input_count");
    }
    let root = checked_root(&request.root)?;
    let mut needles = Vec::new();
    let mut coverage = Vec::new();
    let mut names = BTreeSet::new();
    for device in &request.devices {
        label(&device.name)?;
        if !names.insert(&device.name) {
            return Err("duplicate_device");
        }
        coverage.push(device_needles(&root, device, &mut needles)?);
    }
    for plaintext in request.plaintexts {
        scan::add(&mut needles, "plaintext", "harness", plaintext.into_bytes())?;
    }
    for marker in request.markers {
        label(&marker.name)?;
        let bytes = STANDARD
            .decode(marker.base64)
            .map_err(|_| "marker_encoding")?;
        scan::add(&mut needles, "marker", &marker.name, bytes)?;
    }
    let patterns = scan::patterns(&needles)?;
    let controls = scan::controls(&needles)?;
    let mut surfaces = Vec::new();
    let mut total = 0;
    let mut labels = BTreeSet::new();
    for surface in request.files {
        label(&surface.label)?;
        if !labels.insert(surface.label.clone()) {
            return Err("duplicate_surface");
        }
        let bytes = read_file(&root, &surface.path, MAX_FILE_BYTES)?;
        total += bytes.len();
        if total > MAX_TOTAL_BYTES {
            return Err("surface_total_limit");
        }
        let hits = scan::scan(&bytes, &patterns)?;
        surfaces.push(json!({"label":surface.label,"bytes":bytes.len(),
            "sha256":scan::digest(&bytes),"hits":hits}));
    }
    Ok(
        json!({"secret_coverage":coverage,"needle_count":needles.len(),
        "pattern_count":patterns.len(),"surfaces":surfaces,"controls":controls,
        "scanned_bytes":total,"scope":"synthetic_local_exact_samples_bounded_encodings"}),
    )
}

fn label(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 96
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-/".contains(&b))
    {
        return Err("label");
    }
    Ok(())
}

fn checked_root(root: &Path) -> Result<PathBuf> {
    if !root.is_absolute()
        || root.components().any(|c| matches!(c, Component::ParentDir))
        || fs::canonicalize(root).map_err(|_| "root")? != root
    {
        return Err("root");
    }
    let metadata = fs::symlink_metadata(root).map_err(|_| "root")?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err("root_permissions");
    }
    Ok(root.to_path_buf())
}

fn checked_path(root: &Path, path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path == root
        || !path.starts_with(root)
        || path.components().any(|c| matches!(c, Component::ParentDir))
        || fs::canonicalize(path).map_err(|_| "surface_path")? != path
    {
        return Err("surface_path");
    }
    Ok(())
}

fn read_file(root: &Path, path: &Path, limit: usize) -> Result<Vec<u8>> {
    checked_path(root, path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "surface_read")?;
    let metadata = file.metadata().map_err(|_| "surface_metadata")?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("surface_file_limit");
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "surface_read")?;
    if bytes.len() > limit || bytes.len() as u64 != metadata.len() {
        return Err("surface_file_changed");
    }
    Ok(bytes)
}

fn device_needles(root: &Path, device: &Device, needles: &mut Vec<scan::Needle>) -> Result<Value> {
    checked_path(root, &device.directory)?;
    let key: [u8; 32] = read_file(root, &device.directory.join("device.key"), 32)?
        .try_into()
        .map_err(|_| "snapshot_key_length")?;
    let path = device.directory.join("state.enc");
    checked_path(root, &path)?;
    let before = read_file(root, &path, MAX_FILE_BYTES)?;
    let context =
        serde_json::to_vec(&("Rocket-IM/state-lab/v1", &device.context)).map_err(|_| "context")?;
    let plaintext =
        openmls_probe::snapshot::load(&path, &key, &context).map_err(|_| "snapshot_load")?;
    let state: Value = serde_json::from_slice(&plaintext).map_err(|_| "snapshot_json")?;
    if state.get("version") != Some(&json!(1))
        || state.get("context")
            != Some(&serde_json::to_value(&device.context).map_err(|_| "context")?)
        || before != read_file(root, &path, MAX_FILE_BYTES)?
    {
        return Err("snapshot_context_or_changed");
    }
    scan::add(needles, "snapshot_key", &device.name, key.to_vec())?;
    let entries = state
        .get("provider_entries")
        .and_then(Value::as_array)
        .ok_or("provider_entries")?;
    for entry in entries {
        let pair = entry
            .as_array()
            .filter(|p| p.len() == 2)
            .ok_or("provider_entry")?;
        let key = byte_array(&pair[0]).ok_or("provider_key")?;
        let raw = byte_array(&pair[1]).ok_or("provider_value")?;
        let category = if key.starts_with(b"SignatureKeyPair") {
            "signature_private"
        } else if [
            b"EpochKeyPairs".as_slice(),
            b"EncryptionKeyPair",
            b"KeyPackage",
        ]
        .iter()
        .any(|label| key.starts_with(label))
        {
            "hpke_private"
        } else if key.starts_with(b"EpochSecrets") || key.starts_with(b"MessageSecrets") {
            "mls_secret"
        } else {
            continue;
        };
        let value: Value = serde_json::from_slice(&raw).map_err(|_| "provider_json")?;
        private_values(&value, category, &device.name, false, 0, needles)?;
    }
    let mut counts = serde_json::Map::new();
    for category in [
        "snapshot_key",
        "signature_private",
        "hpke_private",
        "mls_secret",
    ] {
        let count = needles
            .iter()
            .filter(|n| n.device == device.name && n.category == category)
            .count();
        if count == 0 {
            return Err("secret_coverage_missing");
        }
        counts.insert(category.into(), json!(count));
    }
    Ok(json!({"device":device.name,"samples":counts,"state_sha256":scan::digest(&before)}))
}

fn private_values(
    value: &Value,
    category: &'static str,
    device: &str,
    sensitive: bool,
    depth: usize,
    needles: &mut Vec<scan::Needle>,
) -> Result<()> {
    if depth > 48 {
        return Err("provider_depth");
    }
    if sensitive {
        if let Some(bytes) = byte_array(value) {
            if (16..=128).contains(&bytes.len()) {
                scan::add(needles, category, device, bytes)?;
            }
            return Ok(());
        }
    }
    match value {
        Value::Object(object) => {
            for (name, child) in object {
                let marked = sensitive
                    || match category {
                        "signature_private" => name == "private",
                        "hpke_private" => name.contains("private"),
                        "mls_secret" => matches!(
                            name.as_str(),
                            "secret"
                                | "init_secret"
                                | "exporter_secret"
                                | "external_secret"
                                | "resumption_psk"
                                | "sender_data_secret"
                                | "membership_key"
                                | "confirmation_key"
                                | "secret_tree"
                        ),
                        _ => false,
                    };
                // epoch_authenticator 是确认材料；本观测器不把它冒充用户解密钥。
                if category != "mls_secret" || name != "epoch_authenticator" {
                    private_values(child, category, device, marked, depth + 1, needles)?;
                }
            }
        }
        Value::Array(array) => {
            for child in array {
                private_values(child, category, device, sensitive, depth + 1, needles)?;
            }
        }
        _ => (),
    }
    Ok(())
}

fn byte_array(value: &Value) -> Option<Vec<u8>> {
    value
        .as_array()?
        .iter()
        .map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
        .collect()
}
