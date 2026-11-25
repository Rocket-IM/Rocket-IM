//! 仅测试构建：在 Rust 内抽样实际快照/密钥并扫描受保护文件，不导出原始秘密。
use super::*;
use crate::persistent::data::Saved;
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn samples(value: &Value, output: &mut BTreeSet<Vec<u8>>, depth: usize) {
    if depth > 20 {
        return;
    }
    match value {
        Value::String(text) if text.len() >= 16 => {
            output.insert(text.as_bytes().to_vec());
        }
        Value::Array(values) => {
            if values.len() >= 16 && values.iter().all(|v| v.as_u64().is_some_and(|n| n <= 255)) {
                let bytes: Vec<u8> = values
                    .iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u8))
                    .collect();
                output.insert(bytes.clone());
                output.insert(hex(&bytes).into_bytes());
                output.insert(serde_json::to_vec(values).unwrap_or_default());
                if let Ok(nested) = serde_json::from_slice::<Value>(&bytes) {
                    samples(&nested, output, depth + 1);
                }
            }
            for value in values {
                samples(value, output, depth + 1);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                samples(value, output, depth + 1);
            }
        }
        _ => {}
    }
}
impl Protection {
    pub(in crate::persistent) fn audit(&self, saved: &Saved, include_key: bool) -> Result<Value> {
        let mut needles = BTreeSet::new();
        for bytes in [
            encode(&saved.data)?,
            saved.crypto.clone(),
            encode(&saved.meta)?,
        ] {
            if let Ok(value) = serde_json::from_slice(&bytes) {
                samples(&value, &mut needles, 0);
            }
        }
        if include_key {
            let (mut record, _) = self.record()?;
            let key = Zeroizing::new(
                record
                    .key
                    .take()
                    .ok_or_else(|| Error::paused("logged_out"))?,
            );
            needles.insert(key.as_bytes().to_vec());
            needles.insert(unhex(&key, 32)?);
        }
        let mut paths = vec![self.path.clone(), self.keychain.clone()];
        if let Ok(input) = std::env::var("ROCKET_IM_TEST_AUDIT_PATHS") {
            let extra: Vec<PathBuf> =
                serde_json::from_str(&input).map_err(|_| Error::new("audit_paths_invalid"))?;
            if extra.len() > 512 {
                return Err(Error::new("audit_paths_invalid"));
            }
            paths.extend(extra);
        }
        for suffix in ["-journal", "-wal", "-shm"] {
            paths.push(PathBuf::from(format!("{}{suffix}", self.path.display())));
        }
        if let Some(parent) = self.keychain.parent() {
            for entry in fs::read_dir(parent).map_err(|_| Error::new("audit_read_failed"))? {
                let entry = entry.map_err(|_| Error::new("audit_read_failed"))?;
                if entry.file_name().to_string_lossy().starts_with('.') {
                    paths.push(entry.path());
                }
            }
        }
        let mut files = Vec::new();
        for path in paths {
            if !path.is_file() {
                continue;
            }
            let data = fs::read(&path).map_err(|_| Error::new("audit_read_failed"))?;
            let hits = needles
                .iter()
                .filter(|n| n.len() >= 16 && data.windows(n.len()).any(|w| w == n.as_slice()))
                .count();
            files.push(json!({"path":path,"bytes":data.len(),"matches":hits,"sha256":hash(&data)}));
        }
        let result = json!({"sample_count":needles.len(),"files":files,
            "budgets":{"normal_messages":saved.data.messages.len(),
                "rejected_sends":saved.data.requests.values().filter(|r|r.rejection.is_some()).count(),
                "requests":saved.data.requests.len(),"data_bytes":encode(&saved.data)?.len(),
                "crypto_bytes":saved.crypto.len(),"metadata_bytes":encode(&saved.meta)?.len()},
            "snapshot":super::super::store::digest(saved)?,
            "candidate_outcome_hash": saved.meta.journal.as_ref().and_then(|j| j.candidate.as_ref().and_then(|c| c.data.requests.get(&j.request)))
                .map(|r| {
                    let canonical: Value = decode(&encode(&r.result)?)?;
                    encode(&canonical).map(|bytes| hash(&bytes))
                }).transpose()?});
        use zeroize::Zeroize;
        for mut needle in needles {
            needle.zeroize();
        }
        Ok(result)
    }
}
