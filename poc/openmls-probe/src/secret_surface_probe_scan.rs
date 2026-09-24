//! 有界字节/编码观察及实际样本的内存正负对照；禁止回传原样本。
use super::{byte_array, Result};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(super) struct Needle {
    pub category: &'static str,
    pub device: String,
    bytes: Vec<u8>,
}
pub(super) struct Pattern {
    category: &'static str,
    device: String,
    sample: usize,
    encoding: &'static str,
    bytes: Vec<u8>,
}

pub(super) fn add(
    needles: &mut Vec<Needle>,
    category: &'static str,
    device: &str,
    bytes: Vec<u8>,
) -> Result<()> {
    if !(16..=64 * 1024).contains(&bytes.len()) {
        return Err("needle_length");
    }
    if needles
        .iter()
        .any(|n| n.category == category && n.device == device && n.bytes == bytes)
    {
        return Ok(());
    }
    if needles.len() >= 2048
        || needles.iter().map(|n| n.bytes.len()).sum::<usize>() + bytes.len() > 2 * 1024 * 1024
    {
        return Err("needle_limit");
    }
    needles.push(Needle {
        category,
        device: device.into(),
        bytes,
    });
    Ok(())
}

fn encodings(bytes: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let lower = hex(bytes, false);
    let upper = hex(bytes, true);
    let compact = format!(
        "[{}]",
        bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    let spaced = format!(
        "[{}]",
        bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
    vec![
        ("raw", bytes.to_vec()),
        ("hex_lower", lower.into_bytes()),
        ("hex_upper", upper.into_bytes()),
        ("base64", STANDARD.encode(bytes).into_bytes()),
        ("base64_no_pad", STANDARD_NO_PAD.encode(bytes).into_bytes()),
        ("base64_url", URL_SAFE.encode(bytes).into_bytes()),
        (
            "base64_url_no_pad",
            URL_SAFE_NO_PAD.encode(bytes).into_bytes(),
        ),
        ("json_bytes_compact", compact.into_bytes()),
        ("json_bytes_spaced", spaced.into_bytes()),
    ]
}

pub(super) fn patterns(needles: &[Needle]) -> Result<Vec<Pattern>> {
    let mut result = Vec::new();
    let mut total = 0;
    for (sample, needle) in needles.iter().enumerate() {
        for (encoding, bytes) in encodings(&needle.bytes) {
            total += bytes.len();
            if total > 32 * 1024 * 1024 {
                return Err("pattern_limit");
            }
            result.push(Pattern {
                category: needle.category,
                device: needle.device.clone(),
                sample,
                encoding,
                bytes,
            });
        }
    }
    Ok(result)
}

pub(super) fn controls(needles: &[Needle]) -> Result<Value> {
    let mut checked = 0;
    for needle in needles {
        let mut wrong = needle.bytes.clone();
        // 相同长度、明确不同的样本；对照不写盘，不注入 Relay。
        wrong[0] ^= 0xff;
        let patterns = patterns(std::slice::from_ref(needle))?;
        let wrong = encodings(&wrong);
        for (pattern, (_, negative)) in patterns.iter().zip(wrong) {
            let mut positive = b"positive-control|".to_vec();
            positive.extend(&pattern.bytes);
            positive.extend(b"|end");
            if scan(&positive, std::slice::from_ref(pattern))?.is_empty()
                || !scan(&negative, std::slice::from_ref(pattern))?.is_empty()
            {
                return Err("control_failed");
            }
            checked += 1;
        }
    }
    Ok(
        json!({"actual_samples":needles.len(),"positive_encoding_checks":checked,
        "wrong_sample_negative_checks":checked,"status":"PASS", "location":"memory_only"}),
    )
}

struct Observation<'a> {
    patterns: &'a [Pattern],
    hits: BTreeSet<(usize, &'static str, &'static str)>,
    nodes: usize,
    decoded_bytes: usize,
}

pub(super) fn scan(bytes: &[u8], patterns: &[Pattern]) -> Result<Vec<Value>> {
    let mut observation = Observation {
        patterns,
        hits: BTreeSet::new(),
        nodes: 0,
        decoded_bytes: 0,
    };
    observation.bytes(bytes, "raw", 0)?;
    Ok(observation
        .hits
        .into_iter()
        .map(|(index, encoding, view)| {
            let p = &patterns[index];
            json!({"category":p.category,"device":p.device,"sample":p.sample,
            "encoding":encoding,"view":view})
        })
        .collect())
}

impl Observation<'_> {
    fn matches(&mut self, bytes: &[u8], view: &'static str) {
        for (index, pattern) in self.patterns.iter().enumerate() {
            if bytes
                .windows(pattern.bytes.len())
                .any(|window| window == pattern.bytes)
            {
                self.hits.insert((index, pattern.encoding, view));
            }
        }
    }

    fn budget(&mut self, depth: usize) -> Result<()> {
        self.nodes += 1;
        if depth > 24 || self.nodes > 100_000 {
            return Err("decode_structure_limit");
        }
        Ok(())
    }

    fn bytes(&mut self, bytes: &[u8], view: &'static str, depth: usize) -> Result<()> {
        self.budget(depth)?;
        self.matches(bytes, view);
        if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
            self.value(&value, depth + 1)?;
        }
        Ok(())
    }

    fn decoded(&mut self, bytes: &[u8], view: &'static str, depth: usize) -> Result<()> {
        self.decoded_bytes += bytes.len();
        if self.decoded_bytes > 64 * 1024 * 1024 {
            return Err("decode_bytes_limit");
        }
        self.bytes(bytes, view, depth + 1)
    }

    fn value(&mut self, value: &Value, depth: usize) -> Result<()> {
        self.budget(depth)?;
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    self.matches(key.as_bytes(), "json_key");
                    self.value(value, depth + 1)?;
                }
            }
            Value::Array(array) => {
                if let Some(bytes) = byte_array(value).filter(|b| b.len() >= 16) {
                    self.decoded(&bytes, "json_byte_array", depth)?;
                } else {
                    for value in array {
                        self.value(value, depth + 1)?;
                    }
                }
            }
            Value::String(text) => {
                self.matches(text.as_bytes(), "json_string");
                // JSON 内嵌 JSON 的转义字符串也要按解析后的原值观察。
                if let Ok(value) = serde_json::from_str::<Value>(text) {
                    self.value(&value, depth + 1)?;
                }
                if (16..=32 * 1024 * 1024).contains(&text.len()) {
                    let mut decoded = BTreeSet::new();
                    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
                        if let Ok(bytes) = engine.decode(text) {
                            if bytes.len() >= 16 && decoded.insert(bytes.clone()) {
                                self.decoded(&bytes, "base64_decoded", depth)?;
                            }
                        }
                    }
                    if let Some(bytes) = decode_hex(text) {
                        self.decoded(&bytes, "hex_decoded", depth)?;
                    }
                }
            }
            _ => (),
        }
        Ok(())
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() < 32 || !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        })
        .collect()
}

fn hex(bytes: &[u8], upper: bool) -> String {
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let table = if upper { UPPER } else { LOWER };
    bytes
        .iter()
        .flat_map(|byte| {
            [
                table[(byte >> 4) as usize] as char,
                table[(byte & 0x0f) as usize] as char,
            ]
        })
        .collect()
}

pub(super) fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes), false)
}
