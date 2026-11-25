//! 仅在合成provider内存提取实际保留材料；按锁定上游序列化/MLS派生，不能用作生产解密器。
use super::attack::expand;
use super::*;
pub(super) struct Material {
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub origin: &'static str,
}
pub(super) fn inventory(actor: &Actor) -> Result<Value, String> {
    let values = checked("provider inventory", actor.provider.storage().values.read())?;
    let count = |prefix: &[u8]| values.keys().filter(|k| k.starts_with(prefix)).count();
    Ok(
        json!({"provider_entries":values.len(),"message_secret_records":count(b"MessageSecrets"),"key_package_records":count(b"KeyPackage"),"encryption_key_pair_records":count(b"EncryptionKeyPair"),"epoch_key_pair_records":count(b"EpochKeyPairs"),"device_signer_retained":true,"raw_secrets_exported":false}),
    )
}
fn bytes(value: &Value, len: usize) -> Result<Vec<u8>, String> {
    let bytes: Vec<u8> = checked("secret byte shape", serde_json::from_value(value.clone()))?;
    ensure(bytes.len() == len, "secret byte length")?;
    Ok(bytes)
}
fn secret(value: &Value) -> Result<Vec<u8>, String> {
    bytes(
        value.pointer("/value/vec").ok_or("missing secret value")?,
        32,
    )
}
pub(super) fn message(actor: &Actor) -> Result<Value, String> {
    let values = checked("retained provider", actor.provider.storage().values.read())?;
    let mut found = vec![];
    for (k, v) in values.iter() {
        if k.starts_with(b"MessageSecrets") {
            let value: Value = checked("message secrets encoding", serde_json::from_slice(v))?;
            found.push(
                value
                    .get("message_secrets")
                    .ok_or("missing current epoch secrets")?
                    .clone(),
            );
        }
    }
    ensure(found.len() == 1, "expected one current secrets record")?;
    found.pop().ok_or_else(|| "missing message secrets".into())
}
fn derived(
    actor: &Actor,
    mut head: Vec<u8>,
    start: u32,
    generation: u32,
    origin: &'static str,
) -> Result<Material, String> {
    ensure(
        start <= generation && generation - start <= 64,
        "test ratchet bound",
    )?;
    for g in start..generation {
        head = expand(actor, &head, "secret", &g.to_be_bytes(), 32)?;
    }
    Ok(Material {
        key: expand(actor, &head, "key", &generation.to_be_bytes(), 16)?,
        nonce: expand(actor, &head, "nonce", &generation.to_be_bytes(), 12)?,
        origin,
    })
}
pub(super) fn material(
    actor: &Actor,
    sender: u32,
    generation: u32,
) -> Result<Option<Material>, String> {
    ensure(sender < 8 && generation <= 64, "test input bound")?;
    let msg = message(actor)?;
    let tree = msg.get("secret_tree").ok_or("missing secret tree")?;
    let ratchets = tree["application_sender_ratchets"]
        .as_array()
        .ok_or("missing application ratchets")?;
    let ratchet = ratchets.get(sender as usize).ok_or("sender outside tree")?;
    if !ratchet.is_null() {
        let (head, cache) = if let Some(enc) = ratchet.get("EncryptionRatchet") {
            (enc, None)
        } else if let Some(dec) = ratchet.get("DecryptionRatchet") {
            (&dec["ratchet_head"], Some(&dec["past_secrets"]))
        } else {
            return Err("unsupported ratchet variant".into());
        };
        let start: u32 = checked(
            "head generation",
            serde_json::from_value(head["generation"].clone()),
        )?;
        if generation >= start {
            return Ok(Some(derived(
                actor,
                secret(&head["secret"])?,
                start,
                generation,
                "ratchet_head",
            )?));
        }
        let Some(cache) = cache else {
            return Ok(None);
        };
        let index = (start - generation - 1) as usize;
        let Some(pair) = cache.as_array().ok_or("cache shape")?.get(index) else {
            return Ok(None);
        };
        if pair.is_null() {
            return Ok(None);
        }
        let key = bytes(pair.pointer("/0/value/vec").ok_or("cache key")?, 16)?;
        let nonce = bytes(pair.pointer("/1").ok_or("cache nonce")?, 12)?;
        return Ok(Some(Material {
            key,
            nonce,
            origin: "retained_key_nonce",
        }));
    }
    let leaves = tree["leaf_nodes"].as_array().ok_or("leaf nodes")?;
    let parents = tree["parent_nodes"].as_array().ok_or("parent nodes")?;
    let size = tree["size"].as_u64().ok_or("tree size")? as u32;
    ensure(
        size > 0 && size < 16 && (size + 1).is_power_of_two(),
        "fixed small tree size",
    )?;
    let target = sender * 2;
    let mut node = size.div_ceil(2) - 1;
    let mut value = None;
    loop {
        if value.is_none() {
            let entry = if node.is_multiple_of(2) {
                leaves.get((node / 2) as usize)
            } else {
                parents.get(((node - 1) / 2) as usize)
            }
            .ok_or("tree node")?;
            if !entry.is_null() {
                value = Some(secret(&entry["secret"])?);
            }
        }
        if node == target {
            break;
        }
        let level = node.trailing_ones();
        ensure(level > 0, "target path")?;
        let label = if target < node { "left" } else { "right" };
        if let Some(s) = value.take() {
            value = Some(expand(actor, &s, "tree", label.as_bytes(), 32)?);
        }
        node ^= if target < node {
            1 << (level - 1)
        } else {
            3 << (level - 1)
        };
    }
    let leaf = value.ok_or("no retained leaf or ratchet")?;
    let head = expand(actor, &leaf, "application", b"", 32)?;
    Ok(Some(derived(actor, head, 0, generation, "secret_tree")?))
}
