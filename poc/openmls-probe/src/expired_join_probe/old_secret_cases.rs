//! 每份新密文都保留旧/新正对照、裸AEAD调用及合法MLS接收证据。
use super::old_secrets::Scenario;
use super::*;
use super::{raw_message as raw, raw_secrets};
pub(super) fn evaluate(s: &Scenario) -> Result<Value, String> {
    let inventory = super::raw_secrets::inventory(&s.old_bundle)?;
    ensure(
        inventory["key_package_records"]
            .as_u64()
            .is_some_and(|n| n > 0),
        "original bundle was not retained",
    )?;
    let mut rows = vec![];
    let mut not_retained = vec![];
    let mut body_calls = 0;
    let mut sender_calls = 0;
    for t in &s.targets {
        let packet = raw::packet(&t.packet)?;
        let data = raw::sender(&t.current, &t.packet)?;
        ensure(data.generation == t.generation, "generation not actual")?;
        let current = raw_secrets::material(&t.current, data.sender, data.generation)?
            .ok_or("current material absent")?;
        raw::payload(
            &checked(
                "new body positive",
                raw::body(&t.current, &packet, data, &current.key, &current.nonce),
            )?,
            &t.payload,
        )?;
        let mut altered = raw::packet(&t.packet)?;
        *altered.body.last_mut().ok_or("empty body")? ^= 1;
        raw::rejected(raw::body(
            &t.current,
            &altered,
            data,
            &current.key,
            &current.nonce,
        ))?;
        let mut wrong_aad = raw::packet(&t.packet)?;
        wrong_aad.aad.push(1);
        raw::rejected(raw::body(
            &t.current,
            &wrong_aad,
            data,
            &current.key,
            &current.nonce,
        ))?;
        let mut corrupt = t.packet.clone();
        corrupt[packet.sender_offset] ^= 1;
        raw::rejected(attack::attempt(&t.current, &corrupt)?)?;
        for (name, old) in &s.old {
            let control = s
                .controls
                .iter()
                .find(|c| c.sender == t.sender && c.generation == t.generation)
                .ok_or("old control missing")?;
            let old_data = raw::sender(old, &control.packet)?;
            ensure(old_data.sender == data.sender, "sender leaf changed")?;
            raw::rejected(attack::attempt(old, &t.packet)?)?;
            sender_calls += 1;
            let Some(key) = raw_secrets::material(old, data.sender, data.generation)? else {
                not_retained.push(json!({"stage":t.stage,"sender":t.sender,"generation":t.generation,"view":name,"result":"NO_RETAINED_GENERATION_NOT_COUNTED"}));
                continue;
            };
            let old_packet = raw::packet(&control.packet)?;
            raw::payload(
                &checked(
                    "old body positive",
                    raw::body(old, &old_packet, old_data, &key.key, &key.nonce),
                )?,
                &control.payload,
            )?;
            raw::rejected(raw::body(old, &packet, data, &key.key, &key.nonce))?;
            body_calls += 1;
            rows.push(json!({"stage":t.stage,"epoch":packet.epoch,"sender":t.sender,"generation":data.generation,"view":name,"material":key.origin,"old_on_old":"PASS","new_on_new":"PASS","old_on_new":"AeadDecryptionError","sender_data_oracle":true,"ciphertext_sha256":digest(&t.packet),"old_control_ciphertext_sha256":digest(&control.packet),"payload_sha256":digest(&t.payload),"legal_mls_receivers":t.legal_receivers,"gate_used":false}));
        }
    }
    ensure(
        rows.iter().any(|r| r["material"] == "retained_key_nonce")
            && rows.iter().any(|r| r["material"] == "ratchet_head")
            && rows.iter().any(|r| r["material"] == "secret_tree"),
        "material coverage absent",
    )?;
    let retained = s
        .old
        .iter()
        .map(|(name, actor)| Ok((name.clone(), raw_secrets::inventory(actor)?)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    ensure(
        retained.values().all(|v| {
            v["message_secret_records"] == 1
                && v["epoch_key_pair_records"].as_u64().is_some_and(|n| n > 0)
        }),
        "complete old epoch material not retained",
    )?;
    Ok(
        json!({"name":s.name,"status":"PASS_SCOPED","facts":s.facts,"target_count":s.targets.len(),"old_sender_aead_rejections":sender_calls,"old_body_aead_rejections":body_calls,"rows":rows,"not_retained":not_retained,"body_tamper_and_aad_controls":s.targets.len(),"sender_data_tamper_controls":s.targets.len(),"original_bundle_inventory":inventory,"old_view_inventory":retained}),
    )
}
