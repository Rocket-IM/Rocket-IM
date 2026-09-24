use super::{
    checked, codec, ensure, groups,
    state::{DeviceState, Inbound, Outbound},
    LabError, MAX_MESSAGE_BYTES, MAX_RECORDS,
};
use openmls::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    id: String,
    payload: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedContext {
    version: u32,
    sender: super::Context,
    group_id: String,
    id: String,
}

pub(super) fn send(
    state: &mut DeviceState,
    id: String,
    payload: String,
) -> Result<Value, LabError> {
    codec::valid_id(&id)?;
    ensure(
        payload.len() <= MAX_MESSAGE_BYTES,
        "message_limit",
        "合成内容超过 64 KiB",
    )?;
    let payload_digest = codec::digest(payload.as_bytes());
    if let Some(record) = state.outbox.get(&id) {
        ensure(
            record.payload_digest == payload_digest,
            "conflict",
            "相同消息 ID 对应不同内容",
        )?;
        return Ok(
            json!({"id":id,"ciphertext":codec::encode(&record.ciphertext),"epoch":record.epoch,"reused":true}),
        );
    }
    ensure(
        state.outbox.len() < MAX_RECORDS,
        "resource_limit",
        "发送队列达到上限",
    )?;
    let mut group = state.group()?;
    groups::validate_members(state, &group)?;
    let aad = AuthenticatedContext {
        version: 1,
        sender: state.context.clone(),
        group_id: codec::encode(group.group_id().as_slice()),
        id: id.clone(),
    };
    group.set_aad(checked("aad_encoding", serde_json::to_vec(&aad))?);
    let plaintext = checked(
        "envelope_encoding",
        serde_json::to_vec(&Envelope {
            id: id.clone(),
            payload,
        }),
    )?;
    let message = checked(
        "send_encrypt",
        group.create_message(&state.provider, &state.signer()?, &plaintext),
    )?;
    let ciphertext = checked("message_encoding", message.to_bytes())?;
    let epoch = group.epoch().as_u64();
    let response =
        json!({"id":id,"ciphertext":codec::encode(&ciphertext),"epoch":epoch,"reused":false});
    state.outbox.insert(
        id,
        Outbound {
            payload_digest,
            ciphertext,
            epoch,
        },
    );
    Ok(response)
}

pub(super) fn receive(
    state: &mut DeviceState,
    id: String,
    encoded: &str,
) -> Result<Value, LabError> {
    codec::valid_id(&id)?;
    let bytes = codec::decode(encoded)?;
    let ciphertext_digest = codec::digest(&bytes);
    if let Some(record) = state.inbox.get(&id) {
        ensure(
            record.ciphertext_digest == ciphertext_digest,
            "conflict",
            "相同消息 ID 对应不同密文",
        )?;
        return Ok(
            json!({"id":id,"payload_sha256":codec::digest_hex(&record.payload_digest),"duplicate":true,"epoch":record.epoch}),
        );
    }
    ensure(
        state.inbox.len() < MAX_RECORDS,
        "resource_limit",
        "接收去重记录达到上限",
    )?;
    let mut group = state.group()?;
    groups::validate_members(state, &group)?;
    let protocol = codec::protocol(&bytes)?;
    let epoch = protocol.epoch().as_u64();
    let processed = checked(
        "receive_validation",
        group.process_message(&state.provider, protocol),
    )?;
    let aad: AuthenticatedContext =
        checked("aad_decoding", serde_json::from_slice(processed.aad()))?;
    let sender = codec::credential_context(processed.credential())?;
    ensure(
        aad.version == 1
            && aad.id == id
            && aad.sender == sender
            && sender.service == state.context.service
            && aad.group_id == codec::encode(group.group_id().as_slice()),
        "message_binding",
        "认证上下文与消息 ID、实例、群或真实发送设备不匹配",
    )?;
    let plaintext = match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => message.into_bytes(),
        _ => return Err(LabError::new("message_type", "预期应用密文")),
    };
    let envelope: Envelope = checked("envelope_decoding", serde_json::from_slice(&plaintext))?;
    ensure(
        envelope.id == id,
        "message_binding",
        "外层消息 ID 与 E2EE 信封不匹配",
    )?;
    ensure(
        envelope.payload.len() <= MAX_MESSAGE_BYTES,
        "message_limit",
        "合成内容超过 64 KiB",
    )?;
    let payload_digest = codec::digest(envelope.payload.as_bytes());
    state.inbox.insert(
        id.clone(),
        Inbound {
            ciphertext_digest,
            payload_digest,
            epoch,
        },
    );
    Ok(
        json!({"id":id,"payload_sha256":codec::digest_hex(&payload_digest),"duplicate":false,"epoch":epoch}),
    )
}
