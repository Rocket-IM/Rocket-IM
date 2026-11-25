//! 仅显式实验构建使用的恶意客户端装置；正常发布包没有此入口。
use super::{checked, codec, ensure, state::DeviceState, LabError};
use crate::key_package::{self as protocol, Action, Request};
use openmls::prelude::{
    tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize},
    *,
};
use openmls_traits::{signatures::Signer, storage::StorageProvider, OpenMlsProvider};
use serde_json::{json, Value};

pub(super) fn execute(
    state: &mut DeviceState,
    mode: String,
    request_id: String,
    original: String,
) -> Result<Value, LabError> {
    let signer = state.signer()?;
    if mode == "missing_bundle" {
        let reference = checked(
            "probe",
            openmls::ciphersuite::hash_ref::make_key_package_ref(
                &codec::decode(&original)?,
                codec::CIPHERSUITE,
                state.provider.crypto(),
            ),
        )?;
        checked(
            "probe",
            state.provider.storage().delete_key_package(&reference),
        )?;
        return Ok(json!({"synthetic_corruption":"bundle_removed"}));
    }
    let now = checked(
        "clock",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH),
    )?
    .as_secs();
    let mut builder = KeyPackage::builder().key_package_lifetime(Lifetime::init(
        now - 1,
        now + if mode == "excess_lifetime" {
            86401
        } else {
            7200
        },
    ));
    if mode == "last_resort" {
        builder = builder.mark_as_last_resort();
    }
    let suite = if mode == "wrong_suite" {
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    } else {
        codec::CIPHERSUITE
    };
    let mut credential = state.own_credential()?;
    if mode == "wrong_identity" {
        credential.credential=BasicCredential::new(serde_json::to_vec(&json!({"service":state.context.service,"account":"wrong","device":state.context.device})).map_err(|e|LabError::new("probe",e.to_string()))?).into();
    }
    let bundle = checked(
        "probe",
        builder.build(suite, &state.provider, &signer, credential),
    )?;
    let mut bytes = checked("probe", bundle.key_package().tls_serialize_detached())?;
    if mode == "reuse_init" {
        let old = checked(
            "probe",
            KeyPackageIn::tls_deserialize_exact(codec::decode(&original)?),
        )?;
        let incoming = checked("probe", KeyPackageIn::tls_deserialize_exact(&bytes))?;
        let mut value = checked("probe", serde_json::to_value(incoming))?;
        value["payload"]["init_key"] =
            checked("probe", serde_json::to_value(old))?["payload"]["init_key"].clone();
        let old_signature: Signature =
            checked("probe", serde_json::from_value(value["signature"].clone()))?;
        let incoming: KeyPackageIn = checked("probe", serde_json::from_value(value.clone()))?;
        let encoded = checked("probe", incoming.tls_serialize_detached())?;
        let signature_len = checked("probe", old_signature.tls_serialize_detached())?.len();
        ensure(encoded.len() > signature_len, "probe", "签名边界无效")?;
        let content = SignContent::new(
            "KeyPackageTBS",
            encoded[..encoded.len() - signature_len].to_vec().into(),
        );
        let signature = signer
            .sign(&checked("probe", content.tls_serialize_detached())?)
            .map_err(|_| LabError::new("probe", "测试签名失败"))?;
        value["signature"] = checked("probe", serde_json::to_value(Signature::from(signature)))?;
        let resigned: KeyPackageIn = checked("probe", serde_json::from_value(value))?;
        bytes = checked("probe", resigned.tls_serialize_detached())?;
        // 此反例必须通过真实库验证，不能靠无效签名冒充init复用测试。
        protocol::material::inspect(
            &codec::encode(&bytes),
            &state.context.service,
            &super::key_package_state::own(state),
        )?;
    } else if mode == "bad_signature" {
        if let Some(last) = bytes.last_mut() {
            *last ^= 1;
        }
    } else {
        ensure(
            matches!(
                mode.as_str(),
                "last_resort" | "wrong_suite" | "wrong_identity" | "excess_lifetime"
            ),
            "probe",
            "未知测试模式",
        )?;
    }
    let request = Request {
        protocol_version: "rim-key-package-request-1".into(),
        service_id: state.context.service.clone(),
        request_id,
        actor: super::key_package_state::own(state),
        action: Action::Publish {
            packages: vec![original, codec::encode(&bytes)],
        },
    };
    let proof = protocol::sign(&request, &signer)?;
    Ok(json!({"proof":proof,"mode":mode,"resigned_package":codec::encode(&bytes)}))
}
