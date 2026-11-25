//! 冻结格式向量只进入公共解析/验签层；占位 MLS 材料不送入协议处理器。
use super::*;
use serde_json::Value;
use witness::*;

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../api/realtime/join-recovery-witness-vectors.json"
    ))
    .unwrap()
}
fn envelope(v: &Value, name: &str) -> SignedRecord {
    serde_json::from_value(v["format_envelopes"][name]["envelope"].clone()).unwrap()
}
fn policy(v: &Value) -> PolicyEnvelope {
    PolicyEnvelope {
        policy_bytes: v["unsigned_objects"]["policy"]["raw_bytes"]
            .as_str()
            .unwrap()
            .into(),
        policy_ref: serde_json::from_value(
            v["format_envelopes"]["intent"]["decoded"]["policy_ref"].clone(),
        )
        .unwrap(),
    }
}
fn format(v: &Value) -> Result<(), PermissionError> {
    let shape = v["decoded_schema"].as_str().unwrap();
    let max = match shape {
        "WitnessRequest" => REQUEST_WIRE_LIMIT,
        "WitnessResponse" => RESPONSE_WIRE_LIMIT,
        _ => 32768,
    };
    let wire = STANDARD.decode(v["wire_bytes"].as_str().unwrap()).unwrap();
    let p = parse_signed_wire(&wire, max)?;
    match shape {
        "Intent" | "Claim" | "Close" => {
            parse_request(&p)?;
        }
        "AllocationReceipt" | "AcceptedReceipt" | "ClosedReceipt" => {
            verify_receipt(v["expected_signer_key"].as_str().unwrap(), &p)?;
        }
        "Statement" => {
            let s: Statement = raw(&p.statement_bytes)?;
            s.validate()?;
            receipts::signature(
                &s.actor.signature_key,
                s.domain()?,
                &scalar::bytes(&p.statement_bytes, 16384)?,
                &p.signature_bytes,
            )?;
        }
        "WitnessRequest" => {
            parse_witness_request(&p)?;
        }
        "WitnessResponse" => {
            parse_witness_response(&p)?;
        }
        _ => panic!("未知冻结格式 {shape}"),
    }
    Ok(())
}
#[test]
fn frozen_encoding_vectors() {
    let all = vectors();
    let vectors = all["encoding_vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 36);
    for v in vectors {
        let result = format(v);
        assert_eq!(
            result.is_ok(),
            v["expected"] == "ACCEPT_FORMAT_ONLY",
            "{}: {result:?}",
            v["id"]
        );
        println!(
            "W1_ENCODING {} {:?}",
            v["id"],
            result.as_ref().err().map(|e| e.code)
        );
    }
}
#[test]
fn frozen_unsigned_and_scalar_vectors() {
    let all = vectors();
    for v in all["unsigned_vectors"].as_array().unwrap() {
        let b = serde_json::to_vec(&v["input"]).unwrap();
        let result = match v["definition"].as_str().unwrap() {
            "Policy" => parse_bytes::<Policy>(&b, 8192).and_then(|v| validate_policy(&v)),
            "Activation" => {
                parse_bytes::<Activation>(&b, 16384).and_then(|v| validate_activation(&v))
            }
            "InstallationFact" => {
                parse_bytes::<InstallationFact>(&b, 16384).and_then(|v| validate_installation(&v))
            }
            "InstalledRecord" => {
                parse_bytes::<InstalledRecord>(&b, 65536).and_then(|v| validate_installed(&v))
            }
            n => panic!("{n}"),
        };
        assert_eq!(
            result.is_ok(),
            v["expected_valid"].as_bool().unwrap(),
            "{}: {result:?}",
            v["id"]
        );
        println!(
            "W1_UNSIGNED {} {:?}",
            v["id"],
            result.as_ref().err().map(|e| e.code)
        );
    }
    for v in all["scalar_vectors"].as_array().unwrap() {
        let result = v["input"]
            .as_str()
            .is_some_and(|s| match v["definition"].as_str().unwrap() {
                "U64" => scalar::decimal(s).is_ok(),
                "PositiveU64" => scalar::decimal(s).is_ok_and(|n| n > 0),
                "Hash" => scalar::hash(s).is_ok(),
                n => panic!("{n}"),
            });
        assert_eq!(
            result,
            v["expected_valid"].as_bool().unwrap(),
            "{}",
            v["id"]
        );
        println!("W1_SCALAR {} {result}", v["id"]);
    }
}
#[test]
fn policy_exact_original_and_response_binding() {
    let v = vectors();
    let p = policy(&v);
    assert_eq!(parse_policy(&p).unwrap().policy_id, "fixed_w1");
    let intent = parse_intent(&envelope(&v, "intent")).unwrap();
    validate_intent_policy(&intent, &p).unwrap();
    let request = envelope(&v, "witness_request");
    let response = envelope(&v, "witness_response");
    verify_witness_response(&p, &request, &response).unwrap();
    let mut changed = p.clone();
    let mut raw = STANDARD.decode(&p.policy_bytes).unwrap();
    raw.push(b' ');
    changed.policy_bytes = STANDARD.encode(raw);
    assert!(
        parse_policy(&changed).is_err(),
        "语义相同原字节变化必须拒绝旧 P hash"
    );
    let mut missing_w = intent.clone();
    missing_w.directory_refs.retain(|d| d.account_id != "carol");
    assert!(validate_intent_policy(&missing_w, &p).is_err());
    let reordered = &v["encoding_vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == "FMT-P-reordered_resigned")
        .unwrap()["input_envelope"];
    let different: SignedRecord = serde_json::from_value(reordered.clone()).unwrap();
    assert!(parse_witness_request(&different).is_ok());
    assert!(
        verify_witness_response(&p, &different, &response).is_err(),
        "语义相同但重签重排不是响应的原请求"
    );
}
#[test]
fn new_legacy_tuple_and_null_are_not_interchangeable() {
    let v = vectors();
    let intent = envelope(&v, "intent");
    let parsed = parse_intent(&intent).unwrap();
    let receipt = verify_receipt(
        v["test_identities"]["service"]["member"]["signature_key"]
            .as_str()
            .unwrap(),
        &envelope(&v, "allocation"),
    )
    .unwrap();
    receipt_context(&receipt, &parsed, &intent).unwrap();
    let mut old = receipt.clone();
    old.protocol_version = "rim-recovery-receipt-1".into();
    old.witness_profile = None;
    old.policy_ref = None;
    old.validate().unwrap();
    assert!(receipt_context(&old, &parsed, &intent).is_err());
    let mut value = v["format_envelopes"]["intent"]["decoded"].clone();
    value["policy_ref"] = Value::Null;
    assert!(raw::<Request>(&STANDARD.encode(serde_json::to_vec(&value).unwrap())).is_err());
    value.as_object_mut().unwrap().remove("policy_ref");
    assert!(
        raw::<Request>(&STANDARD.encode(serde_json::to_vec(&value).unwrap()))
            .unwrap()
            .validate()
            .is_err()
    );
    value["protocol_version"] = serde_json::json!("rim-recovery-request-1");
    assert!(
        raw::<Request>(&STANDARD.encode(serde_json::to_vec(&value).unwrap()))
            .unwrap()
            .validate()
            .is_err()
    );
}

#[test]
fn frozen_digest_chain_has_no_reserialization() {
    let v = vectors();
    for (name, entry) in v["format_envelopes"].as_object().unwrap() {
        let proof: SignedRecord = serde_json::from_value(entry["envelope"].clone()).unwrap();
        assert_eq!(
            signed_digest(&proof).unwrap(),
            entry["signed_record_sha256"],
            "{name}"
        );
    }
    let proof: Proof = serde_json::from_value(v["candidate_proof"].clone()).unwrap();
    assert_eq!(candidate_digest(&proof).unwrap(), v["candidate_sha256"]);
    let change = v["accepted_ref"]["change_id"].as_str().unwrap();
    assert_eq!(
        serde_json::to_value(admission_ref(change, &proof, &envelope(&v, "accepted")).unwrap())
            .unwrap(),
        v["accepted_ref"]
    );
    let (_, reference) = parse_policy_bytes(&policy(&v).policy_bytes).unwrap();
    assert_eq!(
        reference.policy_sha256,
        v["unsigned_objects"]["policy"]["policy_sha256"]
    );
    let fact = &v["unsigned_objects"]["installation_fact"];
    assert_eq!(
        crate::permission::commit_digest(
            &STANDARD
                .decode(fact["raw_bytes"].as_str().unwrap())
                .unwrap()
        ),
        fact["sha256"]
    );
}

#[test]
fn authenticated_binding_failures_keep_distinct_reasons() {
    use ed25519_dalek::{Signer, SigningKey};
    let v = vectors();
    let p = policy(&v);
    let q = envelope(&v, "witness_request");
    let sign_value = |value: &Value, seed: u8, domain: &[u8]| {
        let bytes = serde_json::to_vec(value).unwrap();
        let mut signed = domain.to_vec();
        signed.extend(&bytes);
        SignedRecord {
            statement_bytes: STANDARD.encode(bytes),
            signature_bytes: STANDARD
                .encode(SigningKey::from_bytes(&[seed; 32]).sign(&signed).to_bytes()),
        }
    };
    for (field, value, seed, code) in [
        (
            "policy_ref",
            serde_json::json!({"policy_id":"other_policy", "policy_version":"1","policy_sha256":"11".repeat(32)}),
            0x22,
            "w1_policy_mismatch",
        ),
        (
            "witness",
            v["test_identities"]["actor"]["member"].clone(),
            0x11,
            "w1_witness_ineligible",
        ),
        (
            "challenge",
            serde_json::json!("42".repeat(32)),
            0x22,
            "w1_binding_mismatch",
        ),
        (
            "scope",
            serde_json::json!({"service_id":"other_service",
                "conversation_id":"c1", "group_id":"Z3JvdXAtMQ=="}),
            0x22,
            "w1_binding_mismatch",
        ),
    ] {
        let mut response = v["format_envelopes"]["witness_response"]["decoded"].clone();
        response[field] = value;
        let proof = sign_value(&response, seed, witness::RESPONSE_DOMAIN);
        assert_eq!(
            verify_witness_response(&p, &q, &proof).unwrap_err().code,
            code,
            "{field}"
        );
    }
    let mut request = v["format_envelopes"]["witness_request"]["decoded"].clone();
    request["policy_ref"]["policy_id"] = serde_json::json!("other_policy");
    assert_eq!(
        verify_witness_request(&p, &sign_value(&request, 0x33, witness::REQUEST_DOMAIN))
            .unwrap_err()
            .code,
        "w1_policy_mismatch"
    );
    let response = &v["format_envelopes"]["witness_response"]["decoded"];
    let mut inconsistent = response.clone();
    inconsistent["next"]["checkpoint"]["crypto_state_ref"] = serde_json::json!("43".repeat(32));
    assert_eq!(
        verify_witness_response(
            &p,
            &q,
            &sign_value(&inconsistent, 0x22, witness::RESPONSE_DOMAIN)
        )
        .unwrap_err()
        .code,
        "w1_binding_mismatch"
    );
    assert_eq!(
        verify_witness_response(
            &p,
            &q,
            &sign_value(response, 0x11, witness::RESPONSE_DOMAIN)
        )
        .unwrap_err()
        .code,
        "permission_signature"
    );
}

#[test]
fn installed_record_rejects_exact_expiry_timestamp() {
    let v = vectors();
    let mut record: InstalledRecord = raw(v["unsigned_objects"]["installed_record"]["raw_bytes"]
        .as_str()
        .unwrap())
    .unwrap();
    validate_installed(&record).unwrap();
    record.installed_at_unix_secs = parse_witness_response(&record.response)
        .unwrap()
        .expires_at_unix_secs;
    assert!(validate_installed(&record).is_err());
}
