//! 原始嵌套封装的入站限制；不执行 SDK 或处理占位 MLS 字节。
use super::*;
use serde_json::Value;

fn all() -> Value {
    serde_json::from_str(include_str!(
        "../../../../api/realtime/join-recovery-witness-vectors.json"
    ))
    .unwrap()
}
fn wrap(envelope: &str, response: bool) -> String {
    if response {
        format!(
            r#"{{"operation":"join_recovery","command":{{"kind":"witness_observe","delivery":{{"response":{envelope},"known_evidence":[],"supplemental_evidence":[]}}}}}}"#
        )
    } else {
        format!(
            r#"{{ "operation": "join_recovery", "metadata":"quoted {{\"request\": []}}", "command": {{ "kind":"witness_respond", "request":{envelope} }} }}"#
        )
    }
}
#[test]
fn original_nested_wire_rejects_normalization_and_duplicates() {
    let v = all();
    let p: SignedRecord =
        serde_json::from_value(v["format_envelopes"]["witness_request"]["envelope"].clone())
            .unwrap();
    let compact = serde_json::to_string(&p).unwrap();
    witness::validate_lab_envelopes(&wrap(&compact, false)).unwrap();
    for bad in [
        serde_json::to_string_pretty(&p).unwrap(),
        format!(
            r#"{{"signature_bytes":"{}","statement_bytes":"{}"}}"#,
            p.signature_bytes, p.statement_bytes
        ),
        compact.replacen(':', ": ", 1),
        compact.replacen('=', r#"\u003d"#, 1),
    ] {
        assert_ne!(bad, compact, "测试替换必须改变原字节");
        assert!(
            witness::validate_lab_envelopes(&wrap(&bad, false)).is_err(),
            "禁止入站规范化后冒充原封装: {bad}"
        );
    }
    let duplicate = wrap(&compact, false).replacen(
        r#""kind":"witness_respond""#,
        r#""kind":"witness_respond","kind":"witness_respond""#,
        1,
    );
    assert!(witness::validate_lab_envelopes(&duplicate).is_err());
    assert!(
        witness::validate_lab_envelopes(&wrap(&compact, false).replacen(
            r#""request":"#,
            r#""other":"#,
            1
        ))
        .is_err()
    );
}
#[test]
fn nested_request_and_response_use_actual_wire_limits() {
    let v = all();
    for name in [
        "FMT-P-witness_request_wire_limit",
        "FMT-N-witness_request_wire_limit",
        "FMT-P-witness_response_wire_limit",
        "FMT-N-witness_response_wire_limit",
    ] {
        let case = v["encoding_vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == name)
            .unwrap();
        let raw = String::from_utf8(
            STANDARD
                .decode(case["wire_bytes"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let result = witness::validate_lab_envelopes(&wrap(&raw, name.contains("response")));
        assert_eq!(
            result.is_ok(),
            name.starts_with("FMT-P"),
            "{name}: {result:?}"
        );
    }
}
