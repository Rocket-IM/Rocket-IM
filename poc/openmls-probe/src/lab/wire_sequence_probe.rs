//! 默认关闭的大序号测试起点；只移动已验签空流的双游标，不补造历史或处理成功。

#[cfg(feature = "wire-sequence-probe")]
pub(super) fn seed(
    state: &mut super::state::DeviceState,
    stream_id: &str,
    base_seq: &str,
) -> Result<serde_json::Value, super::LabError> {
    use super::ensure;
    ensure(
        base_seq == "9007199254740990",
        "sequence_seed_invalid",
        "测试起点仅允许固定的十进制字符串 9007199254740990",
    )?;
    ensure(
        state.rebuild.is_none(),
        "sequence_seed_unavailable",
        "重建候选或后继不能使用普通流测试起点",
    )?;
    let sync = &mut state.wire_sync;
    ensure(
        state.permissions.recovery.relay_receipt_key.is_some()
            && sync.source_verified
            && sync.stream_id.as_deref() == Some(stream_id),
        "sequence_seed_source_required",
        "测试流必须先固定 Service 公钥并通过真实空签页绑定相同流",
    )?;
    ensure(
        sync.download_cursor == 0
            && sync.processed_cursor == 0
            && sync.slots.is_empty()
            && sync.applied_controls.is_empty()
            && !sync.halted,
        "sequence_seed_not_empty",
        "只能设置尚未使用且未暂停的空流，不能重复设置或跳过已有记录",
    )?;
    sync.download_cursor = 9_007_199_254_740_990;
    sync.processed_cursor = 9_007_199_254_740_990;
    Ok(serde_json::json!({
        "status":"synthetic_sequence_seeded",
        "scope":"synthetic_local_sequence_fixture",
        "historical_events":"NOT_EXECUTED",
        "base_seq":base_seq,
        "sync":sync.summary(),
    }))
}

#[cfg(test)]
mod tests {
    use crate::lab::wire_tests::Fixture;
    use serde_json::{json, Value};
    use std::fs;

    fn request() -> Value {
        json!({"operation":"wire_sequence_seed","stream_id":"B_stream","base_seq":"9007199254740990"})
    }

    fn reject(f: &Fixture, operation: Value, code: &str) {
        let state = fs::read(f.root.join("B/state.enc")).unwrap();
        let key = fs::read(f.root.join("B/device.key")).unwrap();
        f.fails("B", operation, code);
        assert!(
            state == fs::read(f.root.join("B/state.enc")).unwrap(),
            "拒绝请求改变了快照文件"
        );
        assert!(
            key == fs::read(f.root.join("B/device.key")).unwrap(),
            "拒绝请求改变了设备密钥文件"
        );
    }

    #[cfg(not(feature = "wire-sequence-probe"))]
    #[test]
    fn sequence_seed_is_unknown_in_default_build() {
        reject(&Fixture::new(), request(), "invalid_request");
    }

    #[cfg(feature = "wire-sequence-probe")]
    mod enabled {
        use super::*;
        use crate::lab::{
            state::DeviceState, store::LockedDevice, stream_source_test_support::*, Context,
            CrashPoint,
        };
        use ed25519_dalek::SigningKey;

        const BASE: u64 = 9_007_199_254_740_990;

        fn bound() -> (Fixture, SigningKey) {
            let (f, key) = setup();
            f.call("B", signed(&key, &page(vec![], 0, 0), 0, 100));
            (f, key)
        }

        // 只构造不可接受的快照以覆盖防绕过门禁，不作为正常业务成功证据。
        fn alter_invalid_fixture(f: &Fixture, alter: impl FnOnce(&mut DeviceState)) {
            let locked = LockedDevice::open(&f.root.join("B")).unwrap();
            let mut state = locked
                .load(&Context {
                    service: "S1".into(),
                    account: "B".into(),
                    device: "B".into(),
                })
                .unwrap()
                .unwrap();
            alter(&mut state);
            locked.save(&mut state, CrashPoint::None).unwrap();
        }

        fn persisted(f: &Fixture) -> Value {
            let locked = LockedDevice::open(&f.root.join("B")).unwrap();
            let state = locked
                .load(&Context {
                    service: "S1".into(),
                    account: "B".into(),
                    device: "B".into(),
                })
                .unwrap()
                .unwrap();
            serde_json::to_value(state).unwrap()
        }

        #[test]
        fn sequence_seed_requires_pinned_verified_matching_empty_stream() {
            let unpinned = Fixture::new();
            reject(&unpinned, request(), "sequence_seed_source_required");
            let (unbound, _) = setup();
            reject(&unbound, request(), "sequence_seed_source_required");
            let legacy = Fixture::new();
            legacy.download(vec![], 0);
            pin(&legacy, &SigningKey::from_bytes(&[61; 32]));
            reject(&legacy, request(), "sequence_seed_source_required");
            let (bound, _) = bound();
            let mut wrong_stream = request();
            wrong_stream["stream_id"] = json!("other_stream");
            reject(&bound, wrong_stream, "sequence_seed_source_required");
        }

        #[test]
        fn sequence_seed_rejects_wrong_base_and_json_types_atomically() {
            let (f, _) = bound();
            for value in [
                json!("0"),
                json!("9007199254740991"),
                json!("09007199254740990"),
                json!("18446744073709551616"),
            ] {
                let mut operation = request();
                operation["base_seq"] = value;
                reject(&f, operation, "sequence_seed_invalid");
            }
            for value in [json!(BASE), Value::Null, json!(true)] {
                let mut operation = request();
                operation["base_seq"] = value;
                reject(&f, operation, "invalid_request");
            }
        }

        #[test]
        fn sequence_seed_cannot_reset_downloaded_or_processed_records() {
            let (f, key) = bound();
            f.call("B", signed(&key, &page(vec![slot(1)], 1, 1), 0, 100));
            reject(&f, request(), "sequence_seed_not_empty");
            f.call("B", json!({"operation":"wire_process"}));
            reject(&f, request(), "sequence_seed_not_empty");
        }

        #[test]
        fn sequence_seed_rejects_halted_or_control_cache_even_with_zero_cursors() {
            for control_cache in [false, true] {
                let (f, _) = bound();
                alter_invalid_fixture(&f, |state| {
                    if control_cache {
                        state.wire_sync.applied_controls.insert(
                            "existing".into(),
                            crate::lab::wire_sync::Control {
                                control_id: "existing".into(),
                                from_state_ref: "a".repeat(64),
                                to_state_ref: "b".repeat(64),
                                payload_bytes: "unused".into(),
                            },
                        );
                    } else {
                        state.wire_sync.halted = true;
                    }
                });
                reject(&f, request(), "sequence_seed_not_empty");
            }
        }

        #[test]
        fn sequence_seed_obeys_existing_consistency_and_removed_access_guards() {
            let (f, _) = bound();
            f.call("B", json!({"operation":"consistency_challenge"}));
            reject(&f, request(), "consistency_paused");
            let (f, _) = bound();
            alter_invalid_fixture(&f, |state| {
                state.permissions.recovery.access_removed = true;
            });
            reject(&f, request(), "access_removed");
        }

        #[test]
        fn sequence_seed_preserves_crypto_and_survives_reload_only_once() {
            let (f, _) = bound();
            let before = f.call("B", json!({"operation":"wire_inspect"}));
            let persisted_before = persisted(&f);
            let seeded = f.call("B", request());
            assert_eq!(seeded["scope"], "synthetic_local_sequence_fixture");
            assert_eq!(seeded["historical_events"], "NOT_EXECUTED");
            assert_eq!(seeded["sync"]["download_cursor"], BASE.to_string());
            assert_eq!(seeded["sync"]["processed_cursor"], BASE.to_string());
            let mut reloaded = f.call("B", json!({"operation":"wire_inspect"}));
            assert_eq!(reloaded["sync"], seeded["sync"]);
            reloaded["sync"] = before["sync"].clone();
            assert_eq!(reloaded, before);
            let mut persisted_after = persisted(&f);
            persisted_after["wire_sync"] = persisted_before["wire_sync"].clone();
            assert!(
                persisted_after == persisted_before,
                "测试起点改变了双游标之外的持久状态"
            );
            reject(&f, request(), "sequence_seed_not_empty");
        }

        #[test]
        fn seeded_signed_three_slot_download_process_and_replay_are_exact_above_js_limit() {
            let (f, key) = bound();
            f.call("B", request());
            for seq in BASE + 1..=BASE + 3 {
                let operation = signed(&key, &page(vec![slot(seq)], seq, BASE + 3), seq - 1, 1);
                let downloaded = f.call("B", operation.clone());
                assert_eq!(downloaded["sync"]["download_cursor"], seq.to_string());
                assert_eq!(
                    downloaded["sync"]["processed_cursor"],
                    (seq - 1).to_string()
                );
                assert_eq!(f.call("B", operation)["status"], "downloaded");
                let processed = f.call("B", json!({"operation":"wire_process"}));
                assert_eq!(processed["sync"]["processed_cursor"], seq.to_string());
                assert_eq!(processed["results"][0]["event_seq"], seq.to_string());
                assert_eq!(
                    processed["results"][0]["result"]["status"],
                    "receipt_recorded"
                );
                let inspected = f.call(
                    "B",
                    json!({"operation":"wire_slot_inspect","event_seq":seq.to_string()}),
                );
                assert_eq!(inspected["event_seq"], seq.to_string());
                assert_eq!(inspected["slot"], slot(seq));
            }
            let final_state = f.call("B", json!({"operation":"wire_inspect"}));
            assert_eq!(final_state["sync"]["slot_count"], 3);
            assert_eq!(final_state["sync"]["download_cursor"], "9007199254740993");
            assert_eq!(final_state["sync"]["processed_cursor"], "9007199254740993");
            assert_eq!(final_state["inbox_count"], 0);
        }

        #[test]
        fn seeded_signed_page_rejects_numeric_and_overflow_fields_before_save() {
            let (f, key) = bound();
            f.call("B", request());
            for field in ["event_seq", "next_after_seq", "watermark"] {
                for value in [json!(BASE + 1), json!("18446744073709551616")] {
                    let numeric = value.is_number();
                    let mut invalid = page(vec![slot(BASE + 1)], BASE + 1, BASE + 1);
                    if field == "event_seq" {
                        invalid["events"][0][field] = value;
                    } else {
                        invalid[field] = value;
                    }
                    reject(
                        &f,
                        signed(&key, &invalid, BASE, 1),
                        if numeric {
                            "stream_page_invalid"
                        } else {
                            "invalid_envelope"
                        },
                    );
                }
            }
            for value in [json!(BASE + 1), json!("18446744073709551616")] {
                let numeric = value.is_number();
                reject(
                    &f,
                    json!({"operation":"wire_slot_inspect","event_seq":value}),
                    if numeric {
                        "invalid_request"
                    } else {
                        "invalid_envelope"
                    },
                );
            }
        }
    }
}
