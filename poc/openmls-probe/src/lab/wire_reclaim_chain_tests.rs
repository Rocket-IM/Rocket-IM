//! 已接受尾的全部祖先一起回收，旧原请求仍返回各自真实终态。
use super::super::wire_rejection_tests::support as rejection_support;
use super::super::wire_send_order_test_support::*;
use super::*;

#[test]
fn closed_and_rejected_ancestors_keep_distinct_original_terminal_and_request() {
    let (f, key) = setup();
    let p1 = f.send("B", "M1");
    let request =
        json!({"operation":"wire_close_request","logical_message_id":"M1","attempt_id":"P1"});
    let original_request = f.call("B", request.clone());
    let closed = rejection_support::close(&f, &key, "P1", "C1");
    f.call("B", closed.clone());
    let p2_op = rejection_support::successor("P2", "P1", "C1");
    let p2 = f.call("B", p2_op.clone());
    let (record, cp) = rejection_support::advance(&f, &key, "C");
    let rejected = rejection_support::rejection(
        &rejection_support::body(&p2, &cp, "R1", Some(("P1", "C1"))),
        &key,
    );
    f.call("B", rejected.clone());
    rejection_support::apply(&f, "B", &record);
    let p3_op = rejection_support::successor("P3", "P2", "R1");
    let p3 = f.call("B", p3_op.clone());
    f.call("B", accept(&p3, &key, "K1"));
    download(&f, &key, "B", vec![], 0, 0);
    let provider = load(&f, "B").provider_entries;
    f.call(
        "B",
        json!({"operation":"wire_reclaim","receipt":permit(&f,&key,"B",&p3,"RC","deleted")}),
    );
    let state = load(&f, "B");
    assert_eq!(state.provider_entries, provider);
    assert!(state.wire.outbox.is_empty() && state.wire.tails.is_empty());
    assert!(state.wire_closures.is_none() && state.wire_rejections.is_none());
    let raw = serde_json::to_string(&state).unwrap();
    for old in [&p1, &p2, &p3] {
        assert!(!raw.contains(old["envelope"]["payload_bytes"].as_str().unwrap()));
    }
    assert_eq!(f.call("B", request), original_request);
    for (op, status, id) in [
        (
            json!({"operation":"wire_send","logical_message_id":"M1","attempt_id":"P1","payload":"synthetic test content"}),
            "closed",
            "C1",
        ),
        (p2_op, "rejected", "R1"),
    ] {
        let result = f.call("B", op);
        assert_eq!(result["status"], status);
        assert_eq!(result["closure_id"], id);
        assert_eq!(result["payload_reclaimed"], true);
        assert!(result.get("acceptance_id").is_none());
        if status == "rejected" {
            assert_eq!(result["code"], "state_stale");
        }
    }
    assert_eq!(f.call("B", p3_op)["acceptance_id"], "K1");
    for op in [closed, rejected, accept(&p3, &key, "K1")] {
        assert_eq!(f.call("B", op)["duplicate"], true);
    }
    reject(
        &f,
        "B",
        json!({"operation":"wire_close_request","logical_message_id":"M1","attempt_id":"P2"}),
        "rejection_conflict",
    );
    reject(
        &f,
        "B",
        json!({"operation":"wire_close_request","logical_message_id":"M1","attempt_id":"P3"}),
        "closure_conflict",
    );
    assert_eq!(f.call("B", rejection_support::next())["reused"], false);
}
