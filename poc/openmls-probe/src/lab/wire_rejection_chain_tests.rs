//! 主动封口和状态拒绝共用一条尝试链；真实 MLS 进度不因终态种类另开额度。
use super::*;

#[test]
fn rejection_and_closure_share_four_successors_in_both_chain_orders() {
    for rejected_first in [true, false] {
        let f = Fixture::with_devices(&["A", "B", "C", "D"]);
        let key = SigningKey::from_bytes(&[74; 32]);
        pin(&f, &key);
        enable(&f, "B");
        let mut sent = f.send("B", "M1");
        let mut previous = None;
        for i in 1..=4 {
            let attempt = format!("P{i}");
            let id = format!("T{i}");
            if i == if rejected_first { 1 } else { 2 } {
                let (record, cp) = advance(&f, &key, "C");
                let predecessor = previous
                    .as_ref()
                    .map(|(a, c): &(String, String)| (a.as_str(), c.as_str()));
                f.call("B", rejection(&body(&sent, &cp, &id, predecessor), &key));
                apply(&f, "B", &record);
            } else {
                let proof = close(&f, &key, &attempt, &id);
                f.call("B", proof);
            }
            sent = f.call("B", successor(&format!("P{}", i + 1), &attempt, &id));
            previous = Some((attempt, id));
        }
        assert_eq!(inspect(&f, "B")["outbox_count"], 5);
        let (record, cp) = advance(&f, &key, "D");
        f.call(
            "B",
            rejection(&body(&sent, &cp, "R5", Some(("P4", "T4"))), &key),
        );
        apply(&f, "B", &record);
        reject(
            &f,
            "B",
            successor("P6", "P5", "R5"),
            "send_order_successor_limit",
        );
        reject(&f, "B", next(), "send_order_pending");
    }
}

#[test]
fn rejection_required_checkpoint_can_be_a_verified_ancestor_of_current_state() {
    let f = Fixture::with_devices(&["A", "B", "C", "D"]);
    let key = SigningKey::from_bytes(&[74; 32]);
    pin(&f, &key);
    enable(&f, "B");
    let sent = f.send("B", "M1");
    let (first, cp) = advance(&f, &key, "C");
    f.call("B", rejection(&body(&sent, &cp, "R1", None), &key));
    apply(&f, "B", &first);
    let (second, current) = advance(&f, &key, "D");
    apply(&f, "B", &second);
    let next_packet = f.call("B", successor("P2", "P1", "R1"));
    let header: Value = serde_json::from_slice(
        &codec::decode(next_packet["envelope"]["header_bytes"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(header["authorization_version"], "3");
    assert_eq!(header["crypto_state_ref"], current["crypto_state_ref"]);
    f.call("B", accept(&next_packet, &key, "K1"));
    f.call("B", next());
}

#[test]
fn rejection_can_persist_after_real_self_removal_without_restoring_send_access() {
    let (f, key) = setup();
    enable(&f, "B");
    let sent = f.send("B", "M1");
    let (record, cp) = advance(&f, &key, "B");
    apply(&f, "B", &record);
    assert_eq!(
        f.call("B", json!({"operation":"permission_inspect"}))["access_removed"],
        true
    );
    let proof = rejection(&body(&sent, &cp, "R1", None), &key);
    f.call("B", proof.clone());
    let before = fs::read(f.root.join("B/state.enc")).unwrap();
    assert_eq!(f.call("B", proof)["duplicate"], true);
    assert!(before == fs::read(f.root.join("B/state.enc")).unwrap());
    reject(&f, "B", successor("P2", "P1", "R1"), "access_removed");
}
