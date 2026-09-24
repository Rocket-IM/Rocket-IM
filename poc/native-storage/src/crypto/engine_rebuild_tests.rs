//! 真实 OpenMLS 三成员加入、绑定拒绝及 provider 重启验证，不模拟 MLS 密文。
use super::{credential_with_key, group_id, Engine, SUITE};
use crate::crypto::{
    anchor::{
        protocol,
        rebuild_protocol::{self, Member, Plan, RebuildTrust},
    },
    contract::Scope,
    model::{decode, encode, hash, Identity},
};
use openmls::prelude::{tls_codec::Serialize as _, KeyPackage};
use serde_json::{json, Value};

fn scope(account: &str, device: &str) -> Scope {
    Scope {
        service: "native-rebuild-test".into(),
        account: account.into(),
        device: device.into(),
    }
}

struct Fixture {
    source: Engine,
    successor: Engine,
    bob: Identity,
    plan: Value,
    prior_welcome: String,
}
impl Fixture {
    fn new() -> Self {
        let mut source = Engine::new(&scope("alice", "authorizer")).unwrap();
        let bob = Engine::new(&scope("bob", "bob-device")).unwrap().identity();
        let prior_welcome = source.create_group("approved-target", &bob).unwrap();
        let successor = Engine::new(&scope("alice", "successor")).unwrap();
        let old = Engine::new(&scope("alice", "old-device"))
            .unwrap()
            .identity();
        let own = source.identity();
        let peer = successor.identity();
        let plan = Plan {
            protocol_version: rebuild_protocol::PROTOCOL.into(),
            rebuild_id: hash(b"unique rebuild"),
            old_scope: protocol::Scope {
                service: old.service,
                account: old.account,
                device: old.device,
                identity_key: protocol::encode_hex(&decode(&old.identity_key).unwrap()),
                store_id: hash(b"old store"),
            },
            old_head: hash(b"old head"),
            old_txn: hash(b"old txn"),
            old_revision: "4".into(),
            old_conversation_id: "old-conversation".into(),
            old_group_id: encode(&group_id(&own.service, "old-conversation")),
            anchor_public_key: hash(b"anchor public key"),
            successor_scope: protocol::Scope {
                service: peer.service.clone(),
                account: peer.account.clone(),
                device: peer.device.clone(),
                identity_key: protocol::encode_hex(&decode(&peer.identity_key).unwrap()),
                store_id: hash(b"new store"),
            },
            successor_head: hash(b"new initial head"),
            successor_client_public_key: hash(b"new client public key"),
            key_package_sha256: hash(&decode(&peer.key_package).unwrap()),
            trust: RebuildTrust {
                authorizer: Member::from_identity(&own),
                checkpoint: serde_json::from_value(source.checkpoint().unwrap()).unwrap(),
                relay_receipt_key: own.identity_key.clone(),
            },
        };
        plan.validate().unwrap();
        Self {
            source,
            successor,
            bob,
            plan: serde_json::to_value(plan).unwrap(),
            prior_welcome,
        }
    }
    fn members(&self) -> Vec<Identity> {
        vec![
            self.source.identity(),
            self.bob.clone(),
            self.successor.identity(),
        ]
    }
    fn add(&mut self) -> Value {
        self.source
            .add_rebuild_member(&self.successor.identity(), &self.plan)
            .unwrap()
    }
}

#[test]
fn rebuild_real_add_join_and_bidirectional_after_restore() {
    let mut f = Fixture::new();
    let before = f.source.checkpoint().unwrap();
    let members = f.members();
    let authorizer = f.source.identity();
    let added = f.add();
    let (plan, admission) = Engine::validate_rebuild_result(&added).unwrap();
    assert_eq!(serde_json::to_value(plan).unwrap(), f.plan);
    assert_eq!(admission.checkpoint_before.members.len(), 2);
    assert_eq!(admission.checkpoint_after.members.len(), 3);
    assert_ne!(
        before["crypto_state_ref"],
        added["checkpoint"]["crypto_state_ref"]
    );
    f.successor
        .join_rebuild(
            "approved-target",
            &members,
            &authorizer,
            added["welcome"].as_str().unwrap(),
        )
        .unwrap();
    assert_eq!(
        f.successor.checkpoint().unwrap(),
        f.source.checkpoint().unwrap()
    );
    assert_eq!(f.successor.group_id().unwrap(), admission.group_id);
    let mut source =
        Engine::restore(&f.source.export().unwrap(), &scope("alice", "authorizer")).unwrap();
    let mut successor =
        Engine::restore(&f.successor.export().unwrap(), &scope("alice", "successor")).unwrap();
    let sent = source.send("new-1", "批准后合成消息").unwrap();
    assert_eq!(successor.receive(&sent).unwrap().text, "批准后合成消息");
    let reply = successor.send("new-2", "新设备合成回复").unwrap();
    assert_eq!(source.receive(&reply).unwrap().text, "新设备合成回复");
    assert!(source
        .add_rebuild_member(&f.successor.identity(), &f.plan)
        .is_err());
}

#[test]
fn rebuild_approval_rejects_format_valid_foreign_checkpoint_and_authorizer() {
    let f = Fixture::new();
    for change in 0..5 {
        let mut plan = f.plan.clone();
        match change {
            0 => plan["trust"]["checkpoint"]["crypto_state_ref"] = hash(b"foreign state").into(),
            1 => plan["trust"]["checkpoint"]["conversation_id"] = "foreign-target".into(),
            2 => plan["trust"]["checkpoint"]["authorization_version"] = "7".into(),
            3 => plan["trust"]["authorizer"]["signature_key"] = f.bob.identity_key.clone().into(),
            _ => plan["successor_scope"]["account"] = "other-account".into(),
        }
        assert!(f.source.approve_plan(&plan).is_err());
    }
    let approved = f.source.approve_plan(&f.plan).unwrap();
    rebuild_protocol::verify_approval(&serde_json::from_value(f.plan).unwrap(), &approved).unwrap();
}

#[test]
fn rebuild_add_rejects_successor_scope_and_key_package_substitution() {
    let f = Fixture::new();
    let source = f.source.export().unwrap();
    let other = Engine::new(&scope("alice", "other-device")).unwrap();
    for change in 0..5 {
        let mut candidate = Engine::restore(&source, &scope("alice", "authorizer")).unwrap();
        let mut identity = f.successor.identity();
        match change {
            0 => identity.device = "other-device".into(),
            1 => identity.identity_key = other.identity().identity_key,
            2 => identity.key_package = other.identity().key_package,
            3 => identity.account = "other-account".into(),
            _ => identity.service = "other-service".into(),
        }
        assert!(candidate.add_rebuild_member(&identity, &f.plan).is_err());
    }
    // 即使计划的摘要随替换包一起改，也必须由真实 KeyPackage 绑定设备 credential 和签名公钥。
    let mut peer = f.successor.identity();
    peer.key_package = other.identity().key_package;
    let mut plan = f.plan;
    plan["key_package_sha256"] = hash(&decode(&peer.key_package).unwrap()).into();
    let mut source = Engine::restore(&source, &scope("alice", "authorizer")).unwrap();
    assert!(source.add_rebuild_member(&peer, &plan).is_err());
}

#[test]
fn rebuild_join_rejects_wrong_sender_members_target_package_and_old_welcome() {
    let mut f = Fixture::new();
    let initial = f.successor.export().unwrap();
    let authorizer = f.source.identity();
    let members = f.members();
    let added = f.add();
    for change in 0..8 {
        let mut candidate = Engine::restore(&initial, &scope("alice", "successor")).unwrap();
        let mut expected = members.clone();
        let mut sender = authorizer.clone();
        let mut target = "approved-target";
        let mut welcome = added["welcome"].as_str().unwrap();
        match change {
            0 => target = "other-target",
            1 => sender = f.bob.clone(),
            2 => {
                expected.remove(1);
            }
            3 => expected[1] = expected[0].clone(),
            4 => expected[1].identity_key = f.successor.identity().identity_key,
            5 => welcome = &f.prior_welcome,
            6 => expected[2].key_package = f.bob.key_package.clone(),
            _ => {
                sender.identity_key = f.bob.identity_key.clone();
                expected[0].identity_key = sender.identity_key.clone();
            }
        }
        assert!(candidate
            .join_rebuild(target, &expected, &sender, welcome)
            .is_err());
    }
    let mut other = Engine::new(&scope("alice", "successor")).unwrap();
    assert!(other
        .join_rebuild(
            "approved-target",
            &members,
            &authorizer,
            added["welcome"].as_str().unwrap()
        )
        .is_err());
}

#[test]
fn rebuild_new_member_cannot_receive_pre_add_ciphertext() {
    let mut f = Fixture::new();
    let old_message = f.source.send("pre-add", "加入前合成消息").unwrap();
    let members = f.members();
    let authorizer = f.source.identity();
    let added = f.add();
    f.successor
        .join_rebuild(
            "approved-target",
            &members,
            &authorizer,
            added["welcome"].as_str().unwrap(),
        )
        .unwrap();
    assert_eq!(
        f.successor.receive(&old_message).unwrap_err().code,
        "crypto_scope_mismatch"
    );
    let new_message = f.source.send("post-add", "加入后合成消息").unwrap();
    assert_eq!(
        f.successor.receive(&new_message).unwrap().text,
        "加入后合成消息"
    );
}

#[test]
fn rebuild_saved_members_cannot_be_removed_duplicated_or_replaced() {
    let mut f = Fixture::new();
    let added = f.add();
    assert_eq!(added["checkpoint"]["members"].as_array().unwrap().len(), 3);
    let saved: Value = serde_json::from_slice(&f.source.export().unwrap()).unwrap();
    for change in 0..4 {
        let mut changed = saved.clone();
        match change {
            0 => {
                changed.as_object_mut().unwrap().remove("rebuild_members");
            }
            1 => changed["rebuild_members"][1] = changed["rebuild_members"][0].clone(),
            2 => changed["rebuild_members"][0]["identityKey"] = f.bob.identity_key.clone().into(),
            _ => changed["peer"]["device"] = "foreign-peer".into(),
        }
        assert!(Engine::restore(
            &serde_json::to_vec(&changed).unwrap(),
            &scope("alice", "authorizer")
        )
        .is_err());
    }
    let legacy = Fixture::new().source.export().unwrap();
    assert!(serde_json::from_slice::<Value>(&legacy)
        .unwrap()
        .get("rebuild_members")
        .is_none());
    Engine::restore(&legacy, &scope("alice", "authorizer")).unwrap();
}

#[test]
fn rebuild_committed_result_rejects_tampered_proof_or_payload() {
    let mut f = Fixture::new();
    let added = f.add();
    for change in 0..6 {
        let mut invalid = added.clone();
        match change {
            0 => invalid["welcome"] = encode(b"changed welcome").into(),
            1 => invalid["commit"] = encode(b"changed commit").into(),
            2 => invalid["checkpoint"]["crypto_state_ref"] = hash(b"changed checkpoint").into(),
            3 => invalid["approval"]["signature_bytes"] = encode(&[0; 64]).into(),
            4 => invalid["admission"]["signature_bytes"] = encode(&[0; 64]).into(),
            _ => invalid["unrecognized"] = json!(true),
        }
        assert!(Engine::validate_rebuild_result(&invalid).is_err());
    }
}

#[test]
fn rebuild_welcome_must_consume_exact_original_key_package() {
    let mut f = Fixture::new();
    let original = f.successor.identity();
    // 同一私有 provider 保存两个合法包，模拟可选包选择不能充当精确批准绑定。
    let second = KeyPackage::builder()
        .build(
            SUITE,
            &f.successor.provider,
            &f.successor.signer,
            credential_with_key(&original).unwrap(),
        )
        .unwrap();
    let mut offered = original.clone();
    offered.key_package = encode(&second.key_package().tls_serialize_detached().unwrap());
    assert_ne!(offered.key_package, original.key_package);
    f.plan["key_package_sha256"] = hash(&decode(&offered.key_package).unwrap()).into();
    let members = f.members();
    let authorizer = f.source.identity();
    let added = f.source.add_rebuild_member(&offered, &f.plan).unwrap();
    assert_eq!(
        f.successor
            .join_rebuild(
                "approved-target",
                &members,
                &authorizer,
                added["welcome"].as_str().unwrap()
            )
            .unwrap_err()
            .code,
        "crypto_identity_mismatch"
    );
    assert!(f.successor.export().is_err());
}
