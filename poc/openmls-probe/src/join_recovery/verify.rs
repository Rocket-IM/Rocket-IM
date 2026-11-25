//! 回执原件及候选的完整绑定；R0 不证明设备已完成 MLS 状态安装。
pub use super::validate::authorize;
use super::*;
use crate::permission::{
    self,
    receipts::{self, RecoveryRecord, SignedRecord},
    types as scalar, PermissionCheckpoint, PermissionError,
};
use serde::Deserialize;
use serde_json::{json, Value};

pub fn root(
    record: &RecoveryRecord,
    key: &str,
) -> Result<(AdmissionRef, permission::Member, bool, String), PermissionError> {
    let (receipt, statement) = receipts::verify_receipt(key, record)?;
    require(
        receipt.outcome == receipts::Outcome::Accepted
            && statement.protocol_version == "rim-permission-2",
        "recovery_invalid",
    )?;
    let (target, device, package) = match &statement.action {
        permission::Action::AddMember {
            member,
            key_package_sha256,
            ..
        } => (member.clone(), false, key_package_sha256.clone()),
        permission::Action::AddDevice {
            member,
            key_package_sha256,
            ..
        } => (member.clone(), true, key_package_sha256.clone()),
        _ => {
            return Err(PermissionError::new(
                "recovery_invalid",
                "原入口必须为已接受的 v2 Add",
            ))
        }
    };
    Ok((
        admission_ref(&statement.change_id, &record.change, &record.receipt)?,
        target,
        device,
        package,
    ))
}
pub fn control(
    proof: &SignedRecord,
    intent_proof: &SignedRecord,
) -> Result<(Control, Intent), PermissionError> {
    let i = parse_intent(intent_proof)?;
    let Request::Control(c) = parse_request(proof)? else {
        return Err(PermissionError::new(
            "recovery_invalid",
            "需要领取或关闭请求",
        ));
    };
    require(
        c.protocol_version == i.protocol_version
            && c.witness_profile == i.witness_profile
            && c.policy_ref == i.policy_ref
            && c.scope == i.scope
            && c.recovery_id == i.request_id
            && c.change_id == i.change_id
            && c.intent_sha256 == signed_digest(intent_proof)?
            && (c.signer == i.actor || (c.kind == ControlKind::Close && c.signer == i.signer)),
        "recovery_invalid",
    )?;
    Ok((*c, i))
}
pub fn receipt_context(
    receipt: &Receipt,
    i: &Intent,
    proof: &SignedRecord,
) -> Result<(), PermissionError> {
    require(
        receipt.witness_profile == i.witness_profile
            && receipt.policy_ref == i.policy_ref
            && receipt.scope == i.scope
            && receipt.recovery_id == i.request_id
            && receipt.change_id == i.change_id
            && receipt.root_admission == i.root_admission
            && receipt.current_admission == i.current_admission
            && receipt.target == i.signer
            && receipt.actor == i.actor
            && receipt.intent_sha256 == signed_digest(proof)?,
        "recovery_invalid",
    )
}
pub fn allocation(
    i: &Intent,
    intent: &SignedRecord,
    claim: &SignedRecord,
    proof: &SignedRecord,
    key: &str,
) -> Result<String, PermissionError> {
    let (c, _) = control(claim, intent)?;
    require(c.kind == ControlKind::Claim, "recovery_invalid")?;
    let receipt = verify_receipt(key, proof)?;
    receipt_context(&receipt, i, intent)?;
    let ResultBody::Allocated {
        claim_sha256,
        key_package_sha256,
        key_package_ref,
        predecessor,
    } = receipt.result
    else {
        return Err(PermissionError::new("recovery_invalid", "需要分配原件"));
    };
    require(
        claim_sha256 == signed_digest(claim)?
            && key_package_sha256 == i.key_package_sha256
            && predecessor == i.predecessor,
        "recovery_invalid",
    )?;
    Ok(key_package_ref)
}
pub fn public_candidate(
    cp: &PermissionCheckpoint,
    root_record: &RecoveryRecord,
    key: &str,
    b: &PublicBundle,
) -> Result<(PermissionCheckpoint, Statement, Intent), PermissionError> {
    let i = parse_intent(&b.intent)?;
    let (root_ref, target, device, _) = root(root_record, key)?;
    require(
        root_ref == i.root_admission
            && target == i.signer
            && commit_group(&root_record.change.commit_bytes)? == i.scope.group_id
            && commit_group(&b.change.commit_bytes)? == i.scope.group_id,
        "recovery_invalid",
    )?;
    authorize(cp, &i, device)?;
    require(
        Floor::from(cp) == i.predecessor,
        "recovery_predecessor_changed",
    )?;
    let reference = allocation(&i, &b.intent, &b.claim, &b.allocation, key)?;
    let s: Statement = raw(&b.change.statement_bytes)?;
    s.validate()?;
    let a = &s.action;
    require(
        s.witness_profile == i.witness_profile
            && s.policy_ref == i.policy_ref
            && s.scope == i.scope
            && s.change_id == i.change_id
            && s.actor == i.actor
            && a.target == i.signer
            && a.root_admission == i.root_admission
            && a.current_admission == i.current_admission
            && a.recovery_id == i.request_id
            && a.intent_sha256 == signed_digest(&b.intent)?
            && a.allocation_sha256 == signed_digest(&b.allocation)?
            && a.key_package_sha256 == i.key_package_sha256
            && a.key_package_ref == reference
            && s.previous_authorization_version == cp.authorization_version
            && s.from_state_ref == cp.crypto_state_ref
            && scalar::decimal(&cp.authorization_version)?.checked_add(1)
                == Some(scalar::decimal(&s.authorization_version)?)
            && s.to_state_ref != s.from_state_ref
            && scalar::decimal(&s.issued_at_unix_secs)? >= scalar::decimal(&i.issued_at_unix_secs)?
            && scalar::decimal(&s.expires_at_unix_secs)?
                <= scalar::decimal(&i.expires_at_unix_secs)?,
        "recovery_invalid",
    )?;
    require(
        permission::commit_digest(&scalar::bytes(&b.change.commit_bytes, 524288)?)
            == s.commit_sha256,
        "recovery_invalid",
    )?;
    receipts::signature(
        &s.actor.signature_key,
        s.domain()?,
        &scalar::bytes(&b.change.statement_bytes, 16384)?,
        &b.change.signature_bytes,
    )?;
    let mut next = cp.clone();
    next.authorization_version = s.authorization_version.clone();
    next.crypto_state_ref = s.to_state_ref.clone();
    Ok((next, s, i))
}
pub fn candidate(
    cp: &PermissionCheckpoint,
    root_record: &RecoveryRecord,
    key: &str,
    b: &Bundle,
    fresh: bool,
) -> Result<(PermissionCheckpoint, Statement, Intent), PermissionError> {
    let (next, s, i) = public_candidate(cp, root_record, key, &PublicBundle::from(b))?;
    require(
        permission::commit_digest(&scalar::bytes(&b.key_package, 8192)?)
            == s.action.key_package_sha256
            && permission::commit_digest(&scalar::bytes(&b.welcome, 524288)?)
                == s.action.welcome_sha256,
        "recovery_invalid",
    )?;
    if fresh {
        let material =
            crate::key_package::material::inspect(&b.key_package, &i.scope.service_id, &i.signer)?;
        require(
            material.key_package_ref == s.action.key_package_ref,
            "recovery_invalid",
        )?;
    }
    Ok((next, s, i))
}
pub fn accepted_public(
    cp: &PermissionCheckpoint,
    root_record: &RecoveryRecord,
    key: &str,
    r: &PublicRecord,
) -> Result<(PermissionCheckpoint, Statement, Intent), PermissionError> {
    let (next, s, i) = public_candidate(cp, root_record, key, &r.bundle)?;
    let receipt = verify_receipt(key, &r.receipt)?;
    receipt_context(&receipt, &i, &r.bundle.intent)?;
    require(
        matches!(receipt.result,ResultBody::Accepted {ref allocation_sha256,ref candidate_sha256,ref checkpoint}
        if *allocation_sha256==signed_digest(&r.bundle.allocation)? && *candidate_sha256==candidate_digest(&r.bundle.change)? && *checkpoint==next),
        "recovery_invalid",
    )?;
    Ok((next, s, i))
}
pub fn accepted_evidence(
    cp: &PermissionCheckpoint,
    root_record: &RecoveryRecord,
    key: &str,
    r: &Evidence,
) -> Result<(PermissionCheckpoint, Statement, Intent), PermissionError> {
    match r {
        Evidence::Full(r) => accepted(cp, root_record, key, r),
        Evidence::Public(r) => accepted_public(cp, root_record, key, r),
    }
}
pub fn accepted(
    cp: &PermissionCheckpoint,
    root_record: &RecoveryRecord,
    key: &str,
    r: &Record,
) -> Result<(PermissionCheckpoint, Statement, Intent), PermissionError> {
    let (next, s, i) = candidate(cp, root_record, key, &r.bundle, false)?;
    let receipt = verify_receipt(key, &r.receipt)?;
    receipt_context(&receipt, &i, &r.bundle.intent)?;
    require(
        matches!(receipt.result,ResultBody::Accepted {ref allocation_sha256,ref candidate_sha256,ref checkpoint}
        if *allocation_sha256==signed_digest(&r.bundle.allocation)? && *candidate_sha256==candidate_digest(&r.bundle.change)? && *checkpoint==next),
        "recovery_invalid",
    )?;
    Ok((next, s, i))
}
pub fn execute(input: &str) -> Result<Value, PermissionError> {
    #[derive(Deserialize)]
    #[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
    enum Call {
        VerifyWitnessPolicy {
            policy: witness::PolicyEnvelope,
        },
        VerifyWitnessActivation {
            activation_bytes: String,
        },
        #[serde(rename = "verify_recovery_request")]
        Request {
            proof: SignedRecord,
        },
        #[serde(rename = "verify_recovery_control")]
        Control {
            proof: SignedRecord,
            intent: SignedRecord,
        },
        #[serde(rename = "verify_recovery_root")]
        Root {
            record: RecoveryRecord,
            source_key: String,
            join: permission::admission::JoinMaterial,
        },
        #[serde(rename = "verify_recovery_candidate")]
        Candidate {
            checkpoint: PermissionCheckpoint,
            root: RecoveryRecord,
            source_key: String,
            bundle: Bundle,
        },
        #[serde(rename = "verify_recovery_accepted")]
        Accepted {
            checkpoint: PermissionCheckpoint,
            root: RecoveryRecord,
            source_key: String,
            record: Record,
        },
        #[serde(rename = "verify_recovery_receipt")]
        Receipt {
            source_key: String,
            proof: SignedRecord,
        },
    }
    let call: Call = serde_json::from_str(input)
        .map_err(|_| PermissionError::new("recovery_invalid", "验证输入无效"))?;
    let result = match call {
        Call::VerifyWitnessPolicy { policy } => {
            json!({"statement":witness::parse_policy(&policy)?, "reference":witness::policy_ref(&policy)})
        }
        Call::VerifyWitnessActivation { activation_bytes } => {
            json!({"statement":witness::parse_activation(&activation_bytes)?})
        }
        Call::Request { proof } => json!({"statement":parse_request(&proof)?}),
        Call::Control { proof, intent } => {
            let (c, i) = control(&proof, &intent)?;
            json!({"statement":c,"intent":i})
        }
        Call::Root {
            record,
            source_key,
            join,
        } => {
            let (_, statement) = receipts::verify_receipt(&source_key, &record)?;
            permission::admission::verify_binding(&statement, &join)?;
            let allocation = join
                .allocation
                .as_ref()
                .ok_or_else(|| PermissionError::new("recovery_invalid", "缺少原分配"))?;
            crate::key_package::verify_receipt(&source_key, &allocation.receipt)?;
            let (r, t, d, p) = root(&record, &source_key)?;
            json!({"reference":r,"target":t,"add_device":d,"key_package_sha256":p,"group_id":commit_group(&record.change.commit_bytes)?})
        }
        Call::Candidate {
            checkpoint,
            root,
            source_key,
            bundle,
        } => {
            let (cp, s, i) = candidate(&checkpoint, &root, &source_key, &bundle, true)?;
            json!({"checkpoint":cp,"statement":s,"intent":i})
        }
        Call::Accepted {
            checkpoint,
            root,
            source_key,
            record,
        } => {
            let (cp, s, i) = accepted(&checkpoint, &root, &source_key, &record)?;
            json!({"checkpoint":cp,"statement":s,"intent":i})
        }
        Call::Receipt { source_key, proof } => {
            json!({"statement":verify_receipt(&source_key,&proof)?})
        }
    };
    Ok(json!({"ok":true,"result":result}))
}
