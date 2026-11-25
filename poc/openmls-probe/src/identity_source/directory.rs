//! 从完整历史验证业务授权和旧设备批准；不采信Service声称的首次/最新。
use super::*;
use crate::{
    device_registration,
    permission::{commit_digest, receipts::SignedRecord, types, Member, PermissionError},
};
pub fn hash(s: &Snapshot) -> Result<String, PermissionError> {
    Ok(commit_digest(&serde_json::to_vec(s).map_err(|_| {
        crate::key_package::error("identity_source_encoding")
    })?))
}
pub fn target(entry: &Entry) -> Result<Member, PermissionError> {
    let p = device_registration::verify_proof(&entry.registration)?;
    Ok(Member {
        account_id: p.account_id,
        device_id: p.device_id,
        signature_key: p.signature_key,
    })
}
pub fn permit(proof: &SignedRecord, roots: &Roots) -> Result<Permit, PermissionError> {
    let Document::Permit(p) = verify(proof, &roots.business_key)? else {
        return Err(crate::key_package::error("identity_source_permit"));
    };
    ensure(
        p.service_id == roots.service_id
            && p.issuer == roots.issuer
            && p.audience == roots.audience,
        "identity_source_root",
    )?;
    Ok(p)
}
pub fn verify_chain(chain: &[Snapshot], roots: &Roots) -> Result<(), PermissionError> {
    roots.validate()?;
    ensure(!chain.is_empty() && chain.len() <= 16, "resource_exhausted")?;
    let mut previous: Option<&Snapshot> = None;
    let mut known_subject: Option<String> = None;
    for (i, s) in chain.iter().enumerate() {
        types::id(&s.account_id)?;
        ensure(
            s.protocol_version == "rim-authorized-device-directory-1"
                && s.service_id == roots.service_id
                && s.version == (i + 1).to_string()
                && !s.devices.is_empty()
                && s.devices.len() <= 8,
            "identity_source_directory",
        )?;
        ensure(
            s.previous_sha256
                == match previous {
                    Some(old) => hash(old)?,
                    None => "0".repeat(64),
                },
            "directory_gap",
        )?;
        if let Some(old) = previous {
            ensure(old.account_id == s.account_id, "directory_context")?;
            for e in &old.devices {
                ensure(
                    s.devices.iter().any(|n| {
                        n.registration == e.registration
                            && n.permit == e.permit
                            && n.approval == e.approval
                            && n.accepted_at_ms == e.accepted_at_ms
                            && (e.status != "revoked" || n.status == "revoked")
                    }),
                    "directory_omission",
                )?;
            }
        }
        let mut last = String::new();
        let mut keys = std::collections::BTreeSet::new();
        for e in &s.devices {
            let reg = device_registration::verify_proof(&e.registration)?;
            let p = permit(&e.permit, roots)?;
            ensure(
                p.target == target(e)?
                    && reg.service_id == s.service_id
                    && reg.account_id == s.account_id
                    && reg.device_id > last
                    && keys.insert(reg.signature_key.clone())
                    && matches!(e.status.as_str(), "active" | "revoked")
                    && p.challenge_nonce == reg.challenge_nonce
                    && p.challenge_sha256
                        == commit_digest(&types::bytes(&e.registration.statement_bytes, 4096)?),
                "identity_source_binding",
            )?;
            if let Some(subject) = &known_subject {
                ensure(subject == &p.subject, "identity_source_subject")?;
            } else {
                known_subject = Some(p.subject.clone());
            }
            let accepted = types::decimal(&e.accepted_at_ms)?;
            ensure(
                types::decimal(&p.issued_at_ms)? <= accepted
                    && accepted < types::decimal(&p.expires_at_ms)?
                    && types::decimal(&reg.issued_at_ms)? <= accepted
                    && accepted < types::decimal(&reg.expires_at_ms)?,
                "identity_source_expired",
            )?;
            let new = previous
                .is_none_or(|old| !old.devices.iter().any(|x| x.registration == e.registration));
            if new {
                if let Some(old) = previous {
                    ensure(p.purpose == "add_device", "identity_source_approval")?;
                    let proof = e
                        .approval
                        .as_ref()
                        .ok_or_else(|| crate::key_package::error("identity_source_approval"))?;
                    let Document::Approval(a) = parse(proof)? else {
                        return Err(crate::key_package::error("identity_source_approval"));
                    };
                    verify(proof, &a.actor.signature_key)?;
                    ensure(
                        a.service_id == s.service_id
                            && a.target == p.target
                            && a.permit_sha256 == crate::key_package::digest(&e.permit)?
                            && a.previous_version == old.version
                            && a.previous_sha256 == hash(old)?
                            && accepted < types::decimal(&a.expires_at_ms)?
                            && old.devices.iter().any(|x| {
                                x.status == "active" && target(x).ok().as_ref() == Some(&a.actor)
                            }),
                        "identity_source_approval",
                    )?;
                } else {
                    ensure(
                        p.purpose == "first_device" && e.approval.is_none() && s.devices.len() == 1,
                        "identity_source_first",
                    )?;
                }
            }
            last = reg.device_id;
        }
        previous = Some(s);
    }
    Ok(())
}
