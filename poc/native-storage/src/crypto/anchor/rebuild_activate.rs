//! 独立批准、唯一后继、真实Welcome与已提交日志恢复；不重算未决入群。
use super::*;
use crate::crypto::anchor::{rebuild_protocol, rebuild_remote};
use crate::crypto::contract::Action;
use serde::Deserialize;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Material {
    approval: protocol::Signed,
    admission: protocol::Signed,
    welcome: String,
    commit: String,
    checkpoint: rebuild_protocol::Checkpoint,
}
impl RebuildClient {
    pub fn activate(&mut self, material: Value, fault: &str) -> Reply {
        let mut metrics = Metrics::default();
        let mut newly_active = false;
        let result = if matches!(
            fault,
            "none"
                | "after_link"
                | "after_join_reserve"
                | "after_join_crypto"
                | "before_join_commit"
                | "after_join_commit"
                | "after_join_finish"
                | "after_active"
                | "refuse_join_commit"
        ) {
            self.activate_inner(material, fault, &mut metrics, &mut newly_active)
        } else {
            Err(error("rebuild_fault_invalid"))
        };
        let events = if result.is_ok() && newly_active {
            vec![json!({"kind":"rebuild_active","scope":self.scope})]
        } else {
            vec![]
        };
        self.reply(result, metrics, events)
    }
    fn activate_inner(
        &mut self,
        raw: Value,
        fault: &str,
        metrics: &mut Metrics,
        newly_active: &mut bool,
    ) -> Result<Value> {
        let mut state = self.state()?;
        let recovering_committed_join = state.stage == "joined";
        let plan: Plan = serde_json::from_value(
            state
                .details
                .get("plan")
                .cloned()
                .ok_or_else(|| error("rebuild_prepare_required"))?,
        )
        .map_err(|_| error("rebuild_plan_invalid"))?;
        let material: Material =
            serde_json::from_value(raw.clone()).map_err(|_| error("rebuild_material_invalid"))?;
        rebuild_protocol::verify_approval(&plan, &material.approval)?;
        let admission = rebuild_protocol::verify_admission(&plan, &material.admission)?;
        if protocol::hash(&model::decode(&material.welcome)?) != admission.welcome_sha256
            || protocol::hash(&model::decode(&material.commit)?) != admission.commit_sha256
            || material.checkpoint != admission.checkpoint_after
            || json!(admission.successor_identity) != state.details["identity"]
            || (state.details.get("material").is_some() && state.details["material"] != raw)
        {
            return Err(error("rebuild_material_mismatch"));
        }
        if state.stage == "planned" {
            // 封存远端之前再核对旧本地原件；已完成结果优先走原recover。
            let signer = self.old.remote.clone();
            let evidence = self
                .old
                .inner
                .database
                .call(move |store| store.rebuild_fence(&signer))?;
            if evidence != state.details["old"] {
                return Err(error("rebuild_old_state_changed"));
            }
            let receipt = rebuild_remote::rpc(
                &self.old.remote,
                &plan,
                &material.approval,
                rebuild_remote::Action::Link,
            )?;
            if receipt.response.cancelled {
                return Err(error("rebuild_cancelled"));
            }
            pause(fault, "after_link", metrics)?;
            let mut next = state.clone();
            next.stage = "linked".into();
            next.details["material"] = raw;
            next.details["link_receipt"] = json!(receipt);
            state = self.save_state(&state, next)?;
        } else {
            let receipt = rebuild_remote::rpc(
                &self.old.remote,
                &plan,
                &material.approval,
                rebuild_remote::Action::Inspect,
            )?;
            if receipt.response.cancelled
                || receipt.response.status != rebuild_remote::Status::Linked
            {
                return Err(error("rebuild_not_linked"));
            }
        }
        if state.stage == "joining" {
            return Err(error("rebuild_join_unresolved"));
        }
        if state.stage == "linked" {
            let authorizer = Identity {
                service: plan.old_scope.service.clone(),
                account: plan.trust.authorizer.account_id.clone(),
                device: plan.trust.authorizer.device_id.clone(),
                identity_key: plan.trust.authorizer.signature_key.clone(),
                key_package: String::new(),
            };
            let request = Request {
                request_id: "rebuild-join".into(),
                action: Action::CreateGroup {
                    conversation: plan.trust.checkpoint.conversation_id.clone(),
                    peer: authorizer.clone(),
                },
                fault: Fault::None,
            };
            self.candidate()?.reserve(
                json!({"rebuild_join":plan.digest()?}),
                super::super::contract::AnchorFault::None,
                true,
            )?;
            let mut joining = state.clone();
            joining.stage = "joining".into();
            let old = state.clone();
            let next = joining.clone();
            let owned = request.clone();
            let signer = self.old.remote.clone();
            let prepared = self
                .candidate()?
                .inner
                .database
                .call(move |store| store.rebuild_prepare_join(&old, &next, &owned, &signer))?;
            pause(fault, "after_join_reserve", metrics)?;
            metrics.provider_restores += 1;
            let mut engine = Engine::restore(
                &prepared
                    .provider
                    .ok_or_else(|| error("rebuild_provider_missing"))?,
                &self.scope,
            )?;
            if json!(engine.identity()) != state.details["identity"] {
                return Err(error("rebuild_identity_mismatch"));
            }
            let members = admission
                .checkpoint_after
                .members
                .iter()
                .map(|member| {
                    if member.device_id == self.scope.device
                        && member.account_id == self.scope.account
                    {
                        admission.successor_identity.clone()
                    } else {
                        Identity {
                            service: self.scope.service.clone(),
                            account: member.account_id.clone(),
                            device: member.device_id.clone(),
                            identity_key: member.signature_key.clone(),
                            key_package: String::new(),
                        }
                    }
                })
                .collect::<Vec<_>>();
            metrics.candidate_joins += 1;
            engine.join_rebuild(
                &plan.trust.checkpoint.conversation_id,
                &members,
                &authorizer,
                &material.welcome,
            )?;
            if engine.checkpoint()? != json!(admission.checkpoint_after)
                || engine.group_id()? != admission.group_id
            {
                return Err(error("rebuild_join_context_mismatch"));
            }
            pause(fault, "after_join_crypto", metrics)?;
            let outcome = Outcome {
                revision: "2".into(),
                kind: "create_group".into(),
                cached: false,
                value: json!({"welcome":material.welcome}),
            };
            let candidate = Candidate {
                provider: engine.export()?,
                identity: engine.identity(),
                conversation: engine.conversation(),
                encryptions: "0".into(),
                processed_cursor: "0".into(),
                decryptions: "0".into(),
                outcome,
            };
            pause(fault, "before_join_commit", metrics)?;
            let mut joined = joining.clone();
            joined.stage = "joined".into();
            let next = joined.clone();
            let signer = self.old.remote.clone();
            let sql_fault = if fault == "refuse_join_commit" {
                SqlFault::RefuseCommit
            } else {
                SqlFault::None
            };
            self.candidate()?.inner.database.call(move |store| {
                store.rebuild_join(&joining, &request, candidate, &next, &signer, sql_fault)
            })?;
            state = joined;
            pause(fault, "after_join_commit", metrics)?;
        }
        if state.stage == "joined" {
            let local = self
                .candidate()?
                .inner
                .database
                .call(|store| store.anchor_local())?;
            if let Some(journal) = local.journal {
                if local.head != journal.target || local.gate.as_ref() != Some(&journal.gate) {
                    return Err(error("rebuild_join_state_changed"));
                }
                self.candidate()?.finish(&journal)?;
                pause(fault, "after_join_finish", metrics)?;
                self.candidate()?
                    .inner
                    .database
                    .call(move |store| store.anchor_clear(&journal.gate, &journal.target))?;
            }
            let (local, remote) = self.candidate()?.state()?;
            super::super::healthy(&local, &remote)?;
            let mut active = state.clone();
            active.stage = "active".into();
            state = self.save_state(&state, active)?;
            *newly_active = !recovering_committed_join;
            pause(fault, "after_active", metrics)?;
        }
        if state.stage != "active" {
            return Err(error("rebuild_state_unresolved"));
        }
        let (local, remote) = self.candidate()?.state()?;
        super::super::healthy(&local, &remote)?;
        public(&state)
    }
}
