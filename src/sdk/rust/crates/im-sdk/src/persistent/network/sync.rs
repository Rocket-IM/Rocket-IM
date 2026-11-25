use super::{
    super::{data::Saved, types::*, PersistentDevice},
    ledger,
    session::NetworkSession,
    types::*,
};
use serde::Deserialize;
use serde_json::json;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Welcome {
    welcome: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Processed {
    sequence: String,
    #[serde(default)]
    disposition: String,
}
impl NetworkSession {
    pub(super) fn step(&mut self, device: &mut PersistentDevice) -> Result<bool> {
        if self.recovery_step(device)? {
            return Ok(false);
        }
        let saved = device.database.call(|db| db.read(Ok))?;
        if saved.meta.blocks_operations() {
            return Err(Error::paused("recovery_active"));
        }
        if saved.data.state.pending_request.is_some() {
            return Err(Error::paused("successor_required"));
        }
        if !self.bootstrap(device, &saved)? {
            return Ok(false);
        }
        let saved = device.database.call(|db| db.read(Ok))?;
        let network = saved
            .data
            .network
            .as_ref()
            .ok_or_else(|| Error::paused("network_store_invalid"))?;
        if number(&network.reported)? < number(&network.processed)? {
            let sequence = (number(&network.reported)? + 1).to_string();
            let disposition = if network.retired_events.contains(&sequence) {
                "context_retired"
            } else {
                "received"
            };
            let reply: Processed = self.rpc(
                "processed",
                json!({"sequence":sequence,"disposition":disposition}),
            )?;
            if reply.sequence != sequence || reply.disposition != disposition {
                return Err(Error::paused("network_receipt_invalid"));
            }
            device.database.call(move |db| {
                db.update(false, |s| {
                    s.data
                        .network
                        .as_mut()
                        .ok_or_else(|| Error::paused("network_store_invalid"))?
                        .reported = sequence;
                    Ok(())
                })
            })?;
            return Ok(true);
        }
        // 依原密码提交revision发送，不能按调用方request_id字典顺序重排。
        let pending = saved
            .data
            .requests
            .iter()
            .filter_map(|(id, r)| match &r.result {
                RequestState::Complete { outcome } => match &outcome.value {
                    Value::Sent { envelope }
                        if r.rejection.is_none()
                            && !network.accepted.contains_key(&envelope.message_id)
                            && !network.not_accepted.contains(&envelope.message_id) =>
                    {
                        Some((id.clone(), outcome.clone(), envelope.clone()))
                    }
                    _ => None,
                },
                _ => None,
            })
            .map(|(request, outcome, envelope)| Ok((number(&outcome.revision)?, request, envelope)))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .min_by_key(|(revision, _, _)| *revision);
        if let Some(event) = network
            .events
            .get(number(&network.processed)? as usize)
            .cloned()
        {
            match super::queue::process_event(device, &saved, event) {
                Ok(()) => return Ok(true),
                // 预约前容量拒绝没有消耗密码状态；先确认已有发送，可能释放被拒绝的投影槽。
                Err(e)
                    if pending.is_some()
                        && !e.paused
                        && matches!(
                            e.code.as_str(),
                            "message_limit" | "storage_limit" | "request_limit"
                        ) => {}
                Err(e) => return Err(e),
            }
        }
        if let Some((_, request, envelope)) = pending {
            let reply: Result<Acceptance> =
                self.rpc("send", json!({"request_id":request,"envelope":envelope}));
            let ack = match reply {
                Ok(ack) => ack,
                Err(e)
                    if e.code == "context_not_accepted"
                        && super::queue::retired_context(&saved.data, &envelope.context) =>
                {
                    let message = envelope.message_id.clone();
                    device.database.call(move |db| {
                        db.update(false, |s| {
                            s.data
                                .network
                                .as_mut()
                                .ok_or_else(|| Error::paused("network_store_invalid"))?
                                .not_accepted
                                .insert(message);
                            Ok(())
                        })
                    })?;
                    return Ok(true);
                }
                Err(e) if super::rejection::SendRejection::from_service_send(&e).is_some() => {
                    let rejection = super::rejection::SendRejection::from_service_send(&e)
                        .ok_or_else(|| Error::paused("rejection_record_invalid"))?;
                    super::super::checkpoint("network_after_rejection");
                    device.database.call(move |db| {
                        db.update(true, |s| {
                            super::rejection::commit(s, &request, &envelope, rejection)
                        })
                    })?;
                    super::super::checkpoint("network_after_rejection_commit");
                    return Ok(true);
                }
                Err(e) => return Err(e),
            };
            ledger::validate_ack(&saved.data, &ack)?;
            super::super::checkpoint("network_after_accept");
            device.database.call(move |db| {
                db.update(false, |s| {
                    ledger::validate_ack(&s.data, &ack)?;
                    s.data
                        .network
                        .as_mut()
                        .ok_or_else(|| Error::paused("network_store_invalid"))?
                        .accepted
                        .insert(ack.message_id.clone(), ack);
                    Ok(())
                })
            })?;
            return Ok(true);
        }
        let page: Page = self.rpc(
            "poll",
            json!({"after":network.events.len().to_string(),"upper":network.upper,"limit":2}),
        )?;
        if !page.events.is_empty() || network.upper.is_some() {
            device.database.call(move |db| {
                db.update(false, |s| {
                    let mut n = s
                        .data
                        .network
                        .take()
                        .ok_or_else(|| Error::paused("network_store_invalid"))?;
                    n.download(&s.data, page)?;
                    s.data.network = Some(n);
                    Ok(())
                })
            })?;
            super::super::checkpoint("network_after_download");
        }
        Ok(true)
    }
    fn bootstrap(&mut self, device: &mut PersistentDevice, saved: &Saved) -> Result<bool> {
        let state = &saved.data.state;
        if let Some(conversation) = &state.conversation {
            if conversation != &self.options.conversation
                || state.peer.as_ref() != Some(&self.options.peer)
            {
                return Err(Error::paused("identity_mismatch"));
            }
            if self.options.creator {
                if let Some(record) = saved.data.requests.get("network-create-group") {
                    if let RequestState::Complete { outcome } = &record.result {
                        if let Value::Created { welcome } = &outcome.value {
                            let _: Welcome =
                                self.rpc("publish_welcome", json!({"welcome":welcome}))?;
                        }
                    }
                }
            }
            return Ok(true);
        }
        let own = device.joining_material()?;
        let published: JoiningMaterial = self.rpc("publish_material", &own)?;
        if published != own {
            return Err(Error::paused("identity_mismatch"));
        }
        let peer: Option<JoiningMaterial> = self.rpc("peer_material", json!({}))?;
        let Some(peer) = peer else { return Ok(false) };
        if peer.identity != self.options.peer {
            return Err(Error::paused("identity_mismatch"));
        }
        if self.options.creator {
            device.execute(
                "network-create-group".into(),
                Action::CreateGroup {
                    conversation: self.options.conversation.clone(),
                    peer: peer.identity,
                    key_package: peer.key_package,
                },
            )?;
        } else {
            let welcome: Option<Welcome> = self.rpc("welcome", json!({}))?;
            let Some(welcome) = welcome else {
                return Ok(false);
            };
            device.execute(
                "network-join-group".into(),
                Action::JoinGroup {
                    conversation: self.options.conversation.clone(),
                    peer: peer.identity,
                    welcome: welcome.welcome,
                },
            )?;
        }
        Ok(false)
    }
    pub(super) fn rpc<T: serde::de::DeserializeOwned>(
        &mut self,
        op: &str,
        body: impl serde::Serialize,
    ) -> Result<T> {
        self.socket
            .as_mut()
            .ok_or_else(|| Error::new("network_unavailable"))?
            .call(op, body)
    }
}
