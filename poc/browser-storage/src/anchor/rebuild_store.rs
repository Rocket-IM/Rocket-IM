//! 新候选与批准意图的独立控制记录；不修改旧范围，不把未确认关联当成通信许可。
use super::{
    client::Client,
    commitment, error,
    protocol::{self, Signed},
    rebuild_options::{Offer, Options},
    rebuild_protocol::{self, Plan},
};
use crate::{
    crypto::{model::Identity, requests::Request, store},
    protocol::{ApiError, Checkpoint, Fault},
    transaction, StorageProbe,
};
use rusqlite::{Connection, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::json;

const OFFER_DOMAIN: &[u8] = b"Rocket-IM/browser-rebuild-candidate/v1\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundOffer {
    binding: String,
    offer: Offer,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    pub plan: Plan,
    pub approval: Signed,
}

pub(super) struct Local {
    pub offer: Offer,
    pub intent: Option<Intent>,
    pub linked: bool,
    pub head: String,
    pub conversation: Option<String>,
}

fn tx<T>(
    connection: &mut Connection,
    write: bool,
    body: impl FnOnce(&Transaction<'_>) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    transaction::run(
        connection,
        if write {
            TransactionBehavior::Immediate
        } else {
            TransactionBehavior::Deferred
        },
        Fault::None,
        Checkpoint::None,
        None,
        body,
    )
}

fn raw(
    tx: &Transaction<'_>,
    options: &Options,
) -> Result<(Option<String>, Option<String>, bool), ApiError> {
    let (binding, offer, intent, linked): (String, Option<String>, Option<String>, bool) = tx.query_row(
        "SELECT binding, offer_json, intent_json, linked FROM rebuild_control WHERE singleton=1", [],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).map_err(ApiError::database)?;
    if binding != options.binding()? {
        return Err(error("rebuild_context_mismatch"));
    }
    Ok((offer, intent, linked))
}

fn decode_offer(text: &str, options: &Options) -> Result<Offer, ApiError> {
    if text.len() > 32768 {
        return Err(error("rebuild_candidate_invalid"));
    }
    let signed: Signed =
        serde_json::from_str(text).map_err(|_| error("rebuild_candidate_invalid"))?;
    let bound: BoundOffer = protocol::verify(&signed, &options.public_key()?, OFFER_DOMAIN)?;
    if bound.binding != options.binding()? {
        return Err(error("rebuild_context_mismatch"));
    }
    options.validate_offer(&bound.offer)?;
    Ok(bound.offer)
}

fn save_offer(tx: &Transaction<'_>, options: &Options, offer: &Offer) -> Result<(), ApiError> {
    let signed = protocol::sign(
        &BoundOffer {
            binding: options.binding()?,
            offer: offer.clone(),
        },
        &options.key()?,
        OFFER_DOMAIN,
    )?;
    let text = serde_json::to_string(&signed).map_err(|_| error("rebuild_candidate_invalid"))?;
    if tx
        .execute(
            "UPDATE rebuild_control SET offer_json=?1 WHERE singleton=1 AND offer_json IS NULL",
            [text],
        )
        .map_err(ApiError::database)?
        != 1
    {
        return Err(error("rebuild_candidate_invalid"));
    }
    Ok(())
}

fn initial_offer(tx: &Transaction<'_>, options: &Options) -> Result<Offer, ApiError> {
    let (identity, revision, conversation, encryptions, decryptions, cursor, processing): (Option<String>,String,Option<String>,String,String,String,String) = tx.query_row(
        "SELECT identity_json,revision,conversation,encryptions,decryptions,download_cursor,processing_cursor FROM crypto_meta WHERE singleton=1", [],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?))).map_err(ApiError::database)?;
    let pending: u32 = tx
        .query_row("SELECT COUNT(*) FROM crypto_reservation", [], |row| {
            row.get(0)
        })
        .map_err(ApiError::database)?;
    let entries: u32 = tx.query_row("SELECT (SELECT COUNT(*) FROM crypto_outbox)+(SELECT COUNT(*) FROM crypto_events)+(SELECT COUNT(*) FROM crypto_messages)+(SELECT COUNT(*) FROM crypto_receipts)", [], |row|row.get(0)).map_err(ApiError::database)?;
    if pending != 0
        || entries != 0
        || revision != "1"
        || conversation.is_some()
        || [&encryptions, &decryptions, &cursor, &processing]
            .iter()
            .any(|value| value.as_str() != "0")
    {
        return Err(error("rebuild_candidate_incomplete"));
    }
    let identity: Identity =
        serde_json::from_str(&identity.ok_or_else(|| error("rebuild_candidate_incomplete"))?)
            .map_err(|_| error("rebuild_candidate_invalid"))?;
    options.offer(identity, commitment::in_transaction(tx)?)
}

pub(super) fn initialize(
    storage: &mut StorageProbe,
    options: &Options,
    create: bool,
) -> Result<Offer, ApiError> {
    let connection = storage.connection.as_mut().ok_or_else(ApiError::closed)?;
    if create {
        tx(connection, true, |tx| {
            let exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='rebuild_control')",
                    [],
                    |row| row.get(0),
                )
                .map_err(ApiError::database)?;
            let initialized: bool = tx.query_row("SELECT identity_json IS NOT NULL OR revision!='0' FROM crypto_meta WHERE singleton=1", [], |row|row.get(0)).map_err(ApiError::database)?;
            if exists || initialized {
                return Err(error("rebuild_candidate_exists"));
            }
            tx.execute_batch("CREATE TABLE rebuild_control(singleton INTEGER PRIMARY KEY CHECK(singleton=1), binding TEXT NOT NULL, offer_json TEXT, intent_json TEXT, linked INTEGER NOT NULL CHECK(linked IN(0,1)))").map_err(ApiError::database)?;
            tx.execute(
                "INSERT INTO rebuild_control VALUES(1,?1,NULL,NULL,0)",
                [options.binding()?],
            )
            .map_err(ApiError::database)?;
            Ok(())
        })?;
        let fault = options
            .initial_fault
            .as_deref()
            .filter(|value| *value != "after_commit");
        let request = if let Some(fault) = fault {
            json!({"op":"initialize","test":{"fault":fault}})
        } else {
            json!({"op":"initialize"})
        };
        store::execute(
            connection,
            &storage.scope,
            Request::parse(&request.to_string(), true)?,
            None,
        )?;
        if options.initial_fault.as_deref() == Some("after_commit") {
            return Err(error("rebuild_initial_result_lost"));
        }
    }
    tx(connection, true, |tx| {
        let (offer, intent, linked) = raw(tx, options)?;
        if let Some(offer) = offer {
            return decode_offer(&offer, options);
        }
        if intent.is_some() || linked {
            return Err(error("rebuild_candidate_invalid"));
        }
        // 只补齐已共同提交的新身份公开材料；绝不再次调用 Initialize。
        let offer = initial_offer(tx, options)?;
        save_offer(tx, options, &offer)?;
        Ok(offer)
    })
}

pub(super) fn read(
    connection: &mut Connection,
    options: &Options,
    client: &Client,
) -> Result<Local, ApiError> {
    tx(connection, false, |tx| {
        let (offer, intent, linked) = raw(tx, options)?;
        let offer = decode_offer(
            &offer.ok_or_else(|| error("rebuild_candidate_incomplete"))?,
            options,
        )?;
        let intent: Option<Intent> = intent
            .map(|text| {
                if text.len() > 32768 {
                    return Err(error("rebuild_intent_invalid"));
                }
                let signed =
                    serde_json::from_str(&text).map_err(|_| error("rebuild_intent_invalid"))?;
                client.verify_journal(&signed)
            })
            .transpose()?;
        if linked && intent.is_none() {
            return Err(error("rebuild_intent_invalid"));
        }
        if let Some(intent) = &intent {
            options.validate_plan(&offer, &intent.plan)?;
            rebuild_protocol::verify_approval(&intent.plan, &intent.approval)?;
        }
        let head = commitment::in_transaction(tx)?;
        let (identity, conversation): (Option<String>, Option<String>) = tx
            .query_row(
                "SELECT identity_json,conversation FROM crypto_meta WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(ApiError::database)?;
        let identity: Identity =
            serde_json::from_str(&identity.ok_or_else(|| error("rebuild_candidate_invalid"))?)
                .map_err(|_| error("rebuild_candidate_invalid"))?;
        if identity.service != options.service
            || identity.account != options.account
            || identity.device != options.device
            || identity.identity_key != offer.identity.identity_key
        {
            return Err(error("rebuild_candidate_invalid"));
        }
        if intent.is_none() && (head != offer.head || conversation.is_some()) {
            return Err(error("rebuild_candidate_changed"));
        }
        if let Some(intent) = &intent {
            if conversation
                .as_ref()
                .is_some_and(|value| value != &intent.plan.conversation)
            {
                return Err(error("rebuild_conversation"));
            }
        }
        Ok(Local {
            offer,
            intent,
            linked,
            head,
            conversation,
        })
    })
}

pub(super) fn prepare(
    connection: &mut Connection,
    options: &Options,
    client: &Client,
    intent: &Intent,
) -> Result<(), ApiError> {
    let local = read(connection, options, client)?;
    options.validate_plan(&local.offer, &intent.plan)?;
    rebuild_protocol::verify_approval(&intent.plan, &intent.approval)?;
    if let Some(previous) = local.intent {
        if previous.plan.digest()? != intent.plan.digest()? {
            return Err(error("rebuild_intent_conflict"));
        }
        return Ok(());
    }
    if local.head != local.offer.head || local.linked {
        return Err(error("rebuild_candidate_changed"));
    }
    tx(connection, true, |tx| {
        if commitment::in_transaction(tx)? != local.head {
            return Err(error("rebuild_candidate_changed"));
        }
        let signed = client.sign_journal(intent)?;
        let text = serde_json::to_string(&signed).map_err(|_| error("rebuild_intent_invalid"))?;
        if tx.execute("UPDATE rebuild_control SET intent_json=?1 WHERE singleton=1 AND intent_json IS NULL AND linked=0",[text]).map_err(ApiError::database)?!=1 {return Err(error("rebuild_intent_conflict"));}
        Ok(())
    })
}

pub(super) fn linked(
    connection: &mut Connection,
    options: &Options,
    client: &Client,
    plan: &Plan,
) -> Result<(), ApiError> {
    let local = read(connection, options, client)?;
    if local
        .intent
        .as_ref()
        .ok_or_else(|| error("rebuild_intent_invalid"))?
        .plan
        .digest()?
        != plan.digest()?
    {
        return Err(error("rebuild_intent_conflict"));
    }
    if !local.linked && local.head != local.offer.head {
        return Err(error("rebuild_candidate_changed"));
    }
    tx(connection, true, |tx| {
        raw(tx, options)?;
        tx.execute("UPDATE rebuild_control SET linked=1 WHERE singleton=1", [])
            .map_err(ApiError::database)?;
        Ok(())
    })
}
