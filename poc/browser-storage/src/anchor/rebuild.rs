//! 先建立隔离新身份，再以独立批准关联唯一后继；旧密码状态永不进入此对象。
use super::{
    client::Client,
    coordinator, database, error,
    rebuild_options::Options,
    rebuild_protocol::{self, Action, Status},
    rebuild_store::{self, Intent, Local},
};
use crate::{
    crypto::{
        requests::{Action as CryptoAction, Request},
        store,
    },
    protocol::ApiError,
    StorageProbe,
};
use js_sys::Function;
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct RebuildProbe {
    storage: StorageProbe,
    options: Options,
    client: Client,
}

#[wasm_bindgen]
impl RebuildProbe {
    pub async fn open(
        options_json: String,
        create: bool,
        test_mode: bool,
        rpc: Function,
    ) -> Result<RebuildProbe, JsValue> {
        let options = Options::parse(&options_json).map_err(ApiError::into_js)?;
        if (create && !test_mode) || (!create && options.initial_fault.is_some()) {
            return Err(ApiError::test_only().into_js());
        }
        let mut storage = StorageProbe::open_scope(
            options.storage_scope().map_err(ApiError::into_js)?,
            test_mode,
            false,
            false,
            !create,
        )
        .await
        .map_err(ApiError::into_js)?;
        let result = (|| {
            let connection = storage.connection.as_mut().ok_or_else(ApiError::closed)?;
            if !create {
                super::commitment::read(connection)?;
            }
            store::initialize_schema(connection, &storage.scope)?;
            let offer = rebuild_store::initialize(&mut storage, &options, create)?;
            options.client(&offer, rpc)
        })();
        match result {
            Ok(client) => Ok(Self {
                storage,
                options,
                client,
            }),
            Err(error) => {
                storage.close_inner().map_err(ApiError::into_js)?;
                Err(error.into_js())
            }
        }
    }
    pub async fn execute(&mut self, request_json: String) -> String {
        let result = self.execute_inner(&request_json).await;
        let output = match result {
            Ok(value) => json!({"ok":true,"result":value}),
            Err(error) => {
                self.storage.paused |= error.paused;
                json!({"ok":false,"error":error})
            }
        };
        serde_json::to_string(&output).unwrap_or_else(|_|{self.storage.paused=true;r#"{"ok":false,"error":{"code":"encoding_failed","message":"重建结果编码失败。","paused":true}}"#.into()})
    }
    pub fn close(&mut self) -> Result<(), JsValue> {
        self.storage.close_inner().map_err(ApiError::into_js)
    }
    #[wasm_bindgen(js_name = setCheckpointHook)]
    pub fn set_checkpoint_hook(&mut self, callback: Function) -> Result<(), JsValue> {
        self.storage.set_checkpoint_hook(callback)
    }
}

impl RebuildProbe {
    fn read(&mut self) -> Result<Local, ApiError> {
        rebuild_store::read(
            self.storage
                .connection
                .as_mut()
                .ok_or_else(ApiError::closed)?,
            &self.options,
            &self.client,
        )
    }
    async fn execute_inner(&mut self, text: &str) -> Result<Value, ApiError> {
        if text.len() > 256 * 1024 {
            return Err(ApiError::invalid());
        }
        let mut value: Value = serde_json::from_str(text).map_err(|_| ApiError::invalid())?;
        let op = value["op"]
            .as_str()
            .ok_or_else(ApiError::invalid)?
            .to_owned();
        if matches!(op.as_str(), "status" | "offer" | "resume") {
            if value.as_object().ok_or_else(ApiError::invalid)?.len() != 1 {
                return Err(ApiError::invalid());
            }
            if op == "resume" {
                self.storage.ensure_available()?;
                return self.resume().await;
            }
            return self.status().await;
        }
        self.storage.ensure_available()?;
        if op == "activate" {
            let object = value.as_object_mut().ok_or_else(ApiError::invalid)?;
            object.remove("op");
            let checkpoint = object.remove("anchorTest");
            if let Some(checkpoint) = &checkpoint {
                if !self.storage.test_mode {
                    return Err(ApiError::test_only());
                }
                if checkpoint != &json!({"checkpoint":"after_rebuild_link"})
                    || self.storage.checkpoint.is_none()
                {
                    return Err(ApiError::invalid());
                }
            }
            let intent: Intent = serde_json::from_value(value).map_err(|_| ApiError::invalid())?;
            rebuild_store::prepare(
                self.storage
                    .connection
                    .as_mut()
                    .ok_or_else(ApiError::closed)?,
                &self.options,
                &self.client,
                &intent,
            )?;
            return self.link(checkpoint.is_some()).await;
        }
        let local = self.read()?;
        let intent = local
            .intent
            .as_ref()
            .ok_or_else(|| error("rebuild_approval_required"))?;
        if !local.linked {
            return Err(error("rebuild_approval_required"));
        }
        value
            .as_object_mut()
            .ok_or_else(ApiError::invalid)?
            .remove("anchorTest");
        let request = Request::parse(&value.to_string(), self.storage.test_mode)?;
        match &request.action {
            CryptoAction::JoinGroup {
                conversation, peer, ..
            } => {
                if local.conversation.is_some() {
                    return Err(error("rebuild_already_joined"));
                }
                if conversation != &intent.plan.conversation
                    || serde_json::to_value(peer).map_err(|_| ApiError::invalid())?
                        != serde_json::to_value(&intent.plan.peer)
                            .map_err(|_| ApiError::invalid())?
                {
                    return Err(error("rebuild_admission_binding"));
                }
            }
            CryptoAction::Initialize | CryptoAction::CreateGroup { .. } => {
                return Err(error("rebuild_operation"))
            }
            _ if local.conversation.is_none() => return Err(error("rebuild_join_required")),
            CryptoAction::Download { event }
                if event.envelope.conversation != intent.plan.conversation
                    || event.envelope.service != intent.plan.successor_scope.service =>
            {
                return Err(error("rebuild_admission_binding"))
            }
            _ => {}
        }
        let result = coordinator::execute(&mut self.storage, &self.client, text).await?;
        self.wrap(result)
    }
    async fn request(
        &self,
        intent: &Intent,
        action: Action,
    ) -> Result<rebuild_protocol::Response, ApiError> {
        let signed =
            rebuild_protocol::sign_request(&intent.plan, self.client.signing_key(), action)?;
        let returned=self.client.exchange(&json!({"rebuild":{"plan":intent.plan,"approval":intent.approval,"request":signed}})).await?;
        rebuild_protocol::verify_response(&intent.plan, &returned, &signed)
    }
    async fn status(&mut self) -> Result<Value, ApiError> {
        let local = self.read()?;
        if local.linked {
            let result =
                coordinator::execute(&mut self.storage, &self.client, r#"{"op":"status"}"#).await?;
            return self.wrap(result);
        }
        if let Some(intent) = &local.intent {
            self.request(intent, Action::Inspect).await?;
            return Ok(
                json!({"phase":"paused","candidate":local.offer,"snapshot":null,"status":null}),
            );
        }
        Ok(json!({"phase":"candidate","candidate":local.offer,"snapshot":null,"status":null}))
    }
    async fn link(&mut self, checkpoint: bool) -> Result<Value, ApiError> {
        let local = self.read()?;
        let intent = local
            .intent
            .as_ref()
            .ok_or_else(|| error("rebuild_approval_required"))?;
        if !local.linked && local.head != local.offer.head {
            return Err(error("rebuild_candidate_changed"));
        }
        let remote = self.request(intent, Action::Link).await?;
        if !matches!(remote.status, Status::Linked | Status::Duplicate) {
            return Err(error("rebuild_link_unconfirmed"));
        }
        if !local.linked
            && (remote.current_head != local.head
                || remote.current_revision != "0"
                || remote.active_txn.is_some())
        {
            return Err(error("rebuild_successor_advanced"));
        }
        if checkpoint {
            crate::transaction::pause_for_termination(
                self.storage.checkpoint.as_ref(),
                "after_rebuild_link",
                true,
            )?;
        }
        let connection = self
            .storage
            .connection
            .as_mut()
            .ok_or_else(ApiError::closed)?;
        database::initialize(connection, &self.client)?;
        rebuild_store::linked(connection, &self.options, &self.client, &intent.plan)?;
        self.status().await
    }
    async fn resume(&mut self) -> Result<Value, ApiError> {
        let local = self.read()?;
        if !local.linked {
            return self.link(false).await;
        }
        let result =
            coordinator::execute(&mut self.storage, &self.client, r#"{"op":"resume"}"#).await?;
        self.wrap(result)
    }
    fn wrap(&mut self, result: Value) -> Result<Value, ApiError> {
        let local = self.read()?;
        let phase = if result["status"]["phase"] == "paused" {
            "paused"
        } else if local.conversation.is_some() {
            "ready"
        } else {
            "linked"
        };
        Ok(
            json!({"phase":phase,"candidate":local.offer,"snapshot":result["snapshot"],"status":result["status"]}),
        )
    }
}
