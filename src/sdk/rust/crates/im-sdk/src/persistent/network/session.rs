use super::{
    super::{data::Saved, types::*, PersistentDevice},
    socket::Socket,
    types::*,
};
use super::{auth::Authentication, AuthenticationEvent, AuthenticationResult};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

/// 由单一SDK协调线程持有。调用tick自动建群、发送、补拉和回执；宿主不搬运密文。
/// 网络I/O最长一次读写1秒；重连退避250ms至2秒。关闭丢弃连接，不删除持久队列。
pub struct NetworkSession {
    pub(super) options: NetworkOptions,
    pub(super) socket: Option<Socket>,
    pub(super) connection: String,
    pub(super) error: Option<Error>,
    retry_at: Instant,
    delay: Duration,
    last_event: Vec<u8>,
    authentication: Option<Authentication>,
}
impl NetworkSession {
    pub fn connect(device: &mut PersistentDevice, options: NetworkOptions) -> Result<Self> {
        let binding = options.binding()?;
        let saved = device.database.call(|db| db.read(Ok))?;
        if saved.data.state.identity.is_none() {
            return Err(Error::new("initialize_required"));
        }
        if let Some(n) = &saved.data.network {
            if n.binding.as_ref() != Some(&binding) {
                return Err(Error::new("network_binding_mismatch"));
            }
        } else if saved.data.state.conversation.is_some() {
            // 旧本地群没有本服务的加入记录，不能假装已完成联网建群。
            return Err(Error::new("network_fresh_group_required"));
        } else if saved.data.state.pending_request.is_some() {
            return Err(Error::paused("operation_pending"));
        }
        if saved
            .data
            .state
            .conversation
            .as_ref()
            .is_some_and(|c| c != &options.conversation)
            || saved
                .data
                .state
                .peer
                .as_ref()
                .is_some_and(|p| p != &options.peer)
        {
            return Err(Error::new("identity_mismatch"));
        }
        let authentication = options
            .authentication
            .clone()
            .map(|auth| {
                if !options.token.is_empty() {
                    return Err(Error::new("invalid_authentication_options"));
                }
                Authentication::new(saved.data.state.scope.clone(), auth)
            })
            .transpose()?;
        let socket = if authentication.is_some() {
            None
        } else {
            let mut socket = Socket::connect(&options)?;
            Self::verify(&mut socket, &options, &saved)?;
            device
                .database
                .call(move |db| db.update(false, |s| super::ledger::bind(&mut s.data, binding)))?;
            Some(socket)
        };
        let connection = if authentication.is_some() {
            "authenticating"
        } else {
            "connecting"
        }
        .into();
        Ok(Self {
            options,
            socket,
            connection,
            error: None,
            retry_at: Instant::now(),
            delay: Duration::from_millis(250),
            last_event: vec![],
            authentication,
        })
    }
    pub(super) fn verify(
        socket: &mut Socket,
        options: &NetworkOptions,
        saved: &Saved,
    ) -> Result<()> {
        let session: Session = socket.call("session", serde_json::json!({}))?;
        if session.version != "alpha1"
            || session.service != saved.data.state.scope.service
            || session.conversation != options.conversation
            || Some(&session.own) != saved.data.state.identity.as_ref()
            || session.peer != options.peer
            || session.creator != options.creator
        {
            return Err(Error::paused("identity_mismatch"));
        }
        Ok(())
    }
    pub fn state(&self, device: &PersistentDevice) -> Result<NetworkState> {
        state(device, &self.connection, self.error.clone())
    }
    pub fn offline_state(device: &PersistentDevice) -> Result<NetworkState> {
        state(device, "offline", None)
    }
    /// 桥接层应立即转交请求/取消；无用户凭证或密码材料。
    pub fn take_authentication_events(&mut self) -> Vec<AuthenticationEvent> {
        self.authentication
            .as_mut()
            .map_or_else(Vec::new, Authentication::take_events)
    }
    pub fn complete_authentication(
        &mut self,
        request_id: &str,
        result: AuthenticationResult,
    ) -> Result<()> {
        let auth = self
            .authentication
            .as_mut()
            .ok_or_else(|| Error::new("stale_authentication"))?;
        if let Some(token) = auth.complete(request_id, result)? {
            self.options.token.zeroize();
            self.options.token = token;
        }
        self.retry_at = Instant::now();
        Ok(())
    }
    /// 每次最多处理一页/一个原件/一个发送；只有持久提交完成才产生相应状态变化。
    pub fn tick(&mut self, device: &mut PersistentDevice) -> Result<Option<NetworkState>> {
        if self.connection == "blocked" {
            return Ok(None);
        }
        if let Some(auth) = self.authentication.as_mut() {
            if !auth.ready()? {
                self.socket = None;
                self.options.token.zeroize();
                self.connection = if auth.blocked {
                    "blocked"
                } else {
                    "authenticating"
                }
                .into();
                self.error = auth.error.clone();
                return self.changed(device);
            }
        }
        if Instant::now() < self.retry_at {
            return Ok(None);
        }
        let result = (|| {
            let saved = device.database.call(|db| db.read(Ok))?;
            if let Some(request) = saved
                .data
                .state
                .pending_request
                .clone()
                .filter(|_| !saved.meta.blocks_operations())
            {
                let input = saved
                    .data
                    .requests
                    .get(&request)
                    .and_then(|r| r.input.clone());
                if let Some(input) = input {
                    if let Err(e) = device.recover_request(request, input) {
                        if e.code != "successor_required" {
                            return Err(e);
                        }
                    }
                }
            }
            if self.socket.is_none() {
                let mut socket = Socket::connect(&self.options)?;
                Self::verify(&mut socket, &self.options, &saved)?;
                let binding = self.options.binding()?;
                device.database.call(move |db| {
                    db.update(false, |s| super::ledger::bind(&mut s.data, binding))
                })?;
                if let Some(auth) = self.authentication.as_mut() {
                    auth.verified();
                }
                self.socket = Some(socket);
            }
            self.step(device)
        })();
        match result {
            Ok(ready) => {
                self.connection = if ready { "online" } else { "connecting" }.into();
                self.error = None;
                self.delay = Duration::from_millis(250);
            }
            Err(e) => {
                self.socket = None;
                // 请求开始后才到期：仅在本地期限也已到达时允许进入正常到期续期。
                let expired = if e.code == "unauthorized" {
                    match self.authentication.as_mut() {
                        Some(auth) => !auth.ready()?,
                        None => false,
                    }
                } else {
                    false
                };
                self.connection = if expired {
                    "authenticating"
                } else if matches!(
                    e.code.as_str(),
                    "network_unavailable" | "storage_unavailable"
                ) {
                    "offline"
                } else if matches!(e.code.as_str(), "successor_required" | "recovery_active") {
                    "recovering"
                } else {
                    "blocked"
                }
                .into();
                self.retry_at = Instant::now() + self.delay;
                self.delay = (self.delay * 2).min(Duration::from_secs(2));
                self.error = Some(e);
            }
        }
        self.changed(device)
    }
    fn changed(&mut self, device: &PersistentDevice) -> Result<Option<NetworkState>> {
        let state = self.state(device)?;
        let bytes = encode(&state)?;
        if bytes == self.last_event {
            return Ok(None);
        }
        self.last_event = bytes;
        Ok(Some(state))
    }
}
fn state(
    device: &PersistentDevice,
    connection: &str,
    error: Option<Error>,
) -> Result<NetworkState> {
    device.database.call({
        let connection = connection.to_string();
        move |db| {
            db.read(|s| {
                let n = s.data.network.as_ref();
                let sending = s
                    .data
                    .requests
                    .iter()
                    .filter_map(|(id, r)| {
                        let RequestState::Complete { outcome } = &r.result else {
                            return None;
                        };
                        let Value::Sent { envelope } = &outcome.value else {
                            return None;
                        };
                        let acceptance = n
                            .and_then(|n| n.accepted.get(&envelope.message_id))
                            .cloned();
                        let delivered =
                            n.is_some_and(|n| n.delivered.contains(&envelope.message_id));
                        Some(SendingState {
                            message_id: envelope.message_id.clone(),
                            request_id: id.clone(),
                            status: if r.rejection.is_some() {
                                "rejected"
                            } else if delivered {
                                "delivered"
                            } else if n
                                .is_some_and(|n| n.unavailable.contains(&envelope.message_id))
                            {
                                "context_retired"
                            } else if acceptance.is_some() {
                                "accepted"
                            } else if n
                                .is_some_and(|n| n.not_accepted.contains(&envelope.message_id))
                            {
                                "not_accepted"
                            } else {
                                "local_saved"
                            }
                            .into(),
                            acceptance,
                            rejection: r.rejection.clone(),
                        })
                    })
                    .collect();
                Ok(NetworkState {
                    connection,
                    error,
                    downloaded: n.map_or_else(zero, |n| n.events.len().to_string()),
                    processed: n.map_or_else(zero, |n| n.processed.clone()),
                    reported: n.map_or_else(zero, |n| n.reported.clone()),
                    sending,
                    recovery: super::recovery_types::projection(&s)?,
                    unavailable_history: n.map_or_else(Vec::new, |n| {
                        n.events
                            .iter()
                            .filter(|e| n.retired_events.contains(&e.sequence))
                            .map(|e| UnavailableRecord {
                                sequence: e.sequence.clone(),
                                reason: "context_retired".into(),
                                acceptance: e.acceptance.clone(),
                            })
                            .collect()
                    }),
                })
            })
        }
    })
}
