use super::deadline::DeadlineStream;
// 单连接有界WSS请求；TLS根由调用方显式提供，拒绝明文、跳转和未核验身份。
use super::{super::types::*, types::NetworkOptions};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};
use tungstenite::{
    client::IntoClientRequest, stream::MaybeTlsStream, Connector, Message, WebSocket,
};
const LIMIT: usize = 600 * 1024;
pub(super) struct Socket {
    stream: WebSocket<MaybeTlsStream<DeadlineStream>>,
    sequence: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    id: String,
    ok: bool,
    result: serde_json::Value,
    error: Option<Failure>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    code: String,
}
impl Socket {
    pub fn connect(options: &NetworkOptions) -> Result<Self> {
        let mut request = options
            .url
            .as_str()
            .into_client_request()
            .map_err(|_| Error::new("invalid_endpoint"))?;
        let uri = request.uri();
        if uri.scheme_str() != Some("wss")
            || uri.path_and_query().map(|p| p.as_str()) != Some("/v1/ws")
        {
            return Err(Error::new("tls_required"));
        }
        // Alpha仅支持字面IP，避免DNS等待无法界定；证书SAN仍必须匹配此IP。
        let host = uri.host().ok_or_else(|| Error::new("invalid_endpoint"))?;
        let ip: IpAddr = host
            .parse()
            .map_err(|_| Error::new("literal_ip_required"))?;
        let address = SocketAddr::new(
            ip,
            uri.port_u16()
                .ok_or_else(|| Error::new("endpoint_port_required"))?,
        );
        let root = rustls::pki_types::CertificateDer::from(unhex(&options.ca_certificate, 8192)?);
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(root)
            .map_err(|_| Error::new("invalid_certificate"))?;
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::new("tls_configuration"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        request.headers_mut().insert(
            "Authorization",
            format!("Bearer {}", options.token)
                .parse()
                .map_err(|_| Error::new("invalid_credentials"))?,
        );
        let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(1))
            .map_err(|_| Error::new("network_unavailable"))?;
        tcp.set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(|_| Error::new("network_unavailable"))?;
        tcp.set_write_timeout(Some(Duration::from_secs(1)))
            .map_err(|_| Error::new("network_unavailable"))?;
        let config = tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(LIMIT))
            .max_frame_size(Some(LIMIT));
        let (stream, _) = tungstenite::client_tls_with_config(
            request,
            DeadlineStream::new(tcp),
            Some(config),
            Some(Connector::Rustls(Arc::new(tls))),
        )
        .map_err(|e| match e {
            tungstenite::HandshakeError::Failure(tungstenite::Error::Http(r))
                if r.status().as_u16() == 401 =>
            {
                Error::new("unauthorized")
            }
            tungstenite::HandshakeError::Failure(tungstenite::Error::Tls(_)) => {
                Error::paused("tls_verification_failed")
            }
            tungstenite::HandshakeError::Failure(tungstenite::Error::Io(e))
                if e.kind() == std::io::ErrorKind::InvalidData =>
            {
                Error::paused("tls_verification_failed")
            }
            _ => Error::new("network_unavailable"),
        })?;
        Ok(Self {
            stream,
            sequence: 0,
        })
    }
    pub fn call<T: DeserializeOwned>(&mut self, op: &str, body: impl Serialize) -> Result<T> {
        match self.stream.get_mut() {
            MaybeTlsStream::Rustls(stream) => stream.sock.reset(),
            _ => return Err(Error::paused("tls_required")),
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| Error::new("connection_limit"))?;
        let id = self.sequence.to_string();
        let raw = encode(&serde_json::json!({"id":id,"op":op,"body":body}))?;
        if raw.len() > LIMIT {
            return Err(Error::new("request_too_large"));
        }
        let text = String::from_utf8(raw).map_err(|_| Error::new("invalid_encoding"))?;
        self.stream
            .send(Message::Text(text.into()))
            .map_err(|_| Error::new("network_unavailable"))?;
        let message = self
            .stream
            .read()
            .map_err(|_| Error::new("network_unavailable"))?;
        if let Message::Close(Some(frame)) = &message {
            if frame.code == tungstenite::protocol::frame::coding::CloseCode::Policy
                && frame.reason == "unauthorized"
            {
                return Err(Error::new("unauthorized"));
            }
        }
        let Message::Text(raw) = message else {
            return Err(Error::paused("network_protocol_invalid"));
        };
        let reply: Reply =
            serde_json::from_str(&raw).map_err(|_| Error::paused("network_protocol_invalid"))?;
        if reply.id != id || reply.ok == reply.error.is_some() {
            return Err(Error::paused("network_protocol_invalid"));
        }
        if let Some(e) = reply.error {
            return Err(Error::new(&e.code));
        }
        serde_json::from_value(reply.result).map_err(|_| Error::paused("network_protocol_invalid"))
    }
}
