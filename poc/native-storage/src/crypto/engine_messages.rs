//! 外层路由字段必须与认证 AAD、加密正文及已固定成员身份一致。
use super::{credential, protocol_size, Engine};
use crate::{
    crypto::contract::validate_id,
    crypto::model::{
        self, decode, encode, failed, require, AuthenticatedPlaintext, Envelope, MessageContext,
        PlainMessage,
    },
    model::Error as ApiError,
};
use openmls::prelude::{
    tls_codec::Deserialize as _, ContentType, MlsMessageIn, ProcessedMessageContent, Sender,
};

impl Engine {
    pub(crate) fn send(&mut self, message_id: &str, text: &str) -> Result<Envelope, ApiError> {
        self.available()?;
        validate_id(message_id)?;
        model::text(text)?;
        let conversation = self.conversation.clone().ok_or_else(model::corrupt)?;
        let mut envelope = Envelope {
            service: self.own.service.clone(),
            conversation,
            sender_account: self.own.account.clone(),
            sender_device: self.own.device.clone(),
            message_id: message_id.into(),
            ciphertext: String::new(),
        };
        let context = MessageContext::from_envelope(&envelope)?;
        let aad = failed(serde_json::to_vec(&context))?;
        let plaintext = failed(serde_json::to_vec(&AuthenticatedPlaintext {
            context,
            text: text.into(),
        }))?;
        self.mutate(|candidate| {
            let mut group = candidate.group()?;
            group.set_aad(aad);
            let message =
                failed(group.create_message(&candidate.provider, &candidate.signer, &plaintext))?;
            let bytes = failed(message.to_bytes())?;
            protocol_size(&bytes)?;
            envelope.ciphertext = encode(&bytes);
            Ok(envelope)
        })
    }

    pub(crate) fn receive(&mut self, envelope: &Envelope) -> Result<PlainMessage, ApiError> {
        self.available()?;
        let peer = self.message_peer(envelope)?.clone();
        let context = MessageContext::from_envelope(envelope)?;
        require(
            envelope.service == self.own.service
                && self.conversation.as_deref() == Some(envelope.conversation.as_str())
                && envelope.sender_account == peer.account
                && envelope.sender_device == peer.device,
            "crypto_scope_mismatch",
        )?;
        let bytes = decode(&envelope.ciphertext)?;
        let message = failed(MlsMessageIn::tls_deserialize_exact(&bytes))?;
        let protocol = failed(message.try_into_protocol_message())?;
        let group = self.group()?;
        require(
            protocol.content_type() == ContentType::Application
                && protocol.group_id() == group.group_id()
                && protocol.epoch() == group.epoch(),
            "crypto_scope_mismatch",
        )?;
        self.mutate(|candidate| {
            let mut group = group;
            let processed = failed(group.process_message(&candidate.provider, protocol))?;
            require(
                processed.aad() == failed(serde_json::to_vec(&context))?
                    && processed.credential() == &credential(&peer)
                    && matches!(processed.sender(), Sender::Member(_)),
                "crypto_identity_mismatch",
            )?;
            let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content()
            else {
                return Err(model::corrupt());
            };
            let plaintext = message.into_bytes();
            protocol_size(&plaintext)?;
            let body: AuthenticatedPlaintext = failed(serde_json::from_slice(&plaintext))?;
            require(body.context == context, "crypto_scope_mismatch")?;
            model::text(&body.text)?;
            Ok(PlainMessage {
                message_id: context.message_id,
                sender_account: context.sender_account,
                text: body.text,
            })
        })
    }
}
