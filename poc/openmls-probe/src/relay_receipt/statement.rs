//! 签名器仅接受明确列出的回执协议，不提供任意JSON签名。
use crate::{
    message_acceptance::{MessageAcceptanceStatement, SIGNING_DOMAIN},
    permission::{
        receipts::{ReceiptStatement, RECEIPT_DOMAIN},
        PermissionError,
    },
};
use serde::{Deserialize, Serialize};
#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum Statement {
    Permission(Box<ReceiptStatement>),
    Message(Box<MessageAcceptanceStatement>),
    MessageClosure(Box<crate::message_closure::MessageClosureStatement>),
    MessageRejection(Box<crate::message_rejection::MessageRejectionStatement>),
    History(Box<crate::history_transfer::ReceiptStatement>),
    Consistency(Box<crate::consistency::HeadStatement>),
    RebuildBinding(Box<crate::rebuild_stream::BindingStatement>),
    RebuildPage(Box<crate::rebuild_stream::PageStatement>),
    StreamPage(Box<crate::stream_page::PageStatement>),
}
impl Statement {
    pub(super) fn domain(&self) -> Result<&'static [u8], PermissionError> {
        match self {
            Self::MessageRejection(s) => {
                s.validate()?;
                Ok(crate::message_rejection::SIGNING_DOMAIN)
            }
            Self::MessageClosure(s) => {
                s.validate()?;
                Ok(crate::message_closure::SIGNING_DOMAIN)
            }
            Self::StreamPage(s) => {
                s.validate()?;
                Ok(crate::stream_page::SIGNING_DOMAIN)
            }
            Self::RebuildBinding(s) => {
                s.validate()?;
                Ok(crate::rebuild_stream::BINDING_DOMAIN)
            }
            Self::RebuildPage(s) => {
                s.validate()?;
                Ok(crate::rebuild_stream::PAGE_DOMAIN)
            }
            Self::Consistency(s) => {
                s.validate()?;
                Ok(crate::consistency::SIGNING_DOMAIN)
            }
            Self::History(s) => {
                s.validate()?;
                Ok(crate::history_transfer::RECEIPT_DOMAIN)
            }
            Self::Permission(s) => {
                s.validate()?;
                Ok(RECEIPT_DOMAIN)
            }
            Self::Message(s) => {
                s.validate()?;
                Ok(SIGNING_DOMAIN)
            }
        }
    }
}
