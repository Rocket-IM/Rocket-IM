//! 设备流与控制记录的有界实验类型及输入校验。

use super::{
    ensure,
    wire_types::{decimal, id, reference, Device, Envelope},
    LabError,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Control {
    pub(super) control_id: String,
    pub(super) from_state_ref: String,
    pub(super) to_state_ref: String,
    pub(super) payload_bytes: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Event {
    Message {
        acceptance_id: String,
        envelope: Envelope,
        #[serde(
            default,
            deserialize_with = "super::wire_types::present_receipt",
            skip_serializing_if = "Option::is_none"
        )]
        acceptance_receipt: Option<crate::permission::receipts::SignedRecord>,
    },
    Delivery {
        acceptance_id: String,
        attempt_id: String,
        device: Device,
    },
    Read {
        acceptance_id: String,
        attempt_id: String,
        device: Device,
    },
    CryptoControl {
        control: Control,
    },
    MessageAvailability {
        target_event_seq: String,
        target_event_id: String,
        acceptance_id: String,
        attempt_id: String,
        availability: Availability,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Availability {
    Available,
    Expired,
    Deleted,
    AccessRemoved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Slot {
    pub(super) stream_id: String,
    pub(super) event_seq: String,
    pub(super) event_id: String,
    pub(super) availability: Availability,
    #[serde(
        default,
        deserialize_with = "present_event",
        skip_serializing_if = "Option::is_none"
    )]
    pub(super) event: Option<Event>,
    // 已签终态槽仅补公开回执身份；不恢复事件可用性或消息载荷。
    #[serde(
        default,
        deserialize_with = "present_event",
        skip_serializing_if = "Option::is_none"
    )]
    pub(super) terminal_reference: Option<Event>,
}

fn present_event<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Event>, D::Error> {
    Event::deserialize(deserializer).map(Some)
}

pub(super) fn validate_event(event: &Event) -> Result<(), LabError> {
    match event {
        Event::Message { acceptance_id, .. } => id(acceptance_id),
        Event::Delivery {
            acceptance_id,
            attempt_id,
            device,
        }
        | Event::Read {
            acceptance_id,
            attempt_id,
            device,
        } => {
            for value in [
                acceptance_id,
                attempt_id,
                &device.account_id,
                &device.device_id,
            ] {
                id(value)?;
            }
            Ok(())
        }
        Event::CryptoControl { control } => validate_control(control),
        Event::MessageAvailability {
            target_event_seq,
            target_event_id,
            acceptance_id,
            attempt_id,
            availability,
        } => {
            ensure(
                decimal(target_event_seq)? > 0
                    && matches!(availability, Availability::Deleted | Availability::Expired),
                "invalid_envelope",
                "生命周期声明只允许正序号目标及删除或到期终态",
            )?;
            for value in [target_event_id, acceptance_id, attempt_id] {
                id(value)?;
            }
            Ok(())
        }
    }
}

pub(super) fn validate_control(control: &Control) -> Result<(), LabError> {
    id(&control.control_id)?;
    reference(&control.from_state_ref)?;
    reference(&control.to_state_ref)
}

#[derive(Serialize, Deserialize)]
pub(super) struct StoredSlot {
    pub(super) slot: Slot,
    pub(super) result: Option<Value>,
    pub(super) waiting: bool,
}

#[derive(Serialize, Deserialize)]
pub(super) struct SyncState {
    #[serde(default)]
    pub(super) source_verified: bool,
    pub(super) stream_id: Option<String>,
    pub(super) download_cursor: u64,
    pub(super) processed_cursor: u64,
    pub(super) halted: bool,
    pub(super) pending_limit: usize,
    pub(super) slots: BTreeMap<u64, StoredSlot>,
    pub(super) applied_controls: BTreeMap<String, Control>,
}

impl Default for SyncState {
    fn default() -> Self {
        Self {
            source_verified: false,
            stream_id: None,
            download_cursor: 0,
            processed_cursor: 0,
            halted: false,
            pending_limit: 1000,
            slots: BTreeMap::new(),
            applied_controls: BTreeMap::new(),
        }
    }
}

impl SyncState {
    pub fn summary(&self) -> Value {
        json!({"stream_id":self.stream_id,"source_verified":self.source_verified,"download_cursor":self.download_cursor.to_string(),
            "processed_cursor":self.processed_cursor.to_string(),"halted":self.halted,
            "pending_count":self.slots.values().filter(|slot| slot.result.is_none() || slot.waiting).count(),
            "quarantined_count":self.slots.values().filter(|slot| slot.result.as_ref().is_some_and(|r| r["status"] == "quarantined")).count(),
            "slot_count":self.slots.len(),"applied_control_count":self.applied_controls.len(),
            "pending_limit":self.pending_limit})
    }
}
