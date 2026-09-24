use rockets_native_storage_probe::crypto::contract::{Action, Request};
use serde_json::json;

#[test]
fn initialize_rejects_unknown_fields_instead_of_creating_an_identity() {
    let valid = json!({"request_id":"init", "action":{"op":"initialize"}});
    let parsed: Request = serde_json::from_value(valid.clone()).unwrap();
    assert!(matches!(parsed.action, Action::Initialize {}));
    let mut unknown_action = valid.clone();
    unknown_action["action"]["unexpected"] = json!(true);
    assert!(serde_json::from_value::<Request>(unknown_action).is_err());
    let mut unknown_request = valid;
    unknown_request["unexpected"] = json!(true);
    assert!(serde_json::from_value::<Request>(unknown_request).is_err());
}
