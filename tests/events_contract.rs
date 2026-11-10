use serde_json::json;
use xmsg_mcp_gateway::events::{Subscribe, Unsubscribe};

#[test]
fn observed_subscribe_shape_is_strict_and_mailbox_free() {
    let request = json!({"name":"xmsg.message.received.v1","arguments":{},
        "delivery":{"mode":"webhook","url":"https://callback.example/wake","secret":"whsec_fixture"},"cursor":null});
    assert!(serde_json::from_value::<Subscribe>(request.clone()).is_ok());
    for extra in ["mailbox", "from", "subject", "replace"] {
        let mut wrong = request.clone();
        wrong[extra] = json!("caller-selected");
        assert!(
            serde_json::from_value::<Subscribe>(wrong).is_err(),
            "accepted {extra}"
        );
    }
    let mut wrong = request;
    wrong["arguments"] = json!({"mailbox":"foreign"});
    assert!(serde_json::from_value::<Subscribe>(wrong).is_err());
}

#[test]
fn unsubscribe_does_not_accept_signing_material_or_takeover_flags() {
    let request = json!({"name":"xmsg.message.received.v1","arguments":{},
        "delivery":{"mode":"webhook","url":"https://callback.example/wake"}});
    assert!(serde_json::from_value::<Unsubscribe>(request.clone()).is_ok());
    let mut wrong = request;
    wrong["delivery"]["secret"] = json!("should-not-be-here");
    assert!(serde_json::from_value::<Unsubscribe>(wrong).is_err());
}
