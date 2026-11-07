use xmsg_mcp_gateway::outbound::{ReplyArguments, RequestId, SendArguments};

#[test]
fn request_id_is_required_and_strict() {
    for invalid in ["", " ", "a b", "a\n", "naïve", &"a".repeat(129)] {
        assert!(RequestId::parse(invalid).is_err(), "accepted {invalid:?}");
    }
    for valid in ["a", "client:operation-1.2_3", &"a".repeat(128)] {
        assert_eq!(RequestId::parse(valid).unwrap().as_str(), valid);
    }
    for value in [
        serde_json::json!({"to":"receiver@node", "text":"hello"}),
        serde_json::json!({"request_id":null,"to":"receiver@node", "text":"hello"}),
        serde_json::json!({"request_id":123,"to":"receiver@node", "text":"hello"}),
        serde_json::json!({"request_id":"ok","to":"receiver@node", "text":"hello","id":1}),
    ] {
        let mut reply = value.clone();
        let to = reply.as_object_mut().unwrap().remove("to").unwrap();
        reply["message_id"] = to;
        assert!(
            serde_json::from_value::<ReplyArguments>(reply).is_err(),
            "outbound reply arguments accepted missing or non-strict request_id"
        );
        assert!(
            serde_json::from_value::<SendArguments>(value).is_err(),
            "outbound send arguments accepted missing or non-strict request_id"
        );
    }
    let args: SendArguments = serde_json::from_value(serde_json::json!({
        "request_id":"operation-1","to":"receiver@node","text":"hello"
    }))
    .unwrap();
    assert_eq!(args.request_id.as_str(), "operation-1");
}

#[test]
fn json_rpc_id_cannot_become_a_request_id() {
    trybuild::TestCases::new().compile_fail("tests/ui/request_id_from_rpc.rs");
}

#[test]
fn a_sqlite_transaction_cannot_cross_a_send_task_await() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/transaction_across_await.rs");
    tests.pass("tests/ui/transaction_before_await.rs");
}
