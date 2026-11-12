use serde_json::json;
use xmsg_mcp_gateway::outbound::{ReplyArguments, SendArguments};

#[test]
fn hosted_send_and_reply_accept_inline_file_inputs() {
    for attachment in [
        json!({"name":"report.txt","text":"file bytes"}),
        json!({"name":"image.bin","base64":"AAEC"}),
    ] {
        let send = json!({"request_id":"file-send","to":"receiver@node","text":"file","attachments":[attachment.clone()]});
        assert!(
            serde_json::from_value::<SendArguments>(send).is_ok(),
            "hosted send must accept inline file data"
        );
        let reply = json!({"request_id":"file-reply","message_id":"message","text":"file","attachments":[attachment]});
        assert!(
            serde_json::from_value::<ReplyArguments>(reply).is_ok(),
            "hosted reply must accept inline file data"
        );
    }
}

#[test]
fn hosted_files_refuse_ambiguous_or_host_path_inputs() {
    for input in [
        json!({"name":"file"}),
        json!({"name":"file","text":"x","base64":"eA=="}),
        json!({"name":"file","base64":"%%%"}),
        json!({"name":"file","path":"/private/canary"}),
        json!({"name":"file","sha256":"0".repeat(64)}),
    ] {
        assert!(serde_json::from_value::<SendArguments>(
            json!({"request_id":"invalid","to":"receiver@node","text":"file","attachments":[input]})
        )
        .is_err());
    }
    assert!(serde_json::from_value::<SendArguments>(json!({"request_id":"too-many","to":"receiver@node","text":"file","attachments":vec![json!({"name":"file","text":"x"});9]})).is_err());
}
