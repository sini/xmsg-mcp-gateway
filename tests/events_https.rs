#![cfg(unix)]
#[allow(dead_code)]
#[path = "common/event_callback.rs"]
mod event_callback;
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;
use base64::Engine;
use serde_json::json;
use std::sync::atomic::Ordering;
use xmsg_mcp_gateway::webhook;
fn key(byte: u8) -> String {
    format!(
        "whsec_{}",
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    )
}

#[tokio::test]
async fn real_https_receiver_verifies_challenge_event_retry_and_tamper_refusal() {
    let secret = key(4);
    let fixture = event_callback::CallbackFixture::new(&secret);
    webhook::verify_callback(
        fixture.transport.as_ref(),
        &fixture.url,
        "sub_owned",
        &secret,
    )
    .await
    .unwrap();
    assert_eq!(
        fixture.acked.load(Ordering::SeqCst),
        0,
        "verification is not an accepted mailbox event"
    );
    let body=serde_json::to_vec(&json!({"eventId":"event_stable","name":xmsg_mcp_gateway::events::EVENT_NAME,"timestamp":"2026-11-09T00:00:00Z","data":{"message_id":"owned","preview":"untrusted peer data"},"cursor":null})).unwrap();
    fixture.statuses.lock().unwrap().extend([503, 200]);
    for expected in [503, 200] {
        let response = webhook::signed_post(
            fixture.transport.as_ref(),
            &fixture.url,
            body.clone(),
            "event_stable",
            "sub_owned",
            &secret,
            None,
        )
        .await
        .unwrap();
        assert_eq!(response.status, expected);
    }
    {
        let received = fixture.received.lock().unwrap();
        assert_eq!(received.len(), 2);
        assert_eq!(received[0].body, body);
        assert_eq!(received[0].body, received[1].body);
        assert_eq!(
            received[0].headers["webhook-id"],
            received[1].headers["webhook-id"]
        );
        assert_eq!(received[0].headers["x-mcp-subscription-id"], "sub_owned");
    }
    let headers = webhook::signed_headers(
        "event_stable",
        "sub_owned",
        webhook::signing_time().unwrap(),
        &body,
        &secret,
        None,
    )
    .unwrap();
    let tampered = fixture
        .transport
        .post(&fixture.url, headers, b"tampered".to_vec())
        .await
        .unwrap();
    assert_eq!(tampered.status, 401);
    let wrong = webhook::signed_post(
        fixture.transport.as_ref(),
        &fixture.url,
        body,
        "event_stable",
        "sub_owned",
        &key(9),
        None,
    )
    .await
    .unwrap();
    assert_eq!(wrong.status, 401);
    assert_eq!(fixture.rejected.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.acked.load(Ordering::SeqCst), 1);
}
