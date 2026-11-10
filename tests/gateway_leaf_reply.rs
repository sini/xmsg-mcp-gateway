#![cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;
#[allow(dead_code)]
#[path = "common/real_node.rs"]
mod real_node;
use serde_json::{json, Value};
use std::{collections::BTreeSet, time::Duration};
use xmsg_mcp_gateway::{
    event_store::EventKey,
    grants::Store,
    outbound::{Permission, Policy},
};
fn rpc(name: &str, args: Value) -> Value {
    json!({"jsonrpc":"2.0","id":"leaf-reply","method":"tools/call","params":{"name":name,"arguments":args}})
}
#[tokio::test]
#[ignore = "requires the pinned real leaf/hub daemon fixture"]
async fn mcp_leaf_send_reply_enters_owned_custody_with_attested_origin() {
    let binary = real_node::pinned_binary();
    let ca = real_node::Authority::generate();
    let leaf = real_node::Prepared::create("gateway", "leaf", Some(&ca));
    let hub = real_node::Prepared::create("receiver", "hub", Some(&ca));
    leaf.peer(
        &hub,
        json!({"principals":["receiver"],"targets":["gateway"]}),
    );
    hub.peer(
        &leaf,
        json!({"leaf":true,"principals":["gateway"],"targets":["receiver","gateway"]}),
    );
    let hub = hub.launch(&binary).await;
    let leaf = leaf.launch_leaf(&binary).await;
    let mut receiver = hub.config.register().await.unwrap();
    let mut setup = fixture::Fixture::new();
    let dir = setup.keys._directory.path();
    for claims in setup.tokens.lock().unwrap().values_mut() {
        claims["scope"] = json!("identity:read events:subscribe");
    }
    setup.config["verifier"]["required_scopes"] = json!(["identity:read", "events:subscribe"]);
    let keyfile = dir.join("events-key");
    fixture::private_file(&keyfile, &[8; 32]);
    let key = EventKey::load(&keyfile).unwrap();
    let mut store = Store::open(&setup.store_file).unwrap();
    store.migrate_custody().unwrap();
    store.migrate_outbound().unwrap();
    store.migrate_retirement().unwrap();
    store.migrate_events(&key).unwrap();
    store
        .set_outbound_policy(
            "grant",
            2,
            &Policy {
                send: Some(Permission {
                    targets: BTreeSet::from(["receiver@hub.fixture".into()]),
                    required_scope: "identity:read".into(),
                }),
                reply: None,
            },
        )
        .unwrap();
    drop(store);
    setup.config["request_timeout_ms"] = json!(60000);
    setup.config["events"] =
        json!({"grant_id":"grant","key_file":keyfile,"dispatch_timeout_ms":13000});
    let c = &leaf.config;
    setup.config["messaging"] = json!({"xmsg":{"service":c.service,"expected_node":c.expected_node,"daemon_uid":c.daemon_uid,"register_socket":c.register_socket,"agent_socket":c.agent_socket,"operation_timeout_ms":10000},"manifest":{"reply_ttl_secs":604800,"idempotency_ttl_secs":86400,"svc_queue_cap":100,"dedup_lifetime_secs":3600,"max_framed_bytes":65536},"submission_timeout_ms":10000,"max_reservations":100,"max_retained_bytes":1048576});
    fixture::private_file(
        &setup.config_file,
        &serde_json::to_vec(&setup.config).unwrap(),
    );
    let serving = setup.serving().await;
    let (http,sent,_)=fixture::request(&serving,"good-token",rpc("xmsg_send",json!({"request_id":"plain-leaf-read","to":"receiver@hub.fixture","text":"plain transport request"}))).await;
    assert_eq!(http, axum::http::StatusCode::OK, "{sent}");
    assert_eq!(
        sent["result"]["structuredContent"]["state"], "confirmed",
        "{sent}"
    );
    let original = sent["result"]["structuredContent"]["receipt"]["receipt"]["message_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let delivery = receiver.poll(5).await.unwrap().unwrap();
    assert_eq!(delivery.message_id(), original);
    assert_eq!(delivery.origin().service.as_deref(), Some("gateway"));
    assert_eq!(delivery.origin().node, "leaf.fixture");
    receiver.ack(delivery.message_id()).await.unwrap();
    let reply = receiver
        .reply(
            &original,
            "plain correlated answer",
            Some("plain-reply-key"),
        )
        .await
        .unwrap();
    assert!(reply.pushed_message_id.is_some());
    let observed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (_, inbox, _) =
                fixture::request(&serving, "good-token", rpc("xmsg_inbox", json!({}))).await;
            if let Some(item) = inbox["result"]["structuredContent"]["items"]
                .as_array()
                .and_then(|items| items.iter().find(|i| i["in_reply_to"] == original))
                .cloned()
            {
                break item;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let item = observed.unwrap_or_else(|_| {
        panic!(
            "leaf correlated reply absent from owned custody; hub push outcome {:?}",
            reply.push_outcome
        )
    });
    assert_eq!(item["origin"]["service"], "receiver");
    assert_eq!(item["origin"]["node"], "hub.fixture");
    assert!(item["origin"]["id"].is_null());
    assert_eq!(item["mailbox"], "gateway@leaf.fixture");
    assert_eq!(item["preview"], "plain correlated answer");
    println!("gateway-leaf-reply-complete:mcp-owned-custody-attested-origin");
}
