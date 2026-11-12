#![cfg(unix)]
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;
#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod serving_fixture;

use base64::Engine;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use xmsg_mcp_gateway::{
    auth::Verifier,
    grants::Store,
    outbound::{
        dispatch, Endpoint, Error, Limits, Outcome, Permission, Policy, Receipt, Request,
        RequestId, SendArguments,
    },
    xmsg_config::XmsgConfig,
};

fn fingerprint(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    format!("{:x}", digest.finalize())
}
fn token(claims: &serde_json::Value) -> String {
    format!(
        "e30.{}.fixture",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(claims).unwrap())
    )
}
fn reservation(db: &rusqlite::Connection) -> Vec<String> {
    db.query_row("SELECT * FROM outbound_reservations", [], |row| {
        (0..row.as_ref().column_count())
            .map(|column| Ok(format!("{:?}", row.get_ref(column)?)))
            .collect()
    })
    .unwrap()
}

#[tokio::test]
async fn foreign_pending_and_confirmed_reservations_are_denied_before_reverification() {
    for confirmed in [false, true] {
        for contended in [false, true] {
            let fixture = serving_fixture::Fixture::new();
            let mut first_config = fixture.config["verifier"].clone();
            first_config["required_scopes"] = json!(["send:write"]);
            let mut second_config = first_config.clone();
            second_config["hosted_client"] = json!("second-client");
            let verifier = Verifier::from_profiles(vec![
                serde_json::from_value(first_config).unwrap(),
                serde_json::from_value(second_config).unwrap(),
            ])
            .unwrap();
            let mut other = fixture.binding.clone();
            other.hosted_client = "second-client".into();
            let mut claims = provider::claims(&other);
            claims["scope"] = json!("send:write");
            let bearer = token(&claims);
            fixture
                .tokens
                .lock()
                .unwrap()
                .insert(bearer.clone(), claims);
            let mut own_claims = provider::claims(&fixture.binding);
            own_claims["scope"] = json!("send:write");
            let own_bearer = token(&own_claims);
            fixture
                .tokens
                .lock()
                .unwrap()
                .insert(own_bearer.clone(), own_claims);
            let mut store = Store::open(&fixture.store_file).unwrap();
            store.migrate_profiles().unwrap();
            store.migrate_custody().unwrap();
            store.migrate_outbound().unwrap();
            store.migrate_retirement().unwrap();
            store.enroll("second-grant", &other).unwrap();
            store.set_enabled("second-grant", 1, true).unwrap();
            let policy = Policy {
                send: Some(Permission {
                    targets: ["receiver@peer".into()].into(),
                    required_scope: "send:write".into(),
                }),
                reply: None,
            };
            store.set_outbound_policy("grant", 2, &policy).unwrap();
            store
                .set_outbound_policy("second-grant", 2, &policy)
                .unwrap();

            let directory = tempfile::tempdir().unwrap();
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let config = XmsgConfig {
                service: "gateway".into(),
                expected_node: "fixture".into(),
                daemon_uid: xmsg::client::current_uid(),
                register_socket: directory.path().join("register.sock"),
                agent_socket: directory.path().join("agent.sock"),
                max_frame_bytes: 4096,
                operation_timeout_ms: 2000,
            };
            let listener = UnixListener::bind(&config.register_socket).unwrap();
            let agent = std::os::unix::net::UnixListener::bind(&config.agent_socket).unwrap();
            agent.set_nonblocking(true).unwrap();
            std::fs::set_permissions(
                &config.register_socket,
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            std::fs::set_permissions(&config.agent_socket, std::fs::Permissions::from_mode(0o600))
                .unwrap();
            let server = tokio::spawn(async move {
                let mut stream = BufReader::new(listener.accept().await.unwrap().0);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&line).unwrap()["name"],
                    "gateway"
                );
                stream.get_mut().write_all(b"{\"status\":\"ok\",\"node\":\"fixture\",\"address\":\"gateway@fixture\"}\n").await.unwrap();
                assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
            });
            let registration = config.register().await.unwrap();
            let endpoint = Endpoint::from_registered(&registration).unwrap();
            let owner = fingerprint(&[
                &fixture.binding.service,
                &fixture.binding.issuer,
                &fixture.binding.resource,
                &fixture.binding.subject,
            ]);
            let payload = fingerprint(&["send", "receiver@peer", "", "original"]);
            let receipt = Receipt::Send(xmsg::client::SendResult {
                message_id: "private-receipt".into(),
                address: "receiver@peer".into(),
                outcome: "delivered".into(),
            });
            let encoded_receipt = confirmed.then(|| serde_json::to_string(&receipt).unwrap());
            let at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let db = rusqlite::Connection::open(&fixture.store_file).unwrap();
            db.execute(
                "INSERT INTO outbound_request_fences VALUES(?1,'same-id')",
                [&owner],
            )
            .unwrap();
            db.execute("INSERT INTO outbound_reservations(owner,operation,request_id,payload_hash,sender,grant_id,grant_revision,idempotency_key,target,framed_text,created_at,retry_until,state,receipt,recovery_until) VALUES(?1,'send','same-id',?2,'gateway@fixture','grant',3,'original-key','receiver@peer','original',?3,?4,?5,?6,?4)", rusqlite::params![owner,payload,at,at+86400,if confirmed { "confirmed" } else { "pending" },encoded_receipt]).unwrap();
            let request = Request::Send(SendArguments {
                request_id: RequestId::parse("same-id").unwrap(),
                to: "receiver@peer".into(),
                text: "original".into(),
            });
            let limits = Limits {
                dedup_lifetime_secs: 86400,
                result_recovery_secs: 86400,
                max_framed_bytes: 65536,
                timeout: Duration::from_secs(3),
                max_reservations: 1000,
                max_retained_bytes: 64 * 1024 * 1024,
            };
            let lease = if contended {
                Some(store.try_operation_lease("gateway").unwrap().unwrap())
            } else {
                None
            };
            let before = reservation(&db);
            let calls = fixture.requests.load(Ordering::SeqCst);
            let result = dispatch(
                &mut store, &endpoint, &verifier, &bearer, "bus", &request, &limits,
            )
            .await;
            assert!(matches!(result, Err(Error::Denied)), "foreign reservation recovered: {result:?}; confirmed={confirmed} contended={contended}");
            assert_eq!(
                fixture.requests.load(Ordering::SeqCst) - calls,
                1,
                "foreign reservation reached a second introspection before ownership refusal"
            );
            assert_eq!(
                reservation(&db),
                before,
                "foreign request mutated another grant's reservation"
            );
            assert!(
                matches!(agent.accept(), Err(e) if e.kind()==std::io::ErrorKind::WouldBlock),
                "foreign reservation caused bus I/O"
            );
            if confirmed {
                let result = dispatch(
                    &mut store,
                    &endpoint,
                    &verifier,
                    &own_bearer,
                    "bus",
                    &request,
                    &limits,
                )
                .await
                .unwrap();
                assert_eq!(
                    result,
                    Outcome::Confirmed(receipt),
                    "own-grant receipt recovery positive control failed"
                );
            } else if contended {
                assert_eq!(
                    dispatch(
                        &mut store,
                        &endpoint,
                        &verifier,
                        &own_bearer,
                        "bus",
                        &request,
                        &limits
                    )
                    .await
                    .unwrap(),
                    Outcome::Pending,
                    "own-grant contended reservation must remain pending"
                );
                assert_eq!(reservation(&db), before);
            }
            drop(lease);
            drop(endpoint);
            drop(registration);
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap();
        }
    }
}
