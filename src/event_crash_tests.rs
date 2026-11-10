use super::*;
use crate::event_callback_fixture as callback;
use crate::event_observer_fixture as observer;
use crate::events_test_support::{fixture, secret, Setup};
use std::sync::atomic::Ordering;

#[test]
#[ignore = "invoked only by the bounded Events crash fixture"]
fn event_crash_child() {
    let Some(config) = std::env::var_os("GATEWAY_EVENT_FIXTURE_CONFIG") else {
        return;
    };
    let url = std::env::var("GATEWAY_EVENT_FIXTURE_URL").unwrap();
    let roots = std::env::var_os("GATEWAY_EVENT_FIXTURE_ROOTS").unwrap();
    let base = crate::serving::owner_events(std::path::Path::new(&config)).unwrap();
    let transport = callback::transport_for(&url, std::path::Path::new(&roots));
    let events = Events::with_transport(
        base.file,
        base.key,
        base.verifier,
        base.selected_grant,
        transport,
    );
    let cut = std::env::var("GATEWAY_EVENT_FIXTURE_CUT").unwrap();
    let subscriber = observer::AtEvent {
        target: if cut == "before" {
            "gateway_event_before_webhook"
        } else {
            "gateway_event_after_webhook"
        },
        action: || std::process::exit(75),
    };
    tracing::subscriber::with_default(subscriber, || {
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(tick(&events, "bus", "dot@bus"));
        panic!("crash cut not reached: {result:?}");
    });
}

#[tokio::test]
async fn crashes_after_attempt_and_after_callback_recover_same_event_and_lease() {
    for cut in ["before", "after"] {
        let mut setup = Setup::new();
        let callback = callback::CallbackFixture::new(&secret(4));
        let events = Events::with_transport(
            setup.provider.store_file.clone(),
            setup.key.clone(),
            setup.verifier.clone(),
            "grant".into(),
            callback.transport.clone(),
        );
        let identity = setup.verifier.verify("good-token").await.unwrap();
        events.subscribe(&identity,"good-token","bus","dot@bus",serde_json::from_value(json!({"name":crate::events::EVENT_NAME,"arguments":{},"delivery":{"mode":"webhook","url":callback.url,"secret":secret(4)},"cursor":null})).unwrap()).await.unwrap();
        setup.seed("message", "dot@bus", 2, i64::MAX);
        setup.provider.config["events"] = json!({"key_file":setup.provider.keys._directory.path().join("events-key"),"grant_id":"grant","dispatch_timeout_ms":13000});
        fixture::private_file(
            &setup.provider.config_file,
            &serde_json::to_vec(&setup.provider.config).unwrap(),
        );
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "event_dispatch::crash_tests::event_crash_child",
            ])
            .env("GATEWAY_EVENT_FIXTURE_CONFIG", &setup.provider.config_file)
            .env("GATEWAY_EVENT_FIXTURE_URL", &callback.url)
            .env("GATEWAY_EVENT_FIXTURE_ROOTS", callback.roots())
            .env("GATEWAY_EVENT_FIXTURE_CUT", cut)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() > deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("Events child did not reach crash cut");
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(
            status.code(),
            Some(75),
            "Events child did not reach crash cut"
        );
        let (state, attempts, body): (String, i64, Vec<u8>) = setup
            .db()
            .query_row(
                "SELECT state,attempts,body FROM custody_outbox WHERE event_id='message'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(state, "dispatching");
        assert_eq!(attempts, 1);
        let first: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(first["eventId"], "message");
        assert_eq!(
            callback.acked.load(Ordering::SeqCst),
            if cut == "before" { 0 } else { 1 }
        );
        let store = Store::open(&setup.provider.store_file).unwrap();
        let lease = store.try_operation_lease("gateway").unwrap();
        assert!(lease.is_some(), "dead worker retained the service lease");
        drop(lease);
        // Advance only the fixture's due-time; production retains its bounded crash backoff.
        setup
            .db()
            .execute(
                "UPDATE custody_outbox SET next_attempt=0 WHERE event_id='message'",
                [],
            )
            .unwrap();
        assert_eq!(
            tick(&events, "bus", "dot@bus").await.unwrap(),
            Tick::Accepted
        );
        let requests = callback.received.lock().unwrap();
        assert_eq!(requests.len(), if cut == "before" { 1 } else { 2 });
        for received in requests.iter() {
            assert_eq!(received.body, body, "restart regenerated body/ID");
        }
        assert_eq!(
            setup
                .db()
                .query_row("SELECT COUNT(*) FROM event_observations", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0,
            "transport acceptance fabricated responsibility"
        );
    }
}
