use crate::events_test_support::{request, Behavior, Setup};
use crate::grants::Store;
use crate::reads::{self, InboxArguments, ReadArguments, Request};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tracing::instrument::WithSubscriber;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<BTreeMap<String, String>>>>);
impl tracing::Subscriber for Capture {
    fn enabled(&self, m: &tracing::Metadata<'_>) -> bool {
        m.target() == "gateway_events" && *m.level() == tracing::Level::INFO
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, e: &tracing::Event<'_>) {
        struct Fields(BTreeMap<String, String>);
        impl tracing::field::Visit for Fields {
            fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
                self.0.insert(f.name().into(), v.into());
            }
            fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                self.0.insert(f.name().into(), format!("{v:?}"));
            }
        }
        let mut fields = Fields(BTreeMap::new());
        e.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
}
fn privacy(capture: &Capture, canaries: &[&str]) {
    let rows = capture.0.lock().unwrap();
    let output = format!("{rows:?}");
    for canary in canaries {
        assert!(
            !output.contains(canary),
            "Events diagnostics leaked request data: {output}"
        );
    }
    assert!(
        rows.iter().flat_map(|row| row.keys()).all(|key| [
            "message",
            "class",
            "reason",
            "changed",
            "held",
            "released",
            "attempt",
            "callback_host"
        ]
        .contains(&key.as_str())),
        "Events diagnostics leaked an unapproved field: {output}"
    );
}

#[tokio::test]
async fn committed_fence_dead_letter_and_consumer_state_are_private_and_read_only() {
    let capture = Capture::default();
    let subscriber = capture.clone();
    async {
        let setup=Setup::new();
        let mut request=request();request.delivery.url="https://receiver.example.com/url-canary-45".into();
        let secret=request.delivery.secret.clone();
        let identity=setup.verifier.verify("good-token").await.unwrap();
        setup.runtime().subscribe(&identity,"good-token","bus","dot@bus",request).await.unwrap();
        privacy(&capture,&["url-canary-45","good-token",&secret]);
        capture.0.lock().unwrap().clear();
        let mut store=Store::open(&setup.provider.store_file).unwrap();
        store.set_outbound_policy("grant",2,&crate::outbound::Policy::default()).unwrap();
        assert!(capture.0.lock().unwrap().is_empty(),"policy carry-forward was logged as a fence");
        setup.seed("ID_CANARY_45","dot@bus",3,i64::MAX);
        setup.db().execute("UPDATE custody_items SET text='BODY_CANARY_45'",[]).unwrap();
        setup.callback.behaviors.lock().unwrap().push_back(Behavior::Response(410,None));
        assert_eq!(crate::event_dispatch::tick(&setup.runtime(),"bus","dot@bus").await.unwrap(),crate::event_dispatch::Tick::Dead);
        let rows=capture.0.lock().unwrap().clone();
        assert_eq!(rows.len(),1);assert_eq!(rows[0]["class"],"dead");assert_eq!(rows[0]["reason"],"delivery_gone");
        capture.0.lock().unwrap().clear();
        setup.seed("PENDING_CANARY_45","dot@bus",3,i64::MAX);
        setup.db().execute_batch("CREATE TRIGGER abort_fence BEFORE UPDATE ON event_subscriptions BEGIN SELECT RAISE(ABORT,'forced rollback'); END;").unwrap();
        assert!(store.set_enabled("grant",3,false).is_err());
        assert!(capture.0.lock().unwrap().is_empty(),"rolled-back fence was logged");
        setup.db().execute_batch("DROP TRIGGER abort_fence;").unwrap();
        store.set_enabled("grant",3,false).unwrap();
        let rows=capture.0.lock().unwrap().clone();
        assert_eq!(rows.len(),1,"fence did not emit exactly one transition");assert_eq!(rows[0]["reason"],"disabled_by_revision");assert_eq!(rows[0]["held"],"1");
        privacy(&capture,&["url-canary-45",&secret,"BODY_CANARY_45","ID_CANARY_45","PENDING_CANARY_45","good-token"]);
        assert!(matches!(reads::dispatch(Store::open(&setup.provider.store_file).unwrap(),&identity,"bus","dot@bus",Request::Inbox(InboxArguments{after:None,limit:None})),Err(reads::Error::Authority(crate::grants::Error::Denied))));
        store.set_enabled("grant",4,true).unwrap();
        setup.seed("visible","dot@bus",5,i64::MAX);
        let before=std::fs::read(&setup.provider.store_file).unwrap();
        let inbox=reads::dispatch(Store::open(&setup.provider.store_file).unwrap(),&identity,"bus","dot@bus",Request::Inbox(InboxArguments{after:None,limit:None})).unwrap();
        assert_eq!(inbox["events_status"]["subscription"]["state"],"disabled","consumer did not learn that subscription was fenced");
        let read=reads::dispatch(Store::open(&setup.provider.store_file).unwrap(),&identity,"bus","dot@bus",Request::Read(ReadArguments{message_id:"visible".into(),offset:None,limit:None})).unwrap();
        assert_eq!(read["events_status"]["subscription"]["state"],"disabled");
        let missing=reads::dispatch(Store::open(&setup.provider.store_file).unwrap(),&identity,"bus","foreign@bus",Request::Read(ReadArguments{message_id:"visible".into(),offset:None,limit:None})).unwrap();
        assert_eq!(missing,serde_json::json!({"state":"not_found"}));
        assert_eq!(std::fs::read(&setup.provider.store_file).unwrap(),before,"consumer state read mutated Events state");
    }.with_subscriber(subscriber).await;
}

#[tokio::test]
async fn recovery_success_reports_owned_fenced_subscription_state_without_writes() {
    let setup = Setup::new();
    let identity = setup.subscribe().await;
    let mut store = Store::open(&setup.provider.store_file).unwrap();
    store.set_enabled("grant", 2, false).unwrap();
    store.set_enabled("grant", 3, true).unwrap();
    setup.seed("owned", "dot@bus", 4, i64::MAX);
    let before = std::fs::read(&setup.provider.store_file).unwrap();
    let inbox = reads::dispatch(
        Store::open(&setup.provider.store_file).unwrap(),
        &identity,
        "bus",
        "dot@bus",
        Request::Inbox(InboxArguments {
            after: None,
            limit: None,
        }),
    )
    .unwrap();
    assert_eq!(
        inbox["events_status"]["subscription"]["state"], "disabled",
        "successful recovery omitted fenced subscription state"
    );
    let read = reads::dispatch(
        Store::open(&setup.provider.store_file).unwrap(),
        &identity,
        "bus",
        "dot@bus",
        Request::Read(ReadArguments {
            message_id: "owned".into(),
            offset: None,
            limit: None,
        }),
    )
    .unwrap();
    assert_eq!(read["events_status"]["subscription"]["state"], "disabled");
    assert_eq!(std::fs::read(&setup.provider.store_file).unwrap(), before);
}

#[tokio::test]
async fn expiry_is_observed_once_per_worker_generation_and_reads_report_expired_without_writes() {
    let setup = Setup::new();
    let identity = setup.subscribe().await;
    setup.seed("owned-expiry", "dot@bus", 2, i64::MAX);
    setup
        .db()
        .execute("UPDATE event_subscriptions SET expires=1", [])
        .unwrap();
    let capture = Capture::default();
    let before = std::fs::read(&setup.provider.store_file).unwrap();
    let runtime = setup.runtime();
    let mut observation = crate::event_dispatch::ExpiryObservation::default();
    tracing::subscriber::with_default(capture.clone(), || {
        observation.observe(&runtime, "bus", "dot@bus").unwrap();
        observation.observe(&runtime, "bus", "dot@bus").unwrap();
    });
    assert_eq!(
        capture.0.lock().unwrap().len(),
        1,
        "expiry observation logged every idle poll"
    );
    assert_eq!(capture.0.lock().unwrap()[0]["reason"], "expired");
    let inbox = reads::dispatch(
        Store::open(&setup.provider.store_file).unwrap(),
        &identity,
        "bus",
        "dot@bus",
        Request::Inbox(InboxArguments {
            after: None,
            limit: None,
        }),
    )
    .unwrap();
    let read = reads::dispatch(
        Store::open(&setup.provider.store_file).unwrap(),
        &identity,
        "bus",
        "dot@bus",
        Request::Read(ReadArguments {
            message_id: "owned-expiry".into(),
            offset: None,
            limit: None,
        }),
    )
    .unwrap();
    assert_eq!(
        inbox["events_status"]["subscription"]["state"], "expired",
        "consumer omitted derived subscription expiry"
    );
    assert_eq!(read["events_status"]["subscription"]["state"], "expired");
    assert_eq!(
        std::fs::read(&setup.provider.store_file).unwrap(),
        before,
        "expiry observation persisted a state change"
    );
    setup
        .db()
        .execute("UPDATE event_subscriptions SET generation=generation+1", [])
        .unwrap();
    tracing::subscriber::with_default(capture.clone(), || {
        observation.observe(&runtime, "bus", "dot@bus").unwrap();
        observation.observe(&runtime, "bus", "dot@bus").unwrap();
        let mut restarted = crate::event_dispatch::ExpiryObservation::default();
        restarted.observe(&runtime, "bus", "dot@bus").unwrap();
    });
    assert_eq!(
        capture.0.lock().unwrap().len(),
        3,
        "new generation or worker restart did not get one expiry observation"
    );
}
