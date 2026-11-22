use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tokio::sync::{watch, Notify};
use tracing::instrument::WithSubscriber;
use xmsg::client::{ClientError, RegisteredService};

use crate::custody;
use crate::grants::Store;
use crate::outbound::Endpoint;
use crate::xmsg_config::{DeploymentManifest, ManifestError, XmsgConfig};

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("registration unavailable")]
    Registration(#[source] ClientError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("registered identity unavailable")]
    Identity,
    #[error("bus link ledger unavailable")]
    Ledger,
}

pub(crate) async fn register(
    config: &XmsgConfig,
    manifest: &DeploymentManifest,
) -> Result<RegisteredService, Error> {
    let registered = config.register().await.map_err(Error::Registration)?;
    registered.health().map_err(Error::Registration)?;
    manifest.check(
        registered.reply_ttl_secs(),
        registered.idempotency_ttl_secs(),
        registered.svc_queue_cap(),
        registered.max_body_bytes(),
    )?;
    tracing::info!(target: "gateway_registration", address = registered.address(), "registered xmsg service");
    Ok(registered)
}

pub(crate) struct Snapshot {
    pub(crate) endpoint: Endpoint,
    pub(crate) bus: String,
}

impl Snapshot {
    fn from_registered(registered: &RegisteredService, frame_bytes: usize) -> Result<Self, Error> {
        Ok(Self {
            endpoint: Endpoint::from_registered(registered)
                .map_err(|_| Error::Identity)?
                .with_frame_budget(frame_bytes),
            bus: registered.node().ok_or(Error::Identity)?.to_owned(),
        })
    }
}

#[derive(Clone)]
enum State {
    Ready(Arc<Snapshot>),
    Unavailable(Arc<Error>),
}

struct Owner(Mutex<Option<tokio::task::JoinHandle<()>>>);
impl Drop for Owner {
    fn drop(&mut self) {
        if let Some(task) = self
            .0
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            task.abort();
        }
    }
}

#[derive(Clone)]
pub(crate) struct Ingress {
    pub(crate) grant_id: String,
    pub(crate) limits: custody::Limits,
    pub(crate) capacity_log_interval: Duration,
}

pub(crate) struct Session {
    state: watch::Receiver<State>,
    wake: Arc<Notify>,
    _owner: Owner,
    stop: Arc<Notify>,
    file: PathBuf,
    bus: String,
    limits: custody::Limits,
    mailbox: String,
}

pub(crate) fn warn_custody_deferred(
    reason: &custody::DeferredReason,
    capacity: &custody::Capacity,
) {
    tracing::warn!(target: "gateway_custody", reason = reason.label(),
        rows = capacity.rows, bytes = capacity.bytes,
        max_items = capacity.max_items, max_bytes = capacity.max_bytes,
        active_rows = capacity.active_rows, retired_rows = capacity.retired_rows,
        max_retired_items = capacity.max_retired_items,
        "custody intake deferred");
}

fn observation_interval(reply_ttl_secs: u64) -> Duration {
    Duration::from_secs(reply_ttl_secs)
        .div_f64(2.0)
        .min(Duration::from_secs(60))
}

fn record(
    store: &mut Store,
    bus: &str,
    connected: bool,
    at: SystemTime,
    limits: &custody::Limits,
) -> Result<(), Error> {
    store
        .record_bus_link(bus, connected, limits, at)
        .map_err(|_| Error::Ledger)
}

struct CapacityLog {
    interval: Duration,
    last_sample: Option<tokio::time::Instant>,
}

impl CapacityLog {
    fn due(&self) -> bool {
        self.last_sample
            .is_none_or(|last| last.elapsed() >= self.interval)
            && tracing::enabled!(target: "gateway_custody", tracing::Level::INFO)
    }
}

async fn record_link(
    file: PathBuf,
    bus: String,
    connected: bool,
    limits: custody::Limits,
    capacity_log: Option<&mut CapacityLog>,
) -> Result<tokio::time::Instant, Error> {
    let sample = connected && capacity_log.as_ref().is_some_and(|log| log.due());
    let record_bus = bus.clone();
    let observed_at = tokio::time::Instant::now();
    let capacity = tokio::task::spawn_blocking(move || {
        let mut store = Store::open(&file).map_err(|_| Error::Ledger)?;
        record(
            &mut store,
            &record_bus,
            connected,
            SystemTime::now(),
            &limits,
        )?;
        let capacity = if sample {
            crate::attachment_store::ready(&store.connection)
                .and_then(|ready| custody::capacity(&store.connection, &limits, ready))
                .ok()
        } else {
            None
        };
        Ok::<_, Error>(capacity)
    })
    .await
    .map_err(|_| Error::Ledger)??;
    if let Some(log) = capacity_log.filter(|_| sample) {
        log.last_sample = Some(tokio::time::Instant::now());
    }
    if let Some(capacity) = capacity {
        tracing::info!(target: "gateway_custody",
            active_rows = capacity.active_rows, retired_rows = capacity.retired_rows,
            bytes = capacity.bytes, max_items = capacity.max_items,
            max_retired_items = capacity.max_retired_items, max_bytes = capacity.max_bytes,
            "custody capacity");
    }
    tracing::debug!(target: "gateway_bus_observation", bus, connected, "persisted bus observation");
    Ok(observed_at)
}

impl Session {
    pub(crate) async fn start(
        config: XmsgConfig,
        manifest: DeploymentManifest,
        registered: RegisteredService,
        file: PathBuf,
        mut store: Store,
        ingress: Option<Ingress>,
    ) -> Result<Self, Error> {
        let snapshot = Arc::new(Snapshot::from_registered(
            &registered,
            config.max_frame_bytes,
        )?);
        let bus = snapshot.bus.clone();
        let initial_observation = tokio::time::Instant::now();
        let custody_limits = ingress
            .as_ref()
            .map(|ingress| ingress.limits.clone())
            .unwrap_or_default();
        let initial_limits = custody_limits.clone();
        tokio::task::spawn_blocking(move || {
            record(&mut store, &bus, true, SystemTime::now(), &initial_limits)
        })
        .await
        .map_err(|_| Error::Ledger)??;
        registered.health().map_err(Error::Registration)?;
        let shutdown_bus = snapshot.bus.clone();
        let mailbox = snapshot.endpoint.sender().to_owned();
        let shutdown_file = file.clone();
        let observation_interval = observation_interval(manifest.reply_ttl_secs);
        let (publish, state) = watch::channel(State::Ready(snapshot));
        let stop = Arc::new(Notify::new());
        let owner_stop = stop.clone();
        let wake = Arc::new(Notify::new());
        let owner_wake = wake.clone();
        let shutdown_limits = custody_limits.clone();
        let subscriber = tracing::dispatcher::get_default(Clone::clone);
        let owner = tokio::spawn(
            async move {
                let mut current = registered;
                let mut observed_at = initial_observation;
                let mut capacity_log = ingress.as_ref().map(|ingress| CapacityLog {
                    interval: ingress.capacity_log_interval,
                    last_sample: None,
                });
                let mut delay = Duration::from_secs(1);
                loop {
                    let bus = match current.node() {
                        Some(bus) => bus.to_owned(),
                        None => return,
                    };
                    loop {
                        if let Err(error) = current.health() {
                            publish.send_replace(State::Unavailable(Arc::new(
                                Error::Registration(error),
                            )));
                            break;
                        }
                        if observed_at.elapsed() >= observation_interval {
                            match record_link(file.clone(), bus.clone(), true,custody_limits.clone(),capacity_log.as_mut()).await {
                                Ok(observation) => observed_at = observation,
                                Err(error) => {
                                    publish.send_replace(State::Unavailable(Arc::new(error)));
                                    break;
                                }
                            }
                        }
                        if let Some(ingress) = &ingress {
                            let scope = custody::Scope {
                                bus_instance: bus.clone(),
                                grant_id: ingress.grant_id.clone(),
                            };
                            match Store::open_for_dispatch(&file) {
                                Ok(mut custody_store) => {
                                    let received = tokio::select! {
                                        result = custody::receive_one(
                                            &mut custody_store,
                                            &mut current,
                                            &scope,
                                            &ingress.limits,
                                            SystemTime::now(),
                                        ) => result,
                                        _ = owner_stop.notified() => return,
                                    };
                                    match received {
                                        Ok(Some(custody::Acceptance::Deferred { reason, capacity })) => {
                                            warn_custody_deferred(&reason, &capacity);
                                        },
                                        Ok(Some(_)) => continue,
                                        Ok(None) => {},
                                        Err(custody::Error::Transport(error)) => {
                                            publish.send_replace(State::Unavailable(Arc::new(
                                                Error::Registration(error),
                                            )));
                                            break;
                                        }
                                        Err(_) => {
                                            tracing::warn!(target: "gateway_custody", "custody unavailable; no acceptance acknowledgement claimed");
                                        }
                                    }
                                }
                                Err(_) => tracing::warn!(target: "gateway_custody", "custody store unavailable"),
                            }
                        }
                        tracing::trace!(target: "gateway_bus_health", "registration alive");
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(1).min(observation_interval)) => {},
                            _ = owner_wake.notified() => {},
                            _ = owner_stop.notified() => return,
                        }
                    }
                    drop(current);
                    loop {
                        if let Err(error) = record_link(file.clone(), bus.clone(), false,custody_limits.clone(),None).await {
                            publish.send_replace(State::Unavailable(Arc::new(error)));
                            tokio::select! {
                                _ = tokio::time::sleep(delay) => {},
                                _ = owner_stop.notified() => return,
                            }
                            delay = (delay * 2).min(Duration::from_secs(30));
                            continue;
                        }
                        break;
                    }
                    loop {
                        tokio::select! {
                            _ = tokio::time::sleep(delay) => {},
                            _ = owner_stop.notified() => return,
                        }
                        let replacement = async {
                            let registered = register(&config, &manifest).await?;
                            let snapshot = Arc::new(Snapshot::from_registered(&registered, config.max_frame_bytes)?);
                            let observation = record_link(file.clone(), snapshot.bus.clone(), true, custody_limits.clone(), None).await?;
                            registered.health().map_err(Error::Registration)?;
                            Ok::<_, Error>((registered, snapshot, observation))
                        }
                        .await;
                        match replacement {
                            Ok((registered, snapshot, observation)) => {
                                current = registered;
                                observed_at = observation;
                                publish.send_replace(State::Ready(snapshot));
                                delay = Duration::from_secs(1);
                                break;
                            }
                            Err(error) => {
                                tracing::warn!(error = %error, "xmsg session unavailable");
                                publish.send_replace(State::Unavailable(Arc::new(error)));
                                delay = (delay * 2).min(Duration::from_secs(30));
                            }
                        }
                    }
                }
            }
            .with_subscriber(subscriber),
        );
        Ok(Self {
            state,
            wake,
            _owner: Owner(Mutex::new(Some(owner))),
            stop,
            file: shutdown_file,
            bus: shutdown_bus,
            limits: shutdown_limits,
            mailbox,
        })
    }

    pub(crate) async fn shutdown(&self) -> Result<(), Error> {
        let healthy = self.snapshot().is_ok();
        let task = self
            ._owner
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(task) = task {
            self.stop.notify_one();
            task.await.map_err(|_| Error::Ledger)?;
        }
        if healthy {
            record_link(
                self.file.clone(),
                self.bus.clone(),
                true,
                self.limits.clone(),
                None,
            )
            .await?;
        }
        record_link(
            self.file.clone(),
            self.bus.clone(),
            false,
            self.limits.clone(),
            None,
        )
        .await
        .map(|_| ())
    }

    /// Read scope remains the actual registered address during a temporary bus outage.
    pub(crate) fn custody_scope(&self) -> (&str, &str) {
        (&self.bus, &self.mailbox)
    }

    pub(crate) fn snapshot(&self) -> Result<Arc<Snapshot>, Arc<Error>> {
        match self.state.borrow().clone() {
            State::Unavailable(error) => Err(error),
            State::Ready(snapshot) => match snapshot.endpoint.health() {
                Ok(()) => Ok(snapshot),
                Err(error) => {
                    self.wake.notify_one();
                    Err(Arc::new(Error::Registration(error)))
                }
            },
        }
    }

    pub(crate) fn status(&self) -> serde_json::Value {
        match self.snapshot() {
            Ok(snapshot) => {
                serde_json::json!({"state":"ready","mailbox":snapshot.endpoint.sender()})
            }
            Err(error) => {
                let (state, reason) = match &*error {
                    Error::Manifest(error) => (
                        "blocked",
                        match error {
                            ManifestError::ReplyTtl => "reply_ttl_mismatch",
                            ManifestError::IdempotencyTtl => "idempotency_ttl_mismatch",
                            ManifestError::QueueCapacity => "queue_capacity_mismatch",
                            ManifestError::DedupLifetime => "dedup_lifetime_mismatch",
                            ManifestError::TextBound => "body_bound_mismatch",
                        },
                    ),
                    Error::Registration(_) => ("reconnecting", "registration_unavailable"),
                    Error::Identity => ("blocked", "identity_unavailable"),
                    Error::Ledger => ("blocked", "ledger_unavailable"),
                };
                serde_json::json!({"state":state,"reason":reason})
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    #[test]
    fn production_bus_observations_preserve_fractional_retention() {
        for nanos in [1, 999_999_999] {
            let directory = tempfile::tempdir().unwrap();
            let mut store = Store::initialize(&directory.path().join("store.db")).unwrap();
            store.migrate_custody().unwrap();
            record(
                &mut store,
                "node",
                true,
                UNIX_EPOCH + Duration::from_secs(100),
                &custody::Limits::default(),
            )
            .unwrap();
            let at = UNIX_EPOCH + Duration::new(101, nanos);
            record(&mut store, "node", false, at, &custody::Limits::default()).unwrap();
            let expiry: i64 = store
                .connection
                .query_row("SELECT expires_at FROM custody_gap_summary", [], |row| {
                    row.get(0)
                })
                .unwrap();
            let remaining = (UNIX_EPOCH + Duration::from_secs(expiry as u64))
                .duration_since(at)
                .unwrap();
            let lifetime = custody::Limits::default().metadata_retention_secs as u64;
            assert!(remaining >= Duration::from_secs(lifetime));
            assert!(remaining < Duration::from_secs(lifetime + 1));
        }
    }

    #[test]
    fn coalesced_observations_overestimate_downtime_by_at_most_the_interval() {
        let interval = observation_interval(604800);
        assert_eq!(
            interval,
            Duration::from_secs(60),
            "production observation bound changed"
        );
        assert_eq!(observation_interval(20), Duration::from_secs(10));
        assert_eq!(observation_interval(1), Duration::from_millis(500));
        for age in 0..=60 {
            let directory = tempfile::tempdir().unwrap();
            let mut store = Store::initialize(&directory.path().join("store.db")).unwrap();
            store.migrate_custody().unwrap();
            let limits = custody::Limits::default();
            store
                .record_bus_link("node", true, &limits, UNIX_EPOCH + Duration::from_secs(100))
                .unwrap();
            let true_downtime = 25;
            store
                .record_bus_link(
                    "node",
                    true,
                    &limits,
                    UNIX_EPOCH + Duration::from_secs((100 + age + true_downtime) as u64),
                )
                .unwrap();
            let gap: i64 = store
                .connection
                .query_row("SELECT MAX(widest) FROM custody_gap_summary", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert!(gap >= true_downtime);
            assert!(
                gap <= true_downtime + interval.as_secs() as i64,
                "coalescing exceeded its downtime overestimate bound"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn connected_observation_logs_only_capacity_at_the_configured_interval() {
        use crate::event_observability_tests::Capture;
        use crate::events_test_support::Setup;
        use std::collections::BTreeMap;
        use tracing::instrument::WithSubscriber;

        let setup = Setup::new();
        let file = setup.provider.store_file.clone();
        let mut store = Store::open(&file).unwrap();
        store.migrate_profiles().unwrap();
        store.migrate_authorization_server().unwrap();
        store
            .enroll("private-retired-grant", &setup.provider.binding)
            .unwrap();
        setup.seed("private-active-id", "private-mailbox", 2, i64::MAX);
        setup.seed("private-retired-id", "private-mailbox", 2, i64::MAX);
        let db = setup.db();
        db.execute("UPDATE custody_items SET grant_id='private-retired-grant' WHERE event_id='private-retired-id'", []).unwrap();
        db.execute(
            "INSERT INTO events_cutover(from_grant,to_grant,at,operator,reason,abandoned)
         VALUES('private-retired-grant','grant',1,'fixture','fixture',0)",
            [],
        )
        .unwrap();
        let limits = custody::Limits {
            max_items: 10,
            max_retired_items: 20,
            max_bytes: 30_000,
            ..custody::Limits::default()
        };
        let mut capacity_log = CapacityLog {
            interval: Duration::from_secs(4),
            last_sample: None,
        };
        let capture = Capture::custody_info();
        async {
            for (delay, connected, expected_lines) in
                [(0, true, 1), (3, true, 1), (1, false, 1), (0, true, 2)]
            {
                tokio::time::advance(Duration::from_secs(delay)).await;
                record_link(
                    file.clone(),
                    "private-bus".into(),
                    connected,
                    limits.clone(),
                    Some(&mut capacity_log),
                )
                .await
                .unwrap();
                assert_eq!(capture.0.lock().unwrap().len(), expected_lines);
            }
        }
        .with_subscriber(capture.clone())
        .await;
        let lines = capture.0.lock().unwrap();
        let expected = BTreeMap::from([
            ("message".into(), "custody capacity".into()),
            ("active_rows".into(), "1".into()),
            ("retired_rows".into(), "1".into()),
            ("bytes".into(), "136".into()),
            ("max_items".into(), "10".into()),
            ("max_retired_items".into(), "20".into()),
            ("max_bytes".into(), "30000".into()),
        ]);
        assert_eq!(lines.as_slice(), &[expected.clone(), expected]);
    }
}
