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
    fn from_registered(registered: &RegisteredService) -> Result<Self, Error> {
        Ok(Self {
            endpoint: Endpoint::from_registered(registered).map_err(|_| Error::Identity)?,
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

async fn record_link(
    file: PathBuf,
    bus: String,
    connected: bool,
    limits: custody::Limits,
) -> Result<tokio::time::Instant, Error> {
    let record_bus = bus.clone();
    let observed_at = tokio::time::Instant::now();
    tokio::task::spawn_blocking(move || {
        let mut store = Store::open(&file).map_err(|_| Error::Ledger)?;
        record(
            &mut store,
            &record_bus,
            connected,
            SystemTime::now(),
            &limits,
        )
    })
    .await
    .map_err(|_| Error::Ledger)??;
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
        let snapshot = Arc::new(Snapshot::from_registered(&registered)?);
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
                                        Ok(Some(custody::Acceptance::Deferred)) => {},
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
                        if observed_at.elapsed() >= observation_interval {
                            match record_link(file.clone(), bus.clone(), true,custody_limits.clone()).await {
                                Ok(observation) => observed_at = observation,
                                Err(error) => {
                                    publish.send_replace(State::Unavailable(Arc::new(error)));
                                    break;
                                }
                            }
                        }
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(1).min(observation_interval)) => {},
                            _ = owner_wake.notified() => {},
                            _ = owner_stop.notified() => return,
                        }
                    }
                    drop(current);
                    loop {
                        if let Err(error) = record_link(file.clone(), bus.clone(), false,custody_limits.clone()).await {
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
                            let snapshot = Arc::new(Snapshot::from_registered(&registered)?);
                            let observation = record_link(file.clone(), snapshot.bus.clone(), true, custody_limits.clone()).await?;
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
            )
            .await?;
        }
        record_link(
            self.file.clone(),
            self.bus.clone(),
            false,
            self.limits.clone(),
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
                .query_row("SELECT expires_at FROM custody_gaps", [], |row| row.get(0))
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
                .query_row(
                    "SELECT MAX(gap_end-gap_start) FROM custody_gaps",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(gap >= true_downtime);
            assert!(
                gap <= true_downtime + interval.as_secs() as i64,
                "coalescing exceeded its downtime overestimate bound"
            );
        }
    }
}
