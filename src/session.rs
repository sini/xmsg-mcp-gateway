use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

struct Owner(tokio::task::JoinHandle<()>);
impl Drop for Owner {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) struct Session {
    state: watch::Receiver<State>,
    wake: Arc<Notify>,
    _owner: Owner,
}

fn timestamp() -> Result<i64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|time| i64::try_from(time.as_secs()).ok())
        .ok_or(Error::Ledger)
}

fn record(store: &mut Store, bus: &str, connected: bool) -> Result<(), Error> {
    store
        .record_bus_link(bus, connected, &custody::Limits::default(), timestamp()?)
        .map_err(|_| Error::Ledger)
}

async fn record_link(file: PathBuf, bus: String, connected: bool) -> Result<(), Error> {
    tokio::task::spawn_blocking(move || {
        let mut store = Store::open(&file).map_err(|_| Error::Ledger)?;
        record(&mut store, &bus, connected)
    })
    .await
    .map_err(|_| Error::Ledger)?
}

impl Session {
    pub(crate) async fn start(
        config: XmsgConfig,
        manifest: DeploymentManifest,
        registered: RegisteredService,
        file: PathBuf,
        mut store: Store,
    ) -> Result<Self, Error> {
        let snapshot = Arc::new(Snapshot::from_registered(&registered)?);
        let bus = snapshot.bus.clone();
        tokio::task::spawn_blocking(move || record(&mut store, &bus, true))
            .await
            .map_err(|_| Error::Ledger)??;
        registered.health().map_err(Error::Registration)?;
        let (publish, state) = watch::channel(State::Ready(snapshot));
        let wake = Arc::new(Notify::new());
        let owner_wake = wake.clone();
        let subscriber = tracing::dispatcher::get_default(Clone::clone);
        let owner = tokio::spawn(
            async move {
                let mut current = registered;
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
                        if let Err(error) = record_link(file.clone(), bus.clone(), true).await {
                            publish.send_replace(State::Unavailable(Arc::new(error)));
                            break;
                        }
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                            _ = owner_wake.notified() => {},
                        }
                    }
                    drop(current);
                    loop {
                        if let Err(error) = record_link(file.clone(), bus.clone(), false).await {
                            publish.send_replace(State::Unavailable(Arc::new(error)));
                            tokio::time::sleep(delay).await;
                            delay = (delay * 2).min(Duration::from_secs(30));
                            continue;
                        }
                        break;
                    }
                    loop {
                        tokio::time::sleep(delay).await;
                        let replacement = async {
                            let registered = register(&config, &manifest).await?;
                            let snapshot = Arc::new(Snapshot::from_registered(&registered)?);
                            record_link(file.clone(), snapshot.bus.clone(), true).await?;
                            registered.health().map_err(Error::Registration)?;
                            Ok::<_, Error>((registered, snapshot))
                        }
                        .await;
                        match replacement {
                            Ok((registered, snapshot)) => {
                                current = registered;
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
            _owner: Owner(owner),
        })
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
