use crate::dispatch_outcome as diagnostic;
use std::collections::BTreeSet;
use std::error::Error as _;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;

use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::auth::{self, VerifiedIdentity, Verifier, VerifierConfig};
use crate::grants::{Authorization, Binding, Error as GrantError, Store};
use crate::outbound::{self, Outcome, Policy};
use crate::xmsg_config::{DeploymentManifest, ManifestError, XmsgConfig};
use crate::{event_dispatch, events, reads, recovery, session};

const MAX_OWNER_FILE: usize = 65_536;

fn default_max_request_body_bytes() -> usize {
    1_048_576
}
const VERSIONS: [&str; 3] = ["2025-03-26", "2025-06-18", "2025-11-25"];

#[derive(Debug, thiserror::Error)]
#[error("invalid or unavailable owner serving configuration")]
pub struct ConfigurationError;

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),
    #[error("invalid xmsg connection configuration or service name")]
    ConnectionConfiguration,
    #[error("xmsg registration failed")]
    Registration(#[source] xmsg::client::ClientError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("messaging store is not ready: {0}")]
    Store(#[source] outbound::Error),
    #[error("request budget must cover verification, store wait and submission")]
    RequestBudget,
    #[error("bus link ledger is unavailable")]
    BusLedger,
    #[error("request body budget must cover six times the complete framed bound plus 16384 bytes")]
    RequestBodyBudget,
}

impl From<session::Error> for StartupError {
    fn from(error: session::Error) -> Self {
        match error {
            session::Error::Registration(error) => Self::Registration(error),
            session::Error::Manifest(error) => Self::Manifest(error),
            session::Error::Identity => Self::ConnectionConfiguration,
            session::Error::Ledger => Self::BusLedger,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventsConfiguration {
    key_file: PathBuf,
    grant_id: String,
    #[serde(default)]
    custody_limits: crate::custody::Limits,
    dispatch_timeout_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessagingConfiguration {
    xmsg: XmsgConfig,
    manifest: DeploymentManifest,
    submission_timeout_ms: u64,
    #[serde(default = "default_result_recovery_secs")]
    result_recovery_secs: i64,
    max_reservations: i64,
    max_retained_bytes: i64,
}

fn default_result_recovery_secs() -> i64 {
    86_400
}

fn present_messaging<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<MessagingConfiguration>, D::Error> {
    MessagingConfiguration::deserialize(deserializer).map(Some)
}

struct Messaging {
    session: session::Session,
    limits: outbound::Limits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    #[serde(default = "default_header_read_timeout_ms")]
    header_read_timeout_ms: u64,
    bind: SocketAddr,
    grant_store: PathBuf,
    request_timeout_ms: u64,
    #[serde(default = "default_max_connections")]
    max_connections: usize,
    #[serde(default = "default_max_request_body_bytes")]
    max_request_body_bytes: usize,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    verifier: VerifierConfig,
    events: Option<EventsConfiguration>,
    #[serde(default, deserialize_with = "present_messaging")]
    messaging: Option<MessagingConfiguration>,
    broker: Option<crate::broker::Config>,
}

fn default_header_read_timeout_ms() -> u64 {
    5_000
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("request headers exceeded their read deadline")]
pub struct HeaderReadTimeout;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TransportRefusal {
    #[error("request body exceeds the configured {limit_bytes}-byte limit")]
    BodyTooLarge { limit_bytes: usize },
    #[error("request body could not be read")]
    BodyReadFailed,
}

impl IntoResponse for TransportRefusal {
    fn into_response(self) -> Response {
        let status = match self {
            Self::BodyTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BodyReadFailed => StatusCode::BAD_REQUEST,
        };
        tracing::warn!(target: "gateway_transport", reason = ?self, "transport refused");
        let mut response = status.into_response();
        // Preserve the domain refusal for response middleware and metrics.
        response.extensions_mut().insert(self);
        response
    }
}

struct App {
    dispatch_tasks: tokio::sync::Mutex<tokio::task::JoinSet<()>>,
    verifier: Arc<Verifier>,
    events: Option<Arc<events::Events>>,
    event_worker: Option<event_dispatch::Worker>,
    grant_store: PathBuf,
    request_timeout_ms: u64,
    max_request_body_bytes: usize,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    resource: String,
    issuer: String,
    scopes: Vec<String>,
    challenge: HeaderValue,
    messaging: Option<Messaging>,
    broker: Option<crate::broker::Config>,
}

fn default_max_connections() -> usize {
    128
}

#[derive(Debug, thiserror::Error)]
#[error("connection capacity exhausted")]
pub struct ConnectionCapacityRefusal;

pub struct Serving {
    header_read_timeout: Duration,
    state: Arc<App>,
    router: Router,
    bind: SocketAddr,
    max_connections: usize,
}

fn resolve_profile_path(directory: &Path, file: &mut PathBuf) {
    if file.is_relative() {
        *file = directory.join(&*file);
    }
}

impl Serving {
    pub async fn from_owner_file(config_file: &Path) -> Result<Self, StartupError> {
        Self::from_owner_file_with_transport(config_file, Arc::new(crate::webhook::PublicHttps))
            .await
    }

    async fn from_owner_file_with_transport(
        config_file: &Path,
        transport: Arc<dyn crate::webhook::Transport>,
    ) -> Result<Self, StartupError> {
        let config = load_configuration(config_file)?;
        if !config.bind.ip().is_loopback()
            || config.allowed_hosts.is_empty()
            || config.header_read_timeout_ms == 0
            || config.header_read_timeout_ms > 60_000
            || config.max_connections == 0
            || config.max_connections > Semaphore::MAX_PERMITS
            || config.max_request_body_bytes == 0
            || config.request_timeout_ms == 0
            || config.request_timeout_ms > 60_000
            || config
                .allowed_hosts
                .iter()
                .any(|host| host.trim().is_empty())
            || !config
                .verifier
                .required_scopes
                .iter()
                .any(|scope| scope == "identity:read")
        {
            return Err(ConfigurationError.into());
        }
        if let Some(messaging) = &config.messaging {
            let minimum = messaging
                .manifest
                .max_framed_bytes
                .checked_mul(6)
                .and_then(|bytes| bytes.checked_add(16_384))
                .ok_or(StartupError::RequestBodyBudget)?;
            if config.max_request_body_bytes < minimum {
                return Err(StartupError::RequestBodyBudget);
            }
        }
        if let Some(broker) = &config.broker {
            if broker.origin().is_none() || config.messaging.is_none() || config.events.is_none() {
                return Err(ConfigurationError.into());
            }
        }
        let mut metadata_url =
            reqwest::Url::parse(&config.verifier.resource).map_err(|_| ConfigurationError)?;
        let resource_path = metadata_url.path().trim_end_matches('/').to_owned();
        if resource_path.contains(['{', '}', '*']) || resource_path.starts_with("/.well-known/") {
            return Err(ConfigurationError.into());
        }
        metadata_url.set_path(&format!(
            "{resource_path}/.well-known/oauth-protected-resource"
        ));
        metadata_url.set_query(None);
        metadata_url.set_fragment(None);
        let challenge =
            HeaderValue::from_str(&format!("Bearer resource_metadata=\"{metadata_url}\""))
                .map_err(|_| ConfigurationError)?;
        let resource = config.verifier.resource.clone();
        let issuer = config.verifier.issuer.clone();
        let scopes = config.verifier.required_scopes.clone();
        let profile = Binding {
            service: config.verifier.service.clone(),
            issuer: config.verifier.issuer.clone(),
            resource: config.verifier.resource.clone(),
            subject: config.verifier.subject.clone(),
            hosted_client: config.verifier.hosted_client.clone(),
        };
        let verification_timeout_ms = config.verifier.timeout_ms;
        let verifier =
            Arc::new(Verifier::from_config(config.verifier).map_err(|_| ConfigurationError)?);
        let store = Store::open(&config.grant_store).map_err(|_| ConfigurationError)?;
        store
            .validate_profile(&profile)
            .map_err(|_| ConfigurationError)?;
        let events = if let Some(configuration) = &config.events {
            if config.messaging.is_none()
                || !verifier.requires_scope("events:subscribe")
                || configuration.grant_id.is_empty()
                || configuration.dispatch_timeout_ms > 60_000
                || configuration.dispatch_timeout_ms
                    < verification_timeout_ms.saturating_add(11_000)
                || config.request_timeout_ms
                    < verification_timeout_ms
                        .saturating_mul(2)
                        .saturating_add(41_000)
            {
                return Err(ConfigurationError.into());
            }
            configuration
                .custody_limits
                .validate()
                .map_err(|_| ConfigurationError)?;
            let matches:bool=store.connection.query_row("SELECT EXISTS(SELECT 1 FROM grants WHERE id=?1 AND service=?2 AND issuer=?3 AND resource=?4 AND subject=?5 AND hosted_client=?6)",rusqlite::params![configuration.grant_id,profile.service,profile.issuer,profile.resource,profile.subject,profile.hosted_client],|row|row.get(0)).map_err(|_|ConfigurationError)?;
            if !matches {
                return Err(ConfigurationError.into());
            }
            let key = crate::event_store::EventKey::load(&configuration.key_file)
                .map_err(|_| ConfigurationError)?;
            store
                .require_events_ready(&key)
                .map_err(|_| ConfigurationError)?;
            Some(Arc::new(events::Events::with_transport(
                config.grant_store.clone(),
                key,
                verifier.clone(),
                configuration.grant_id.clone(),
                transport,
            )))
        } else {
            None
        };
        let mut event_worker = None;
        let messaging = if let Some(messaging) = config.messaging {
            store
                .require_outbound_ready()
                .map_err(StartupError::Store)?;
            store
                .require_retirement_ready()
                .map_err(StartupError::Store)?;
            let limits = outbound::Limits {
                dedup_lifetime_secs: i64::try_from(messaging.manifest.idempotency_ttl_secs)
                    .map_err(|_| ManifestError::DedupLifetime)?,
                result_recovery_secs: messaging.result_recovery_secs,
                max_framed_bytes: messaging.manifest.max_framed_bytes,
                timeout: Duration::from_millis(messaging.submission_timeout_ms),
                max_reservations: messaging.max_reservations,
                max_retained_bytes: messaging.max_retained_bytes,
            };
            limits.validate().map_err(StartupError::Store)?;
            let store_wait_ms: i64 = store
                .connection
                .pragma_query_value(None, "busy_timeout", |row| row.get(0))
                .map_err(|_| ConfigurationError)?;
            let minimum_budget = verification_timeout_ms
                .checked_add(u64::try_from(store_wait_ms).map_err(|_| StartupError::RequestBudget)?)
                .and_then(|value| value.checked_add(messaging.submission_timeout_ms))
                .ok_or(StartupError::RequestBudget)?;
            if config.request_timeout_ms < minimum_budget {
                return Err(StartupError::RequestBudget);
            }
            let registered = session::register(&messaging.xmsg, &messaging.manifest).await?;
            if let (Some(events), Some(configuration)) = (&events, &config.events) {
                event_worker = Some(event_dispatch::Worker::start(
                    events.clone(),
                    registered.node().ok_or(ConfigurationError)?.to_owned(),
                    registered.address().ok_or(ConfigurationError)?.to_owned(),
                    Duration::from_millis(configuration.dispatch_timeout_ms),
                ));
            }
            let ingress = config
                .events
                .as_ref()
                .map(|configuration| session::Ingress {
                    grant_id: configuration.grant_id.clone(),
                    limits: configuration.custody_limits.clone(),
                });
            let session = session::Session::start(
                messaging.xmsg,
                messaging.manifest,
                registered,
                config.grant_store.clone(),
                store,
                ingress,
            )
            .await?;
            Some(Messaging { session, limits })
        } else {
            None
        };
        let state = Arc::new(App {
            dispatch_tasks: tokio::sync::Mutex::new(tokio::task::JoinSet::new()),
            verifier,
            events,
            event_worker,
            grant_store: config.grant_store,
            allowed_hosts: config.allowed_hosts,
            allowed_origins: config.allowed_origins,
            request_timeout_ms: config.request_timeout_ms,
            max_request_body_bytes: config.max_request_body_bytes,
            resource,
            issuer,
            scopes,
            challenge,
            messaging,
            broker: config.broker,
        });
        let mut router = Router::new().route("/mcp", any(mcp));
        for path in BTreeSet::from([
            "/.well-known/oauth-protected-resource".to_owned(),
            format!("/.well-known/oauth-protected-resource{resource_path}"),
            format!("{resource_path}/.well-known/oauth-protected-resource"),
        ]) {
            router = router.route(&path, get(protected_resource));
        }
        Ok(Self {
            header_read_timeout: Duration::from_millis(config.header_read_timeout_ms),
            router: router.with_state(state.clone()),
            state,
            bind: config.bind,
            max_connections: config.max_connections,
        })
    }

    pub fn router(&self) -> Router {
        self.router.clone()
    }

    pub async fn serve(self) -> std::io::Result<()> {
        #[cfg(unix)]
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let listener = tokio::net::TcpListener::bind(self.bind).await?;
        println!("serving MCP at {}", listener.local_addr()?);
        let permits = Arc::new(Semaphore::new(self.max_connections));
        let shutdown = async move {
            #[cfg(unix)]
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
            #[cfg(not(unix))]
            let _ = tokio::signal::ctrl_c().await;
        };
        tokio::pin!(shutdown);
        let (stopping, stopped) = tokio::sync::watch::channel(false);
        let mut connections = tokio::task::JoinSet::new();
        let result = loop {
            tokio::select! {
                _ = &mut shutdown => break Ok(()),
                Some(_) = connections.join_next(), if !connections.is_empty() => {},
                accepted = listener.accept() => {
                    let (socket, _) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            if matches!(error.kind(), std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::ConnectionReset) {
                                continue;
                            }
                            tracing::warn!(error = %error, kind = ?error.kind(), "accept failed; retrying");
                            tokio::select! {
                                _ = &mut shutdown => break Ok(()),
                                _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                            }
                            continue;
                        }
                    };
                    let permit = match permits.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            tracing::warn!(target: "gateway_transport", reason = ?ConnectionCapacityRefusal, "connection refused");
                            drop(socket);
                            continue;
                        }
                    };
                    let router = self.router.clone();
                    let deadline = self.header_read_timeout;
                    let mut stopped = stopped.clone();
                    connections.spawn(async move {
                        let _permit = permit;
                        let mut builder = hyper::server::conn::http1::Builder::new();
                        builder.timer(hyper_util::rt::TokioTimer::new());
                        builder.header_read_timeout(deadline);
                        let connection = builder.serve_connection(
                            hyper_util::rt::TokioIo::new(socket),
                            hyper_util::service::TowerToHyperService::new(router),
                        ).with_upgrades();
                        tokio::pin!(connection);
                        let outcome = tokio::select! {
                            outcome = &mut connection => outcome,
                            _ = stopped.changed() => {
                                connection.as_mut().graceful_shutdown();
                                connection.await
                            }
                        };
                        if let Err(error) = outcome {
                            if error.is_timeout() {
                                let reason = HeaderReadTimeout;
                                tracing::warn!(target: "gateway_transport", reason = ?reason, "transport refused");
                            }
                        }
                    });
                }
            }
        };
        drop(listener);
        let _ = stopping.send(true);
        while connections.join_next().await.is_some() {}
        {
            let mut tasks = self.state.dispatch_tasks.lock().await;
            while tasks.join_next().await.is_some() {}
        }
        if let Some(worker) = &self.state.event_worker {
            worker.shutdown().await;
        }
        if let Some(messaging) = &self.state.messaging {
            messaging
                .session
                .shutdown()
                .await
                .map_err(std::io::Error::other)?;
        }
        result
    }
}

fn permitted_request(app: &App, request: &Request) -> bool {
    if request.headers().get_all(header::HOST).iter().count() != 1
        || request.headers().get_all(header::ORIGIN).iter().count() > 1
    {
        return false;
    }
    let Some(host) = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Ok(url) = reqwest::Url::parse(&format!("http://{host}/")) else {
        return false;
    };
    if !url.username().is_empty()
        || url.password().is_some()
        || !app
            .allowed_hosts
            .iter()
            .any(|host| Some(host.as_str()) == url.host_str())
    {
        return false;
    }
    match request.headers().get(header::ORIGIN) {
        None => true,
        Some(value) => value
            .to_str()
            .is_ok_and(|origin| app.allowed_origins.iter().any(|allowed| allowed == origin)),
    }
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, "1")],
    )
        .into_response()
}

fn auth_response(error: auth::Error, challenge: &HeaderValue) -> Response {
    match error {
        auth::Error::InvalidToken => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, challenge.clone())],
        )
            .into_response(),
        _ => unavailable(),
    }
}

fn policy_response(error: outbound::Error) -> Response {
    match error {
        outbound::Error::Authority(GrantError::Denied) => StatusCode::FORBIDDEN.into_response(),
        _ => unavailable(),
    }
}

struct CurrentAuthority {
    grant: Authorization,
    policy: Policy,
    store: Store,
}

async fn authorize_current(
    app: &App,
    identity: Arc<VerifiedIdentity>,
) -> Result<CurrentAuthority, Response> {
    let store_file = app.grant_store.clone();
    let messaging = app.messaging.is_some();
    let subscriber = tracing::dispatcher::get_default(Clone::clone);
    tokio::task::spawn_blocking(move || {
        tracing::dispatcher::with_default(&subscriber, || {
            let store = Store::open(&store_file)?;
            let grant = store.authorize(&identity)?;
            let policy = if messaging {
                store.outbound_policy(&grant.grant_id)?
            } else {
                Policy::default()
            };
            Ok::<_, outbound::Error>(CurrentAuthority {
                grant,
                policy,
                store,
            })
        })
    })
    .await
    .map_err(|_| unavailable())?
    .map_err(policy_response)
}

async fn protected_resource(State(app): State<Arc<App>>, request: Request) -> Response {
    if !permitted_request(&app, &request) {
        return StatusCode::FORBIDDEN.into_response();
    }
    Json(json!({"resource": app.resource, "authorization_servers": [app.issuer], "scopes_supported": app.scopes})).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rpc {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default = "empty_object")]
    params: Value,
}
fn empty_object() -> Value {
    json!({})
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameters {
    #[serde(default, rename = "_meta")]
    _metadata: Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Call {
    name: String,
    #[serde(default = "empty_object", rename = "arguments")]
    arguments: Value,
    #[serde(default, rename = "_meta")]
    _metadata: Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientInfo {
    #[serde(rename = "name")]
    _name: String,
    #[serde(rename = "version")]
    _version: String,
    #[serde(rename = "title")]
    _title: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Initialize {
    #[serde(rename = "protocolVersion")]
    protocol_version: String,
    #[serde(rename = "capabilities")]
    _capabilities: Map<String, Value>,
    #[serde(rename = "clientInfo")]
    _client_info: ClientInfo,
    #[serde(default, rename = "_meta")]
    _metadata: Map<String, Value>,
}

fn reserved_identity(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "subject"
                    | "issuer"
                    | "hosted_client"
                    | "resource"
                    | "verified"
                    | "active"
                    | "iss"
                    | "sub"
                    | "aud"
                    | "client_id"
            ) || reserved_identity(value)
        }),
        Value::Array(values) => values.iter().any(reserved_identity),
        _ => false,
    }
}

fn identity_spoof(body: &Value) -> bool {
    body.as_object().is_some_and(|fields| {
        fields.keys().any(|key| {
            matches!(
                key.as_str(),
                "subject"
                    | "issuer"
                    | "hosted_client"
                    | "resource"
                    | "verified"
                    | "active"
                    | "iss"
                    | "sub"
                    | "aud"
                    | "client_id"
            )
        })
    }) || if body["method"] == "tools/call"
        && crate::broker::NAMES
            .iter()
            .any(|name| body["params"]["name"] == *name)
    {
        let mut arguments = body["params"]["arguments"].clone();
        if let Some(fields) = arguments.as_object_mut() {
            fields.remove("files");
        }
        reserved_identity(&arguments)
    } else {
        reserved_identity(&body["params"]["arguments"])
    } || reserved_identity(&body["params"]["_meta"])
}

fn rpc_result(id: &Value, result: Value) -> Response {
    Json(json!({"jsonrpc":"2.0", "id": id, "result": result})).into_response()
}
fn rpc_error(id: &Value, code: i64, message: &str) -> Response {
    rpc_error_with_data(id, code, message, None)
}
fn rpc_error_with_data(id: &Value, code: i64, message: &str, data: Option<Value>) -> Response {
    let mut error = json!({"code":code,"message":message});
    if let Some(data) = data {
        error["data"] = data;
    }
    Json(json!({"jsonrpc":"2.0", "id": id, "error":error})).into_response()
}
fn tool_unavailable(id: &Value, pre_effect: bool) -> Response {
    rpc_error_with_data(
        id,
        -32004,
        "Tool temporarily unavailable",
        pre_effect.then(|| json!({"submitted":false,"retry":"same request_id"})),
    )
}

#[derive(Clone)]
struct PendingReply {
    operation: &'static str,
    id: Value,
    request_id: String,
}

struct DispatchContext {
    id: Value,
    operation: Option<&'static str>,
}
fn invalid_dispatch(operation: &'static str, id: &Value, message: &str) -> Response {
    diagnostic::emit(operation, "invalid", "arguments");
    rpc_error(id, -32602, message)
}

fn tool_result(data: Value) -> Value {
    json!({"content":[{"type":"text","text":data.to_string()}],
        "structuredContent":data,"isError":false})
}

fn pending_response(pending: &PendingReply) -> Response {
    rpc_result(
        &pending.id,
        tool_result(json!({"state":"pending",
        "request_id":pending.request_id,"retry":"use the same request_id"})),
    )
}

fn list_enabled(app: &App, permission: &Option<outbound::Permission>) -> bool {
    permission
        .as_ref()
        .is_some_and(|permission| app.verifier.requires_scope(&permission.required_scope))
}

fn permission_enabled(app: &App, permission: &Option<outbound::Permission>) -> bool {
    list_enabled(app, permission)
        && permission
            .as_ref()
            .is_some_and(|permission| !permission.targets.is_empty())
}

fn tools(app: &App, policy: &Policy, grant: &Authorization) -> Value {
    let mut tools = vec![
        json!({"name":"xmsg_identity","description":"Read the authenticated gateway identity.",
        "inputSchema":{"type":"object","properties":{},"additionalProperties":false},
        "annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false},
        "securitySchemes":[{"type":"oauth2","scopes":app.scopes}]}),
    ];
    if app.messaging.is_some() {
        for (name, description, properties, required) in [
            (
                "xmsg_inbox",
                "Read bounded previews from the authenticated registered mailbox.",
                json!({"after":{"type":"string","maxLength":256},"limit":{"type":"integer","minimum":1,"maximum":reads::INBOX_MAX,"default":reads::INBOX_DEFAULT}}),
                json!([]),
            ),
            (
                "xmsg_read_message",
                "Read a bounded Unicode character range from an owned message.",
                json!({"message_id":{"type":"string","minLength":1,"maxLength":4096},"offset":{"type":"integer","minimum":0,"default":0},
                    "limit":{"type":"integer","minimum":1,"maximum":reads::READ_MAX,"default":reads::READ_MAX}}),
                json!(["message_id"]),
            ),
        ] {
            tools.push(json!({"name":name,"description":description,
                "inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},
                "annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false},
                "securitySchemes":[{"type":"oauth2","scopes":app.scopes}]}));
        }
        if list_enabled(app, &policy.send) {
            tools.push(json!({"name":"xmsg_list","description":"List authorized send-policy targets with live status.",
                "inputSchema":{"type":"object","properties":{"node":{"type":"string","minLength":1},
                    "kind":{"type":"string","enum":["service","instance","subagent"]},
                    "status":{"type":"string","enum":["live","inactive"]},
                    "within":{"type":"integer","minimum":1,"maximum":604800}},
                    "required":[],"additionalProperties":false},
                "annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false},
                "securitySchemes":[{"type":"oauth2","scopes":app.scopes}]}));
        }
        for (name, permission, target) in [
            ("xmsg_send", &policy.send, "to"),
            ("xmsg_reply", &policy.reply, "message_id"),
        ] {
            if !permission_enabled(app, permission) {
                continue;
            }
            tools.push(json!({"name":name,"description":"Submit authorized external-data text with a durable request_id; retry only with that same request_id.",
                "inputSchema":{"type":"object","properties":{"request_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},
                    target:{"type":"string"},"text":{"type":"string"}},
                    "required":["request_id",target,"text"],"additionalProperties":false},
                "annotations":{"readOnlyHint":false,"destructiveHint":false,"openWorldHint":true,"idempotentHint":true},
                "securitySchemes":[{"type":"oauth2","scopes":app.scopes}]}));
        }
    }
    if app.events.is_some() {
        for (name,argument,description,read_only) in [
            ("xmsg_ack","message_id","Record durable acceptance of responsibility for an owned message. This is not completion; use a durable drainer or deduplication with idempotent effects.",false),
            ("xmsg_message_status","request_id","Read owned send/reply outcomes without retrying or submitting.",true),
        ] {
            tools.push(json!({"name":name,"description":description,"inputSchema":{"type":"object","properties":{argument:{"type":"string","minLength":1,"maxLength":4096}},"required":[argument],"additionalProperties":false},"annotations":{"readOnlyHint":read_only,"destructiveHint":false,"openWorldHint":false,"idempotentHint":true},"securitySchemes":[{"type":"oauth2","scopes":app.scopes}]}));
        }
    }
    if broker_permitted(app, policy, grant) {
        for mut tool in crate::broker::catalog() {
            tool["securitySchemes"] = json!([{"type":"oauth2","scopes":app.scopes}]);
            tools.push(tool);
        }
    }
    json!({"tools":tools})
}

fn broker_permitted(app: &App, policy: &Policy, grant: &Authorization) -> bool {
    match (&app.broker, &app.events, &app.messaging) {
        (Some(config), Some(events), Some(_)) => {
            config.permitted(policy, grant, &events.selected_grant, &app.verifier)
        }
        _ => false,
    }
}

async fn lookup_broker(
    app: Arc<App>,
    identity: Arc<VerifiedIdentity>,
    bus: String,
    mailbox: String,
    request_id: String,
) -> Result<Option<Value>, outbound::Error> {
    tokio::task::spawn_blocking(move || {
        let mut store = Store::open_for_dispatch(&app.grant_store)?;
        let events = app.events.as_ref().ok_or(outbound::Error::Configuration)?;
        let config = app.broker.as_ref().ok_or(outbound::Error::Configuration)?;
        let messaging = app
            .messaging
            .as_ref()
            .ok_or(outbound::Error::Configuration)?;
        let authority = store.authorize(&identity)?;
        let policy = store.outbound_policy(&authority.grant_id)?;
        if !config.permitted(&policy, &authority, &events.selected_grant, &app.verifier) {
            return Err(outbound::Error::Denied);
        }
        store.retire_outbound(identity.service(), &messaging.limits)?;
        crate::broker::lookup(
            &store,
            &identity,
            &bus,
            &mailbox,
            &events.selected_grant,
            config,
            &request_id,
            &messaging.limits,
            &app.verifier,
        )
    })
    .await
    .map_err(|_| outbound::Error::Configuration)?
}

#[allow(clippy::too_many_arguments)]
async fn broker_call(
    app: Arc<App>,
    token: String,
    id: Value,
    request: outbound::SendArguments,
    mut store: Store,
    progress: Arc<OnceLock<PendingReply>>,
    deadline: tokio::time::Instant,
    operation: &'static str,
) -> Response {
    let pending = PendingReply {
        operation,
        id: id.clone(),
        request_id: request.request_id.as_str().to_owned(),
    };
    let _ = progress.set(pending.clone());
    let Some(messaging) = &app.messaging else {
        diagnostic::emit(operation, "pre_effect_unavailable", "messaging_unavailable");
        return tool_unavailable(&id, true);
    };
    let snapshot = match messaging.session.snapshot() {
        Ok(s) => s,
        Err(error) => {
            diagnostic::emit(
                operation,
                "pre_effect_unavailable",
                diagnostic::session(&error),
            );
            return tool_unavailable(&id, true);
        }
    };
    let (send, receive) = tokio::sync::oneshot::channel();
    let task_app = app.clone();
    let subscriber = tracing::dispatcher::get_default(Clone::clone);
    let broker_work = async move {
        let mut confirmed_submission = false;
        let result=async {
            let messaging=task_app.messaging.as_ref().ok_or(outbound::Error::Configuration)?;
            let events=task_app.events.as_ref().ok_or(outbound::Error::Configuration)?;
            let request_id=request.request_id.as_str().to_owned();
            let result=outbound::dispatch_selected(&mut store,&snapshot.endpoint,&task_app.verifier,&token,&snapshot.bus,&outbound::Request::Send(request),&messaging.limits,&events.selected_grant).await?;
            let (state,receipt)=match result {
                Outcome::Confirmed(receipt)=>("pending",Some(receipt)),
                Outcome::Pending=>("pending",None),
                Outcome::Unknown=>("unknown",None),
                Outcome::ExpiredUnknown => return Ok(json!({"state":"unknown","request_id":request_id,"reconciliation_required":true})),
                Outcome::Expired => return Ok(recovery::expired_result(&request_id)),
            };
            if receipt.is_some() {
                confirmed_submission = true;
                tracing::debug!(target:"gateway_broker_submission_confirmed", "submission receipt available; recovering application result");
                let identity=Arc::new(task_app.verifier.verify(&token).await?);
                loop {
                    let value=lookup_broker(task_app.clone(),identity.clone(),snapshot.bus.clone(),snapshot.endpoint.sender().to_owned(),request_id.clone()).await?;
                    if value.is_some() {
                        let current=Arc::new(task_app.verifier.verify(&token).await?);
                        if let Some(value)=lookup_broker(task_app.clone(),current,snapshot.bus.clone(),snapshot.endpoint.sender().to_owned(),request_id.clone()).await? {
                            return Ok(json!({"request_id":request_id,"submission":"confirmed","receipt":receipt,"broker":value}));
                        }
                    }
                    if tokio::time::Instant::now()>=deadline {break;}
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
            Ok::<Value,outbound::Error>(json!({"state":state,"request_id":request_id,"receipt":receipt,"retry":"use the same request_id and identical arguments; status is read-only"}))
        }.await;
        let _ = send.send(result.map_err(|error| (confirmed_submission, error)));
    };
    use tracing::instrument::WithSubscriber;
    let broker_work = broker_work.with_subscriber(subscriber);
    {
        let mut tasks = app.dispatch_tasks.lock().await;
        while tasks.try_join_next().is_some() {}
        tasks.spawn(broker_work);
    }
    let result = tokio::time::timeout_at(deadline, receive).await;
    match &result {
        Ok(Ok(Ok(value))) => match value.get("state").and_then(Value::as_str) {
            Some("pending") => diagnostic::emit(operation, "pending", "pending"),
            Some("unknown" | "expired") => diagnostic::emit(operation, "unknown", "unknown"),
            _ => {}
        },
        Ok(Ok(Err((confirmed, error)))) => {
            let (class, kind) = diagnostic::broker(error, *confirmed);
            diagnostic::emit(operation, class, kind);
        }
        Ok(Err(_)) => diagnostic::emit(operation, "pending", "worker_result_unavailable"),
        Err(_) => diagnostic::emit(operation, "pending", "request_deadline"),
    }
    match result {
        Ok(Ok(Ok(value))) => rpc_result(&id, tool_result(value)),
        Ok(Ok(Err((
            _,
            outbound::Error::Denied | outbound::Error::Authority(GrantError::Denied),
        )))) => StatusCode::FORBIDDEN.into_response(),
        Ok(Ok(Err((_, outbound::Error::Authentication(auth::Error::InvalidToken))))) => {
            auth_response(auth::Error::InvalidToken, &app.challenge)
        }
        Ok(Ok(Err((_, outbound::Error::Conflict)))) => {
            rpc_error(&id, -32009, "request_id payload conflict")
        }
        Ok(Ok(Err((_, outbound::Error::Oversized)))) => {
            rpc_error(&id, -32602, "complete outbound text exceeds bound")
        }
        Ok(Ok(Err((true, _)))) => pending_response(&pending),
        Ok(Ok(Err((false, _)))) => tool_unavailable(&id, true),
        _ => pending_response(&pending),
    }
}

async fn messaging_call(
    app: Arc<App>,
    token: String,
    id: Value,
    request: outbound::Request,
    policy: Policy,
    mut store: Store,
    progress: Arc<OnceLock<PendingReply>>,
) -> Response {
    let (operation, request_id, permission) = match &request {
        outbound::Request::Send(args) => (
            "xmsg_send",
            args.request_id.as_str().to_owned(),
            &policy.send,
        ),
        outbound::Request::Reply(args) => (
            "xmsg_reply",
            args.request_id.as_str().to_owned(),
            &policy.reply,
        ),
    };
    if !permission_enabled(&app, permission) {
        diagnostic::emit(operation, "denied", "policy");
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(messaging) = app.messaging.as_ref() else {
        diagnostic::emit(operation, "pre_effect_unavailable", "messaging_unavailable");
        return tool_unavailable(&id, true);
    };
    let snapshot = match messaging.session.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            diagnostic::emit(
                operation,
                "pre_effect_unavailable",
                diagnostic::session(&error),
            );
            return tool_unavailable(&id, true);
        }
    };
    tracing::info!(target: "gateway_dispatch", operation, "dispatch");
    let (send, receive) = tokio::sync::oneshot::channel();
    let task_app = app.clone();
    let subscriber = tracing::dispatcher::get_default(Clone::clone);
    let work = async move {
        use tracing::instrument::WithSubscriber;
        let result = async {
            let messaging = task_app
                .messaging
                .as_ref()
                .ok_or(outbound::Error::Configuration)?;
            outbound::dispatch(
                &mut store,
                &snapshot.endpoint,
                &task_app.verifier,
                &token,
                &snapshot.bus,
                &request,
                &messaging.limits,
            )
            .await
        }
        .with_subscriber(subscriber)
        .await;
        let _ = send.send(result);
    };
    {
        let mut tasks = app.dispatch_tasks.lock().await;
        while tasks.try_join_next().is_some() {}
        tasks.spawn(work);
    }
    let pending = PendingReply {
        operation,
        id: id.clone(),
        request_id: request_id.clone(),
    };
    let _ = progress.set(pending.clone());
    let result = match receive.await {
        Ok(result) => result,
        Err(_) => {
            diagnostic::emit(operation, "pending", "worker_result_unavailable");
            return pending_response(&pending);
        }
    };
    match &result {
        Err(error) => {
            let (class, kind) = diagnostic::outbound(error);
            diagnostic::emit(operation, class, kind);
        }
        Ok(Outcome::Pending) => diagnostic::emit(operation, "pending", "pending"),
        Ok(Outcome::Unknown | Outcome::ExpiredUnknown) => {
            diagnostic::emit(operation, "unknown", "unknown")
        }
        Ok(Outcome::Expired) => diagnostic::emit(operation, "unknown", "expired"),
        Ok(Outcome::Confirmed(_)) => {}
    }
    match result {
        Ok(Outcome::Pending) => pending_response(&pending),
        Ok(Outcome::Unknown) => rpc_result(
            &id,
            tool_result(json!({"state":"unknown",
            "request_id":request_id,"reconciliation_required":false,
            "retry":"retry with the same request_id and identical arguments before dedup expiry"})),
        ),
        Ok(Outcome::ExpiredUnknown) => rpc_result(
            &id,
            tool_result(json!({"state":"unknown",
            "request_id":request_id,"reconciliation_required":true})),
        ),
        Ok(Outcome::Expired) => rpc_result(&id, tool_result(recovery::expired_result(&request_id))),
        Ok(Outcome::Confirmed(receipt)) => rpc_result(
            &id,
            tool_result(json!({"state":"confirmed","request_id":request_id,"receipt":receipt})),
        ),
        Err(outbound::Error::Denied | outbound::Error::Authority(GrantError::Denied)) => {
            StatusCode::FORBIDDEN.into_response()
        }
        Err(outbound::Error::Authentication(auth::Error::InvalidToken)) => {
            auth_response(auth::Error::InvalidToken, &app.challenge)
        }
        Err(outbound::Error::Conflict) => rpc_error(&id, -32009, "request_id payload conflict"),
        Err(outbound::Error::Oversized) => {
            rpc_error(&id, -32602, "complete outbound text exceeds bound")
        }
        Err(_) => tool_unavailable(&id, true),
    }
}

async fn mcp(State(app): State<Arc<App>>, request: Request) -> Response {
    let progress = Arc::new(OnceLock::new());
    // Authorized dispatch context is not proof that an effect committed.
    let dispatched = Arc::new(OnceLock::new());
    tokio::time::timeout(
        Duration::from_millis(app.request_timeout_ms),
        mcp_request(app, request, progress.clone(), dispatched.clone()),
    )
    .await
    .unwrap_or_else(|_| match progress.get() {
        Some(pending) => {
            diagnostic::emit(pending.operation, "pending", "request_deadline");
            pending_response(pending)
        }
        None => match dispatched.get() {
            Some(context) => {
                if let Some(operation) = context.operation {
                    diagnostic::emit(
                        operation,
                        if operation == "xmsg_ack" {
                            "unknown"
                        } else {
                            "pre_effect_unavailable"
                        },
                        "request_deadline",
                    );
                }
                tool_unavailable(&context.id, false)
            }
            None => unavailable(),
        },
    })
}

async fn mcp_request(
    app: Arc<App>,
    request: Request,
    progress: Arc<OnceLock<PendingReply>>,
    dispatched: Arc<OnceLock<DispatchContext>>,
) -> Response {
    let broker_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    if !permitted_request(&app, &request) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let token = if request
        .headers()
        .get_all(header::AUTHORIZATION)
        .iter()
        .count()
        == 1
    {
        request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
            .map(|(_, token)| token.to_owned())
            .unwrap_or_default()
    } else {
        String::new()
    };
    if token.is_empty() {
        return auth_response(auth::Error::InvalidToken, &app.challenge);
    }
    let method = request.method().clone();
    let headers = request.headers().clone();
    if method == Method::POST
        && headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > app.max_request_body_bytes as u64)
    {
        return TransportRefusal::BodyTooLarge {
            limit_bytes: app.max_request_body_bytes,
        }
        .into_response();
    }
    let raw = if method == Method::POST {
        match to_bytes(request.into_body(), app.max_request_body_bytes).await {
            Ok(raw) => raw,
            Err(error) => {
                let refusal = if error
                    .source()
                    .is_some_and(|source| source.is::<http_body_util::LengthLimitError>())
                {
                    TransportRefusal::BodyTooLarge {
                        limit_bytes: app.max_request_body_bytes,
                    }
                } else {
                    TransportRefusal::BodyReadFailed
                };
                return refusal.into_response();
            }
        }
    } else {
        axum::body::Bytes::new()
    };
    let broker_candidate = serde_json::from_slice::<Value>(&raw)
        .ok()
        .is_some_and(|body| {
            body["method"] == "tools/call"
                && crate::broker::NAMES
                    .iter()
                    .any(|name| body["params"]["name"] == *name)
        });
    let verification = async { app.verifier.verify(&token).await };
    let verified = if broker_candidate {
        match tokio::time::timeout_at(broker_deadline, verification).await {
            Ok(value) => value,
            Err(_) => return unavailable(),
        }
    } else {
        verification.await
    };
    let identity = match verified {
        Ok(identity) => Arc::new(identity),
        Err(error) => return auth_response(error, &app.challenge),
    };
    let authorization = authorize_current(&app, identity.clone());
    let authorization = if broker_candidate {
        match tokio::time::timeout_at(broker_deadline, authorization).await {
            Ok(value) => value,
            Err(_) => return unavailable(),
        }
    } else {
        authorization.await
    };
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => now.as_secs(),
        Err(_) => return unavailable(),
    };
    if now >= identity.expires_at() {
        return auth_response(auth::Error::InvalidToken, &app.challenge);
    }
    let CurrentAuthority {
        grant,
        policy,
        store,
    } = match authorization {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    if method != Method::POST {
        return (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "POST")]).into_response();
    }
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        != Some("application/json")
    {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    if headers
        .get("mcp-protocol-version")
        .is_some_and(|value| !value.to_str().is_ok_and(|value| VERSIONS.contains(&value)))
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let body: Value = match serde_json::from_slice(&raw) {
        Ok(body) => body,
        Err(_) => return rpc_error(&Value::Null, -32700, "Parse error"),
    };
    if identity_spoof(&body) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let rpc: Rpc = match serde_json::from_value(body) {
        Ok(rpc) => rpc,
        Err(_) => return rpc_error(&Value::Null, -32600, "Invalid Request"),
    };
    if rpc.jsonrpc != "2.0"
        || !rpc.params.is_object()
        || rpc
            .id
            .as_ref()
            .is_some_and(|id| !(id.is_string() || id.as_i64().is_some() || id.as_u64().is_some()))
    {
        return rpc_error(&Value::Null, -32600, "Invalid Request");
    }
    let id = rpc.id.unwrap_or(Value::Null);
    if rpc.params.get("_meta").is_some_and(|meta| {
        !meta.is_object()
            || meta.get("progressToken").is_some_and(|token| {
                !(token.is_string() || token.as_i64().is_some() || token.as_u64().is_some())
            })
    }) {
        return rpc_error(&id, -32602, "Invalid params");
    }
    if rpc
        .params
        .get("arguments")
        .is_some_and(|arguments| !arguments.is_object())
    {
        return rpc_error(&id, -32602, "Invalid params");
    }
    if id.is_null() && rpc.method != "notifications/initialized" {
        return rpc_error(&id, -32600, "Invalid Request");
    }
    let result = match rpc.method.as_str() {
        "initialize" => match serde_json::from_value::<Initialize>(rpc.params) {
            Ok(init) => {
                json!({"protocolVersion": if VERSIONS.contains(&init.protocol_version.as_str()) { init.protocol_version.as_str() } else { VERSIONS[2] },
                "capabilities": if app.events.is_some() { json!({"tools":{},"events":{}}) } else { json!({"tools":{}}) },"serverInfo":{"name":"xmsg-mcp-gateway","version":env!("CARGO_PKG_VERSION")}})
            }
            Err(_) => return rpc_error(&id, -32602, "Invalid params"),
        },
        "notifications/initialized" | "ping" | "tools/list" => {
            if serde_json::from_value::<Parameters>(rpc.params).is_err() {
                return rpc_error(&id, -32602, "Invalid params");
            }
            match rpc.method.as_str() {
                "notifications/initialized" => return StatusCode::ACCEPTED.into_response(),
                "ping" => json!({}),
                _ => tools(&app, &policy, &grant),
            }
        }
        "tools/call" => {
            let call: Call = match serde_json::from_value(rpc.params) {
                Ok(call) => call,
                Err(_) => return rpc_error(&id, -32602, "Invalid params"),
            };
            let operation = diagnostic::operation(&call.name);
            let _ = dispatched.set(DispatchContext {
                id: id.clone(),
                operation: Some(operation),
            });
            if crate::broker::NAMES.contains(&call.name.as_str()) {
                if !broker_permitted(&app, &policy, &grant) {
                    diagnostic::emit(operation, "denied", "policy");
                    return StatusCode::FORBIDDEN.into_response();
                }
                let destination = &app.broker.as_ref().unwrap().destination;
                let request = match crate::broker::parse(&call.name, call.arguments, destination) {
                    Ok(request) => request,
                    Err(_) => return invalid_dispatch(operation, &id, "Invalid gist arguments"),
                };
                return broker_call(
                    app,
                    token,
                    id,
                    request,
                    store,
                    progress,
                    broker_deadline,
                    operation,
                )
                .await;
            }
            if matches!(call.name.as_str(), "xmsg_ack" | "xmsg_message_status") {
                let Some(events) = &app.events else {
                    diagnostic::emit(operation, "pre_effect_unavailable", "tool_unavailable");
                    return rpc_error(&id, -32004, "Tool not yet available");
                };
                if grant.grant_id != events.selected_grant {
                    diagnostic::emit(operation, "denied", "policy");
                    return StatusCode::FORBIDDEN.into_response();
                }
                let Some(messaging) = &app.messaging else {
                    diagnostic::emit(operation, "pre_effect_unavailable", "messaging_unavailable");
                    return tool_unavailable(&id, false);
                };
                let (bus, mailbox) = messaging.session.custody_scope();
                let (bus, mailbox) = (bus.to_owned(), mailbox.to_owned());
                let request = if call.name == "xmsg_ack" {
                    serde_json::from_value::<recovery::AckArguments>(call.arguments)
                        .map(recovery::Request::Ack)
                } else {
                    serde_json::from_value::<recovery::StatusArguments>(call.arguments)
                        .map(recovery::Request::Status)
                };
                let request = match request {
                    Ok(request) => request,
                    Err(_) => return invalid_dispatch(operation, &id, "Invalid params"),
                };
                let broker_request_id = match &request {
                    recovery::Request::Status(args) => Some(args.request_id.clone()),
                    _ => None,
                };
                let broker_configuration = app.broker.clone();
                let broker_verifier = app.verifier.clone();
                let retirement_limits = messaging.limits.clone();
                let status_store_file = app.grant_store.clone();
                let key = events.key.clone();
                let selected_grant = events.selected_grant.clone();
                let subscriber = tracing::dispatcher::get_default(Clone::clone);
                let result = tokio::task::spawn_blocking(move || {
                    tracing::dispatcher::with_default(&subscriber, || {
                    let mut recovery_store = Store::open_for_dispatch(&status_store_file).map_err(recovery::Error::Authority)?;
                    let authority = recovery_store.authorize(&identity).map_err(recovery::Error::Authority)?;
                    if authority.grant_id != selected_grant {
                        return Err(recovery::Error::Authority(GrantError::Denied));
                    }
                    if broker_request_id.is_some() {
                        recovery_store.retire_outbound(identity.service(), &retirement_limits)?;
                    }
                    let mut result = recovery::dispatch(
                        recovery_store,
                        &identity,
                        &bus,
                        &mailbox,
                        &selected_grant,
                        &key,
                        request,
                        &retirement_limits,
                    )?;
                    tracing::debug!(target: "gateway_broker_status_result", "submission status read; validate application result next");
                    let broker_result = if let (Some(config), Some(id)) =
                        (&broker_configuration, &broker_request_id)
                    {
                        Some(crate::broker::lookup(
                            &store,
                            &identity,
                            &bus,
                            &mailbox,
                            &selected_grant,
                            config,
                            id,
                            &retirement_limits,
                            &broker_verifier,
                        ))
                    } else {
                        None
                    };

                    match broker_result {
                        Some(Ok(Some(value))) => result["broker"] = value,
                        Some(Err(outbound::Error::Denied)) => {
                            return Err(recovery::Error::Authority(GrantError::Denied))
                        }
                        Some(Err(error)) => return Err(recovery::Error::Broker(error)),
                        _ => {}
                    }
                    Ok::<_, recovery::Error>(result)
                    })
                })
                .await;
                match &result {
                    Ok(Err(error)) => {
                        let (class, kind) = diagnostic::recovery(error);
                        diagnostic::emit(
                            operation,
                            if operation == "xmsg_ack" && class == "pre_effect_unavailable" {
                                "unknown"
                            } else {
                                class
                            },
                            kind,
                        );
                    }
                    Err(_) => diagnostic::emit(
                        operation,
                        if operation == "xmsg_ack" {
                            "unknown"
                        } else {
                            "pre_effect_unavailable"
                        },
                        "worker_join",
                    ),
                    Ok(Ok(_)) => {}
                }
                return match result {
                    Ok(Ok(data)) => rpc_result(&id, tool_result(data)),
                    Ok(Err(recovery::Error::Arguments)) => rpc_error(&id, -32602, "Invalid params"),
                    Ok(Err(recovery::Error::Authority(GrantError::Denied))) => {
                        StatusCode::FORBIDDEN.into_response()
                    }
                    Ok(Err(recovery::Error::Broker(outbound::Error::Authentication(
                        auth::Error::InvalidToken,
                    )))) => auth_response(auth::Error::InvalidToken, &app.challenge),
                    _ => tool_unavailable(&id, false),
                };
            }
            if matches!(call.name.as_str(), "xmsg_inbox" | "xmsg_read_message")
                && app.messaging.is_some()
            {
                let request = match call.name.as_str() {
                    "xmsg_inbox" => serde_json::from_value::<reads::InboxArguments>(call.arguments)
                        .map(reads::Request::Inbox),
                    _ => serde_json::from_value::<reads::ReadArguments>(call.arguments)
                        .map(reads::Request::Read),
                };
                let request = match request {
                    Ok(request) => request,
                    Err(_) => return invalid_dispatch(operation, &id, "Invalid params"),
                };
                let Some(messaging) = &app.messaging else {
                    diagnostic::emit(operation, "pre_effect_unavailable", "messaging_unavailable");
                    return tool_unavailable(&id, false);
                };
                let (bus, mailbox) = messaging.session.custody_scope();
                let (bus, mailbox) = (bus.to_owned(), mailbox.to_owned());
                let result = tokio::task::spawn_blocking(move || {
                    reads::dispatch(store, &identity, &bus, &mailbox, request)
                })
                .await;
                match &result {
                    Ok(Err(error)) => {
                        let (class, kind) = diagnostic::reads(error);
                        diagnostic::emit(operation, class, kind);
                    }
                    Err(_) => diagnostic::emit(operation, "pre_effect_unavailable", "worker_join"),
                    Ok(Ok(_)) => {}
                }
                return match result {
                    Ok(Ok(data)) => rpc_result(&id, tool_result(data)),
                    Ok(Err(reads::Error::Arguments)) => {
                        rpc_error(&id, -32602, "Invalid params or unavailable cursor")
                    }
                    Ok(Err(reads::Error::Authority(GrantError::Denied))) => {
                        StatusCode::FORBIDDEN.into_response()
                    }
                    _ => tool_unavailable(&id, false),
                };
            }
            if call.name == "xmsg_list" && app.messaging.is_some() {
                if !list_enabled(&app, &policy.send) {
                    diagnostic::emit(operation, "denied", "policy");
                    return StatusCode::FORBIDDEN.into_response();
                }
                let arguments =
                    match serde_json::from_value::<outbound::ListArguments>(call.arguments) {
                        Ok(arguments) if arguments.validate().is_ok() => arguments,
                        _ => return invalid_dispatch(operation, &id, "Invalid params"),
                    };
                let Some(messaging) = &app.messaging else {
                    diagnostic::emit(operation, "pre_effect_unavailable", "messaging_unavailable");
                    return tool_unavailable(&id, false);
                };
                let snapshot = match messaging.session.snapshot() {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        diagnostic::emit(
                            operation,
                            "pre_effect_unavailable",
                            diagnostic::session(&error),
                        );
                        return tool_unavailable(&id, false);
                    }
                };
                let mut list_store = store;
                tracing::info!(target: "gateway_dispatch", operation = "xmsg_list", "dispatch");
                let result = outbound::list(
                    &mut list_store,
                    &snapshot.endpoint,
                    &app.verifier,
                    &token,
                    &arguments,
                    &messaging.limits,
                )
                .await;
                if let Err(error) = &result {
                    let (class, kind) = diagnostic::outbound(error);
                    diagnostic::emit(operation, class, kind);
                }
                return match result {
                    Ok(listed) => match serde_json::to_value(listed) {
                        Ok(data) => rpc_result(&id, tool_result(data)),
                        Err(_) => {
                            diagnostic::emit(operation, "pre_effect_unavailable", "encoding");
                            tool_unavailable(&id, false)
                        }
                    },
                    Err(
                        outbound::Error::Denied | outbound::Error::Authority(GrantError::Denied),
                    ) => StatusCode::FORBIDDEN.into_response(),
                    Err(outbound::Error::Authentication(auth::Error::InvalidToken)) => {
                        auth_response(auth::Error::InvalidToken, &app.challenge)
                    }
                    Err(outbound::Error::Configuration) => rpc_error(&id, -32602, "Invalid params"),
                    Err(_) => tool_unavailable(&id, false),
                };
            }
            if matches!(call.name.as_str(), "xmsg_send" | "xmsg_reply") && app.messaging.is_some() {
                let request = match call.name.as_str() {
                    "xmsg_send" => {
                        serde_json::from_value::<outbound::SendArguments>(call.arguments)
                            .map(outbound::Request::Send)
                    }
                    _ => serde_json::from_value::<outbound::ReplyArguments>(call.arguments)
                        .map(outbound::Request::Reply),
                };
                let request = match request {
                    Ok(request) => request,
                    Err(_) => return invalid_dispatch(operation, &id, "Invalid params"),
                };
                return messaging_call(app, token, id, request, policy, store, progress).await;
            }
            if call.name != "xmsg_identity" {
                diagnostic::emit(operation, "invalid", "tool_unavailable");
                return rpc_error(&id, -32004, "Tool not yet available");
            }
            if serde_json::from_value::<Empty>(call.arguments).is_err() {
                return invalid_dispatch(operation, &id, "Invalid params");
            }
            tracing::info!(target: "gateway_dispatch", operation = "xmsg_identity", "dispatch");
            let mut data = json!({"service":identity.service(),"subject":identity.subject(),"issuer":identity.issuer(),
                "resource":identity.resource(),"hosted_client":identity.hosted_client(),"grant_revision":grant.revision});
            if let Some(messaging) = &app.messaging {
                data["messaging_status"] = messaging.session.status();
                if let Some(events) = &app.events {
                    let (bus, mailbox) = messaging.session.custody_scope();
                    match events.health(&identity, bus, mailbox) {
                        Ok(summary) => data["events_status"] = summary,
                        Err(error) => {
                            let (class, kind) = diagnostic::identity(&error);
                            diagnostic::emit(operation, class, kind);
                            return if matches!(error, events::Error::Authority(GrantError::Denied))
                            {
                                StatusCode::FORBIDDEN.into_response()
                            } else {
                                tool_unavailable(&id, false)
                            };
                        }
                    }
                }
            }
            json!({"content":[{"type":"text","text":data.to_string()}],"structuredContent":data,"isError":false})
        }
        "events/list" | "events/subscribe" | "events/unsubscribe" => {
            let _ = dispatched.set(DispatchContext {
                id: id.clone(),
                operation: None,
            });
            let Some(events) = &app.events else {
                return rpc_error(&id, -32004, "Events not yet available");
            };
            if grant.grant_id != events.selected_grant {
                return StatusCode::FORBIDDEN.into_response();
            }
            let Some(messaging) = &app.messaging else {
                return tool_unavailable(&id, false);
            };
            let (bus, mailbox) = messaging.session.custody_scope();
            let result = match rpc.method.as_str() {
                "events/list" => {
                    match serde_json::from_value::<EventList>(rpc.params) {
                        Ok(parameters) if parameters.cursor.is_none() => {}
                        _ => return rpc_error(&id, -32602, "Invalid params"),
                    }
                    Ok(events::catalog())
                }
                "events/subscribe" => {
                    let request = match serde_json::from_value::<events::Subscribe>(rpc.params) {
                        Ok(request) => request,
                        Err(_) => return rpc_error(&id, -32602, "Invalid params"),
                    };
                    events
                        .subscribe(&identity, &token, bus, mailbox, request)
                        .await
                }
                _ => {
                    let request = match serde_json::from_value::<events::Unsubscribe>(rpc.params) {
                        Ok(request) => request,
                        Err(_) => return rpc_error(&id, -32602, "Invalid params"),
                    };
                    events
                        .unsubscribe(&identity, &token, bus, mailbox, request)
                        .await
                }
            };
            return match result {
                Ok(value) => rpc_result(&id, value),
                Err(error) => event_error(&id, error),
            };
        }
        _ => return rpc_error(&id, -32601, "Method not found"),
    };
    rpc_result(&id, result)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventList {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default, rename = "_meta")]
    _metadata: Map<String, Value>,
}

fn event_error(id: &Value, error: events::Error) -> Response {
    match error {
        events::Error::Arguments => rpc_error(id, -32602, "Invalid params or unavailable cursor"),
        events::Error::Conflict => rpc_error(
            id,
            -32009,
            "Subscription binding conflict; explicit owner rebind required",
        ),
        events::Error::Callback(crate::webhook::Error::Secret) => {
            rpc_error(id, -32602, "Invalid signing secret")
        }
        events::Error::Callback(crate::webhook::Error::Random) => tool_unavailable(id, false),
        events::Error::Callback(error) => {
            let reason = match error {
                crate::webhook::Error::Timeout => "timeout",
                crate::webhook::Error::Challenge => "challenge_failed",
                crate::webhook::Error::Destination => "invalid_url",
                crate::webhook::Error::Transport => "unreachable",
                _ => "invalid_response",
            };
            Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":-32015,"message":"CallbackEndpointError","data":{"reason":reason}}})).into_response()
        }
        events::Error::Authority(GrantError::Denied) => StatusCode::FORBIDDEN.into_response(),
        events::Error::Credentials(auth::Error::InvalidToken) => {
            StatusCode::UNAUTHORIZED.into_response()
        }
        _ => tool_unavailable(id, false),
    }
}

fn load_configuration(config_file: &Path) -> Result<Configuration, StartupError> {
    let mut file = File::open(config_file).map_err(|_| ConfigurationError)?;
    let metadata = file.metadata().map_err(|_| ConfigurationError)?;
    if !metadata.is_file() || metadata.len() > MAX_OWNER_FILE as u64 {
        return Err(ConfigurationError.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(ConfigurationError.into());
        }
    }
    let mut raw = Vec::new();
    file.by_ref()
        .take(MAX_OWNER_FILE as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| ConfigurationError)?;
    if raw.len() > MAX_OWNER_FILE {
        return Err(ConfigurationError.into());
    }
    let mut config: Configuration = serde_json::from_slice(&raw).map_err(|_| ConfigurationError)?;
    let absolute = std::path::absolute(config_file).map_err(|_| ConfigurationError)?;
    let directory = absolute.parent().ok_or(ConfigurationError)?;
    resolve_profile_path(directory, &mut config.grant_store);
    resolve_profile_path(directory, &mut config.verifier.client_secret_file);
    if let Some(file) = &mut config.verifier.root_certificate_file {
        resolve_profile_path(directory, file);
    }
    if let Some(events) = &mut config.events {
        resolve_profile_path(directory, &mut events.key_file);
    }
    if let Some(messaging) = &mut config.messaging {
        resolve_profile_path(directory, &mut messaging.xmsg.register_socket);
        resolve_profile_path(directory, &mut messaging.xmsg.agent_socket);
        messaging
            .xmsg
            .validate()
            .map_err(|_| StartupError::ConnectionConfiguration)?;
    }
    Ok(config)
}

/// Local owner commands load authority and keys without starting a listener or service session.
pub fn owner_events(config_file: &Path) -> Result<events::Events, StartupError> {
    let config = load_configuration(config_file)?;
    let events = config.events.ok_or(ConfigurationError)?;
    let store = Store::open(&config.grant_store).map_err(|_| ConfigurationError)?;
    let binding = Binding {
        service: config.verifier.service.clone(),
        issuer: config.verifier.issuer.clone(),
        resource: config.verifier.resource.clone(),
        subject: config.verifier.subject.clone(),
        hosted_client: config.verifier.hosted_client.clone(),
    };
    store
        .validate_profile(&binding)
        .map_err(|_| ConfigurationError)?;
    let matches:bool=store.connection.query_row("SELECT EXISTS(SELECT 1 FROM grants WHERE id=?1 AND service=?2 AND issuer=?3 AND resource=?4 AND subject=?5 AND hosted_client=?6)",rusqlite::params![events.grant_id,binding.service,binding.issuer,binding.resource,binding.subject,binding.hosted_client],|row|row.get(0)).map_err(|_|ConfigurationError)?;
    if !matches {
        return Err(ConfigurationError.into());
    }
    let key =
        crate::event_store::EventKey::load(&events.key_file).map_err(|_| ConfigurationError)?;
    store
        .require_events_ready(&key)
        .map_err(|_| ConfigurationError)?;
    let verifier =
        Arc::new(Verifier::from_config(config.verifier).map_err(|_| ConfigurationError)?);
    if !verifier.requires_scope("events:subscribe") {
        return Err(ConfigurationError.into());
    }
    Ok(events::Events::new(
        config.grant_store,
        key,
        verifier,
        events.grant_id,
    ))
}

#[cfg(test)]
#[path = "serving_events_tests.rs"]
mod events_tests;

#[cfg(test)]
mod recovery_configuration_tests {
    use super::*;

    #[test]
    fn result_recovery_defaults_to_one_day_and_accepts_an_explicit_window() {
        let mut value = serde_json::json!({
            "xmsg":{"service":"gateway","expected_node":"bus","daemon_uid":0,
                "register_socket":"/tmp/register.sock","agent_socket":"/tmp/agent.sock",
                "max_frame_bytes":65536,"operation_timeout_ms":1000},
            "manifest":{"reply_ttl_secs":86400,"idempotency_ttl_secs":86400,
                "svc_queue_cap":100,"dedup_lifetime_secs":3600,"max_framed_bytes":65536},
            "submission_timeout_ms":1000,"max_reservations":100,"max_retained_bytes":1048576
        });
        let default: MessagingConfiguration = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(default.result_recovery_secs, 86400);
        value["result_recovery_secs"] = serde_json::json!(172800);
        let explicit: MessagingConfiguration = serde_json::from_value(value).unwrap();
        assert_eq!(explicit.result_recovery_secs, 172800);
    }
}
