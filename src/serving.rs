use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
use crate::session;
use crate::xmsg_config::{DeploymentManifest, ManifestError, XmsgConfig};

const MAX_REQUEST: usize = 65_536;
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
struct MessagingConfiguration {
    xmsg: XmsgConfig,
    manifest: DeploymentManifest,
    submission_timeout_ms: u64,
    max_reservations: i64,
    max_retained_bytes: i64,
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
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    verifier: VerifierConfig,
    #[serde(default, deserialize_with = "present_messaging")]
    messaging: Option<MessagingConfiguration>,
}

fn default_header_read_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, thiserror::Error)]
pub enum TransportRefusal {
    #[error("request headers exceeded their read deadline")]
    HeaderReadTimeout,
}

struct App {
    dispatch_tasks: tokio::sync::Mutex<tokio::task::JoinSet<()>>,
    verifier: Verifier,
    grant_store: PathBuf,
    request_timeout_ms: u64,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    resource: String,
    issuer: String,
    scopes: Vec<String>,
    challenge: HeaderValue,
    messaging: Option<Messaging>,
}

pub struct Serving {
    header_read_timeout: Duration,
    state: Arc<App>,
    router: Router,
    bind: SocketAddr,
}

fn resolve_profile_path(directory: &Path, file: &mut PathBuf) {
    if file.is_relative() {
        *file = directory.join(&*file);
    }
}

impl Serving {
    pub async fn from_owner_file(config_file: &Path) -> Result<Self, StartupError> {
        let mut file = File::open(config_file).map_err(|_| ConfigurationError)?;
        let metadata = file.metadata().map_err(|_| ConfigurationError)?;
        if !metadata.is_file() || metadata.len() > MAX_REQUEST as u64 {
            return Err(ConfigurationError.into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(ConfigurationError.into());
            }
        }
        let mut raw = Vec::new();
        file.by_ref()
            .take(MAX_REQUEST as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(|_| ConfigurationError)?;
        if raw.len() > MAX_REQUEST {
            return Err(ConfigurationError.into());
        }
        let mut config: Configuration =
            serde_json::from_slice(&raw).map_err(|_| ConfigurationError)?;
        let absolute = std::path::absolute(config_file).map_err(|_| ConfigurationError)?;
        let directory = absolute.parent().ok_or(ConfigurationError)?;
        resolve_profile_path(directory, &mut config.grant_store);
        resolve_profile_path(directory, &mut config.verifier.client_secret_file);
        if let Some(file) = &mut config.verifier.root_certificate_file {
            resolve_profile_path(directory, file);
        }
        if let Some(messaging) = &mut config.messaging {
            resolve_profile_path(directory, &mut messaging.xmsg.register_socket);
            resolve_profile_path(directory, &mut messaging.xmsg.agent_socket);
            messaging
                .xmsg
                .validate()
                .map_err(|_| StartupError::ConnectionConfiguration)?;
        }
        if !config.bind.ip().is_loopback()
            || config.allowed_hosts.is_empty()
            || config.header_read_timeout_ms == 0
            || config.header_read_timeout_ms > 60_000
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
        let verifier = Verifier::from_config(config.verifier).map_err(|_| ConfigurationError)?;
        let store = Store::open(&config.grant_store).map_err(|_| ConfigurationError)?;
        store
            .validate_profile(&profile)
            .map_err(|_| ConfigurationError)?;
        let messaging = if let Some(messaging) = config.messaging {
            store
                .require_outbound_ready()
                .map_err(StartupError::Store)?;
            let limits = outbound::Limits {
                dedup_lifetime_secs: i64::try_from(messaging.manifest.dedup_lifetime_secs)
                    .map_err(|_| ManifestError::DedupLifetime)?,
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
            let session = session::Session::start(
                messaging.xmsg,
                messaging.manifest,
                registered,
                config.grant_store.clone(),
                store,
            )
            .await?;
            Some(Messaging { session, limits })
        } else {
            None
        };
        let state = Arc::new(App {
            dispatch_tasks: tokio::sync::Mutex::new(tokio::task::JoinSet::new()),
            verifier,
            grant_store: config.grant_store,
            allowed_hosts: config.allowed_hosts,
            allowed_origins: config.allowed_origins,
            request_timeout_ms: config.request_timeout_ms,
            resource,
            issuer,
            scopes,
            challenge,
            messaging,
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
                        Err(error) => break Err(error),
                    };
                    let router = self.router.clone();
                    let deadline = self.header_read_timeout;
                    let mut stopped = stopped.clone();
                    connections.spawn(async move {
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
                                let reason = TransportRefusal::HeaderReadTimeout;
                                tracing::warn!(target: "gateway_transport", reason = ?reason, "transport refused");
                            }
                        }
                    });
                }
            }
        };
        let _ = stopping.send(true);
        while connections.join_next().await.is_some() {}
        {
            let mut tasks = self.state.dispatch_tasks.lock().await;
            while tasks.join_next().await.is_some() {}
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
    }) || reserved_identity(&body["params"]["arguments"])
        || reserved_identity(&body["params"]["_meta"])
}

fn rpc_result(id: &Value, result: Value) -> Response {
    Json(json!({"jsonrpc":"2.0", "id": id, "result": result})).into_response()
}
fn rpc_error(id: &Value, code: i64, message: &str) -> Response {
    Json(json!({"jsonrpc":"2.0", "id": id, "error":{"code":code,"message":message}}))
        .into_response()
}

#[derive(Clone)]
struct PendingReply {
    id: Value,
    request_id: String,
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

fn permission_enabled(app: &App, permission: &Option<outbound::Permission>) -> bool {
    permission.as_ref().is_some_and(|permission| {
        !permission.targets.is_empty() && app.verifier.requires_scope(&permission.required_scope)
    })
}

fn tools(app: &App, policy: &Policy) -> Value {
    let mut tools = vec![
        json!({"name":"xmsg_identity","description":"Read the authenticated gateway identity.",
        "inputSchema":{"type":"object","properties":{},"additionalProperties":false},
        "annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false},
        "securitySchemes":[{"type":"oauth2","scopes":app.scopes}]}),
    ];
    if app.messaging.is_some() {
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
    json!({"tools":tools})
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
        return StatusCode::FORBIDDEN.into_response();
    }
    let snapshot = match app
        .messaging
        .as_ref()
        .and_then(|messaging| messaging.session.snapshot().ok())
    {
        Some(snapshot) => snapshot,
        None => return unavailable(),
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
        id: id.clone(),
        request_id: request_id.clone(),
    };
    let _ = progress.set(pending.clone());
    let result = match receive.await {
        Ok(result) => result,
        Err(_) => return pending_response(&pending),
    };
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
        Ok(Outcome::Confirmed(receipt)) => rpc_result(
            &id,
            tool_result(json!({"state":"confirmed","request_id":request_id,"receipt":receipt})),
        ),
        Err(outbound::Error::Denied | outbound::Error::Authority(GrantError::Denied)) => {
            StatusCode::FORBIDDEN.into_response()
        }
        Err(outbound::Error::Authentication(error)) => auth_response(error, &app.challenge),
        Err(outbound::Error::Conflict) => rpc_error(&id, -32009, "request_id payload conflict"),
        Err(outbound::Error::Oversized) => {
            rpc_error(&id, -32602, "complete outbound text exceeds bound")
        }
        Err(_) => unavailable(),
    }
}

async fn mcp(State(app): State<Arc<App>>, request: Request) -> Response {
    let progress = Arc::new(OnceLock::new());
    tokio::time::timeout(
        Duration::from_millis(app.request_timeout_ms),
        mcp_request(app, request, progress.clone()),
    )
    .await
    .unwrap_or_else(|_| match progress.get() {
        Some(pending) => pending_response(pending),
        None => unavailable(),
    })
}

async fn mcp_request(
    app: Arc<App>,
    request: Request,
    progress: Arc<OnceLock<PendingReply>>,
) -> Response {
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
    let raw = if method == Method::POST {
        match to_bytes(request.into_body(), MAX_REQUEST).await {
            Ok(raw) => raw,
            Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        }
    } else {
        axum::body::Bytes::new()
    };
    let identity = match app.verifier.verify(&token).await {
        Ok(identity) => Arc::new(identity),
        Err(error) => return auth_response(error, &app.challenge),
    };
    let authorization = authorize_current(&app, identity.clone()).await;
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
                "capabilities":{"tools":{}},"serverInfo":{"name":"xmsg-mcp-gateway","version":env!("CARGO_PKG_VERSION")}})
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
                _ => tools(&app, &policy),
            }
        }
        "tools/call" => {
            let call: Call = match serde_json::from_value(rpc.params) {
                Ok(call) => call,
                Err(_) => return rpc_error(&id, -32602, "Invalid params"),
            };
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
                    Err(_) => return rpc_error(&id, -32602, "Invalid params"),
                };
                return messaging_call(app, token, id, request, policy, store, progress).await;
            }
            if call.name != "xmsg_identity" {
                return rpc_error(&id, -32004, "Tool not yet available");
            }
            if serde_json::from_value::<Empty>(call.arguments).is_err() {
                return rpc_error(&id, -32602, "Invalid params");
            }
            tracing::info!(target: "gateway_dispatch", operation = "xmsg_identity", "dispatch");
            let mut data = json!({"service":identity.service(),"subject":identity.subject(),"issuer":identity.issuer(),
                "resource":identity.resource(),"hosted_client":identity.hosted_client(),"grant_revision":grant.revision});
            if let Some(messaging) = &app.messaging {
                data["messaging_status"] = messaging.session.status();
            }
            json!({"content":[{"type":"text","text":data.to_string()}],"structuredContent":data,"isError":false})
        }
        "events/list" | "events/subscribe" | "events/unsubscribe" => {
            return rpc_error(&id, -32004, "Events not yet available")
        }
        _ => return rpc_error(&id, -32601, "Method not found"),
    };
    rpc_result(&id, result)
}
