use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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

const MAX_REQUEST: usize = 65_536;
const VERSIONS: [&str; 3] = ["2025-03-26", "2025-06-18", "2025-11-25"];

#[derive(Debug, thiserror::Error)]
#[error("invalid or unavailable owner serving configuration")]
pub struct ConfigurationError;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    bind: SocketAddr,
    grant_store: PathBuf,
    request_timeout_ms: u64,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    verifier: VerifierConfig,
}

struct App {
    verifier: Verifier,
    grant_store: PathBuf,
    request_timeout_ms: u64,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    resource: String,
    issuer: String,
    scopes: Vec<String>,
    challenge: HeaderValue,
}

pub struct Serving {
    router: Router,
    bind: SocketAddr,
}

fn resolve_profile_path(directory: &Path, file: &mut PathBuf) {
    if file.is_relative() {
        *file = directory.join(&*file);
    }
}

impl Serving {
    pub async fn from_owner_file(config_file: &Path) -> Result<Self, ConfigurationError> {
        let mut file = File::open(config_file).map_err(|_| ConfigurationError)?;
        let metadata = file.metadata().map_err(|_| ConfigurationError)?;
        if !metadata.is_file() || metadata.len() > MAX_REQUEST as u64 {
            return Err(ConfigurationError);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(ConfigurationError);
            }
        }
        let mut raw = Vec::new();
        file.by_ref()
            .take(MAX_REQUEST as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(|_| ConfigurationError)?;
        if raw.len() > MAX_REQUEST {
            return Err(ConfigurationError);
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
        if !config.bind.ip().is_loopback()
            || config.allowed_hosts.is_empty()
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
            return Err(ConfigurationError);
        }
        let mut metadata_url =
            reqwest::Url::parse(&config.verifier.resource).map_err(|_| ConfigurationError)?;
        let resource_path = metadata_url.path().trim_end_matches('/').to_owned();
        if resource_path.contains(['{', '}', '*']) || resource_path.starts_with("/.well-known/") {
            return Err(ConfigurationError);
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
        let verifier = Verifier::from_config(config.verifier).map_err(|_| ConfigurationError)?;
        Store::open(&config.grant_store)
            .and_then(|store| store.validate_profile(&profile))
            .map_err(|_| ConfigurationError)?;
        let state = Arc::new(App {
            verifier,
            grant_store: config.grant_store,
            allowed_hosts: config.allowed_hosts,
            allowed_origins: config.allowed_origins,
            request_timeout_ms: config.request_timeout_ms,
            resource,
            issuer,
            scopes,
            challenge,
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
            router: router.with_state(state),
            bind: config.bind,
        })
    }

    pub fn router(&self) -> Router {
        self.router.clone()
    }

    pub async fn serve(self) -> std::io::Result<()> {
        let listener = tokio::net::TcpListener::bind(self.bind).await?;
        println!("serving MCP at {}", listener.local_addr()?);
        axum::serve(listener, self.router)
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await
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

fn policy_response(error: GrantError) -> Response {
    match error {
        GrantError::Denied => StatusCode::FORBIDDEN.into_response(),
        _ => unavailable(),
    }
}

async fn authorize_current(
    app: &App,
    identity: Arc<VerifiedIdentity>,
) -> Result<Authorization, Response> {
    let store_file = app.grant_store.clone();
    let subscriber = tracing::dispatcher::get_default(Clone::clone);
    tokio::task::spawn_blocking(move || {
        tracing::dispatcher::with_default(&subscriber, || {
            let store = Store::open(&store_file)?;
            store.authorize(&identity)
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
    #[serde(default, rename = "arguments")]
    _arguments: Empty,
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

async fn mcp(State(app): State<Arc<App>>, request: Request) -> Response {
    tokio::time::timeout(
        Duration::from_millis(app.request_timeout_ms),
        mcp_request(app, request),
    )
    .await
    .unwrap_or_else(|_| unavailable())
}

async fn mcp_request(app: Arc<App>, request: Request) -> Response {
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
    let grant = match authorization {
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
                _ => {
                    json!({"tools":[{"name":"xmsg_identity","description":"Read the authenticated gateway identity.",
                    "inputSchema":{"type":"object","properties":{},"additionalProperties":false},
                    "annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false},
                    "securitySchemes":[{"type":"oauth2","scopes":app.scopes}]}]})
                }
            }
        }
        "tools/call" => {
            let call: Call = match serde_json::from_value(rpc.params) {
                Ok(call) => call,
                Err(_) => return rpc_error(&id, -32602, "Invalid params"),
            };
            if call.name != "xmsg_identity" {
                return rpc_error(&id, -32004, "Tool not yet available");
            }
            tracing::info!(target: "gateway_dispatch", operation = "xmsg_identity", "dispatch");
            let data = json!({"service":identity.service(),"subject":identity.subject(),"issuer":identity.issuer(),
                "resource":identity.resource(),"hosted_client":identity.hosted_client(),"grant_revision":grant.revision});
            json!({"content":[{"type":"text","text":data.to_string()}],"structuredContent":data,"isError":false})
        }
        "events/list" | "events/subscribe" | "events/unsubscribe" => {
            return rpc_error(&id, -32004, "Events not yet available")
        }
        _ => return rpc_error(&id, -32601, "Method not found"),
    };
    rpc_result(&id, result)
}
