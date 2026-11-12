//! Local OAuth authority; upstream login credentials never enter the durable store.
mod clock;
mod liveness;
mod protocol;
mod store;

use crate::grants::Binding;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;

pub use clock::{Clock, SystemClock};
pub use liveness::{Liveness, Outcome};
pub use store::Cutover;
pub const SCHEMA_VERSION: i64 = 5;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid authorization server configuration")]
    Configuration,
    #[error("invalid authorization grant")]
    InvalidGrant,
    #[error("authorization grant disabled")]
    Denied,
    #[error("authorization clock rollback")]
    ClockRollback,
    #[error("authorization service unavailable")]
    Unavailable,
    #[error("authorization rate exceeded")]
    RateLimited,
    #[error("authorization store unavailable")]
    Database(#[from] rusqlite::Error),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct ClientConfig {
    pub id: String,
    pub secret_file: PathBuf,
    pub redirect_uris: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct UpstreamConfig {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub verify: crate::auth::VerifierConfig,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct LivenessConfig {
    pub api_url: String,
    pub person: String,
    pub group: String,
    pub canary_person: String,
    pub token_file: PathBuf,
    #[serde(default = "default_grace")]
    pub grace_secs: i64,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}
fn default_grace() -> i64 {
    900
}
fn default_timeout() -> u64 {
    5000
}
fn hour() -> i64 {
    3600
}
fn idle() -> i64 {
    2592000
}
fn absolute() -> i64 {
    7776000
}
fn families() -> usize {
    8
}
fn rotations() -> usize {
    12
}
fn rows() -> usize {
    2048
}
fn pending() -> usize {
    64
}
fn rate() -> usize {
    30
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct Config {
    pub issuer: String,
    pub client: ClientConfig,
    pub upstream: UpstreamConfig,
    pub liveness: LivenessConfig,
    #[serde(default = "hour")]
    pub access_ttl_secs: i64,
    #[serde(default = "idle")]
    pub refresh_idle_secs: i64,
    #[serde(default = "absolute")]
    pub refresh_absolute_secs: i64,
    #[serde(default = "families")]
    pub max_families: usize,
    #[serde(default = "rotations")]
    pub rotations_per_hour: usize,
    #[serde(default = "rows")]
    pub max_refresh_rows: usize,
    #[serde(default = "pending")]
    pub pending_max: usize,
    #[serde(default = "rate")]
    pub authorize_rate_per_min: usize,
}

#[cfg(test)]
type AdmissionBarrier = Arc<dyn Fn(i64) + Send + Sync>;

#[cfg(test)]
type LivenessBarrier = Arc<dyn Fn(i64, i64, Outcome) + Send + Sync>;

pub struct Server {
    #[cfg(test)]
    pub(super) upgrade_barrier: std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(test)]
    pub(super) liveness_barrier: std::sync::Mutex<Option<LivenessBarrier>>,
    #[cfg(test)]
    pub(super) admission_barrier: std::sync::Mutex<Option<AdmissionBarrier>>,
    pub(crate) file: PathBuf,
    pub(crate) binding: Binding,
    pub(crate) scopes: Vec<String>,
    pub(crate) config: Config,
    pub(crate) clock: clock::Fence,
    pub(crate) liveness: Liveness,
    pub(crate) runtime: std::sync::Mutex<protocol::State>,
    pub(crate) client_secret: String,
    pub(crate) upstream_verifier: crate::auth::Verifier,
    pub(crate) upstream_client: reqwest::Client,
}

impl Server {
    pub fn from_config(
        config: Config,
        file: PathBuf,
        binding: Binding,
        scopes: Vec<String>,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, Error> {
        if config.issuer == binding.resource
            || config.issuer != binding.issuer
            || config.client.id != binding.hosted_client
            || scopes.is_empty()
            || !(60..=86400).contains(&config.access_ttl_secs)
            || !(3600..=7776000).contains(&config.refresh_idle_secs)
            || !(86400..=31536000).contains(&config.refresh_absolute_secs)
            || config.refresh_absolute_secs < config.refresh_idle_secs
            || !(0..=3600).contains(&config.liveness.grace_secs)
            || [
                config.max_families,
                config.rotations_per_hour,
                config.max_refresh_rows,
                config.pending_max,
                config.authorize_rate_per_min,
            ]
            .iter()
            .any(|n| !(1..=65536).contains(n))
        {
            return Err(Error::Configuration);
        }
        protocol::validate_upstream(&config)?;
        let client_secret = protocol::client(&config.client)?;
        let upstream_verifier = crate::auth::Verifier::from_config(config.upstream.verify.clone())
            .map_err(|_| Error::Configuration)?;
        let upstream_client = provider_client(&config.upstream.verify)?;
        let store = crate::grants::Store::open(&file).map_err(|_| Error::Unavailable)?;
        store.require_authorization_server_ready()?;
        let fence = clock::Fence::new(clock, &store.connection)?;
        let liveness = Liveness::new_with_root(
            &config.liveness,
            config.upstream.verify.root_certificate_file.as_deref(),
        )?;
        Ok(Arc::new(Self {
            file,
            binding,
            scopes,
            config,
            clock: fence,
            liveness,
            runtime: protocol::State::new(),
            client_secret,
            upstream_verifier,
            upstream_client,
            #[cfg(test)]
            admission_barrier: std::sync::Mutex::new(None),
            #[cfg(test)]
            upgrade_barrier: std::sync::Mutex::new(None),
            #[cfg(test)]
            liveness_barrier: std::sync::Mutex::new(None),
        }))
    }
}

pub(crate) fn hash(value: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
pub(crate) fn random(prefix: &str) -> Result<String, Error> {
    use base64::Engine;
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::Unavailable)?;
    Ok(format!(
        "{prefix}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    ))
}
pub(crate) fn token_shape(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + 43
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub(crate) fn private_text(file: &std::path::Path) -> Result<String, Error> {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(file).map_err(|_| Error::Configuration)?;
    if !metadata.is_file() || metadata.len() > 4096 || metadata.permissions().mode() & 0o077 != 0 {
        return Err(Error::Configuration);
    }
    let mut value = String::new();
    std::fs::File::open(file)
        .map_err(|_| Error::Configuration)?
        .take(4097)
        .read_to_string(&mut value)
        .map_err(|_| Error::Configuration)?;
    let value = value.trim().to_owned();
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_whitespace) {
        return Err(Error::Configuration);
    }
    Ok(value)
}
pub(crate) fn validate_schema(db: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    store::validate(db)
}

fn provider_client(config: &crate::auth::VerifierConfig) -> Result<reqwest::Client, Error> {
    let mut builder =
        crate::webhook::https_client_builder(std::time::Duration::from_millis(config.timeout_ms));
    if let Some(file) = &config.root_certificate_file {
        let pem = std::fs::read(file).map_err(|_| Error::Configuration)?;
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(&pem).map_err(|_| Error::Configuration)?,
        );
    }
    builder.build().map_err(|_| Error::Configuration)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod test_provider;
