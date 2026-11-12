use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use reqwest::Client;
use reqwest::{Certificate, Url};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use crate::grants::exact_audience;

const MAX_RESPONSE: u64 = 65_536;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct VerifierConfig {
    pub service: String,
    pub issuer: String,
    pub resource: String,
    #[serde(default)]
    pub audience: Option<String>,
    pub subject: String,
    pub hosted_client: String,
    pub introspection_url: String,
    pub introspection_client: String,
    pub client_secret_file: PathBuf,
    #[serde(default)]
    pub provider_addresses: Vec<IpAddr>,
    pub required_scopes: Vec<String>,
    pub timeout_ms: u64,
    pub root_certificate_file: Option<PathBuf>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid identity verifier configuration")]
    Configuration,
    #[error("invalid bearer credential")]
    InvalidToken,
    #[error("authorization grant disabled")]
    Denied,
    #[error("identity provider unavailable")]
    Unavailable,
}

#[path = "auth/identity.rs"]
mod identity;
pub use identity::VerifiedIdentity;

#[derive(Clone, Debug)]
pub(crate) struct VerifiedContext {
    identity: Arc<VerifiedIdentity>,
    authority: crate::grants::Authorization,
}

impl VerifiedContext {
    pub(crate) fn new(
        identity: Arc<VerifiedIdentity>,
        authority: crate::grants::Authorization,
    ) -> Self {
        Self {
            identity,
            authority,
        }
    }

    pub(crate) fn identity(&self) -> &Arc<VerifiedIdentity> {
        &self.identity
    }

    pub(crate) fn authority(&self) -> &crate::grants::Authorization {
        &self.authority
    }
}

pub const MAX_PROFILES: usize = 16;

pub struct Verifier {
    profiles: Vec<ProfileVerifier>,
    route_claims: bool,
    opaque_default: Option<usize>,
    local: Option<Arc<LocalProfile>>,
    advertised: Vec<bool>,
    local_advertised: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    #[serde(flatten)]
    pub config: VerifierConfig,
    #[serde(default)]
    pub opaque_default: bool,
}

#[derive(Deserialize)]
struct RoutingClaims {
    iss: String,
    #[serde(default, deserialize_with = "present_string")]
    client_id: Option<String>,
    #[serde(default, deserialize_with = "present_string")]
    azp: Option<String>,
    aud: Value,
}

fn present_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

impl RoutingClaims {
    fn client(&self) -> Result<&str, Error> {
        match (self.client_id.as_deref(), self.azp.as_deref()) {
            (Some(client), Some(azp)) if client == azp => Ok(client),
            (Some(client), None) | (None, Some(client)) => Ok(client),
            _ => Err(Error::InvalidToken),
        }
    }
}

impl Verifier {
    pub fn from_config(config: VerifierConfig) -> Result<Self, Error> {
        Ok(Self {
            profiles: vec![ProfileVerifier::from_config(config)?],
            route_claims: false,
            opaque_default: None,
            local: None,
            advertised: vec![true],
            local_advertised: true,
        })
    }

    pub fn from_profiles(configs: Vec<VerifierConfig>) -> Result<Self, Error> {
        Self::from_profile_configs(
            configs
                .into_iter()
                .map(|config| ProfileConfig {
                    config,
                    opaque_default: false,
                })
                .collect(),
        )
    }

    pub fn from_profile_configs(configs: Vec<ProfileConfig>) -> Result<Self, Error> {
        let defaults: Vec<_> = configs
            .iter()
            .enumerate()
            .filter_map(|(index, profile)| profile.opaque_default.then_some(index))
            .collect();
        if defaults.len() > 1 {
            return Err(Error::Configuration);
        }
        let opaque_default = defaults.first().copied();
        let configs: Vec<_> = configs.into_iter().map(|profile| profile.config).collect();
        if configs.is_empty() || configs.len() > MAX_PROFILES {
            return Err(Error::Configuration);
        }
        let first = &configs[0];
        for (index, config) in configs.iter().enumerate() {
            if config.service != first.service
                || config.resource != first.resource
                || configs[..index].iter().any(|prior| {
                    prior.issuer == config.issuer
                        && prior.hosted_client == config.hosted_client
                        && (prior.audience.as_deref().unwrap_or(&prior.resource)
                            == config.audience.as_deref().unwrap_or(&config.resource)
                            || prior.subject == config.subject)
                })
            {
                return Err(Error::Configuration);
            }
        }
        let configs_len = configs.len();
        Ok(Self {
            profiles: configs
                .into_iter()
                .map(ProfileVerifier::from_config)
                .collect::<Result<_, _>>()?,
            route_claims: true,
            opaque_default,
            local: None,
            advertised: vec![true; configs_len],
            local_advertised: true,
        })
    }

    pub fn bindings(&self) -> Vec<crate::grants::Binding> {
        self.profiles
            .iter()
            .map(|profile| crate::grants::Binding {
                service: profile.config.service.clone(),
                issuer: profile.config.issuer.clone(),
                resource: profile.config.resource.clone(),
                subject: profile.config.subject.clone(),
                hosted_client: profile.config.hosted_client.clone(),
            })
            .chain(self.local.iter().map(|local| local.server.binding.clone()))
            .collect()
    }

    pub fn resource(&self) -> &str {
        self.profiles
            .first()
            .map(|p| p.config.resource.as_str())
            .unwrap_or_else(|| {
                self.local
                    .as_ref()
                    .unwrap()
                    .server
                    .binding
                    .resource
                    .as_str()
            })
    }

    pub fn issuers(&self) -> Vec<String> {
        let mut issuers = Vec::new();
        for (index, profile) in self.profiles.iter().enumerate() {
            if self.advertised[index] && !issuers.contains(&profile.config.issuer) {
                issuers.push(profile.config.issuer.clone());
            }
        }
        if let Some(local) = &self.local {
            if self.local_advertised && !issuers.contains(&local.server.binding.issuer) {
                issuers.push(local.server.binding.issuer.clone());
            }
        }
        issuers
    }

    pub fn scopes(&self) -> Vec<String> {
        let mut scopes = Vec::new();
        for profile in &self.profiles {
            for scope in &profile.config.required_scopes {
                if !scopes.contains(scope) {
                    scopes.push(scope.clone());
                }
            }
        }
        if let Some(local) = &self.local {
            for scope in &local.server.scopes {
                if !scopes.contains(scope) {
                    scopes.push(scope.clone());
                }
            }
        }
        scopes
    }

    pub fn max_timeout_ms(&self) -> u64 {
        self.profiles
            .iter()
            .map(|profile| profile.config.timeout_ms)
            .max()
            .unwrap_or(0)
    }

    pub fn requires_scope(&self, scope: &str) -> bool {
        self.profiles
            .iter()
            .all(|profile| profile.requires_scope(scope))
            && self
                .local
                .as_ref()
                .is_none_or(|local| local.server.scopes.iter().any(|s| s == scope))
    }

    pub fn requires_scope_for_binding(
        &self,
        binding: &crate::grants::Binding,
        scope: &str,
    ) -> bool {
        self.profiles.iter().any(|profile| {
            let config = &profile.config;
            config.service == binding.service
                && config.issuer == binding.issuer
                && config.resource == binding.resource
                && config.subject == binding.subject
                && config.hosted_client == binding.hosted_client
                && profile.requires_scope(scope)
        }) || self.local.as_ref().is_some_and(|local| {
            &local.server.binding == binding && local.server.scopes.iter().any(|s| s == scope)
        })
    }

    pub fn requires_scope_for(&self, identity: &VerifiedIdentity, scope: &str) -> bool {
        self.profiles.iter().any(|profile| {
            let config = &profile.config;
            config.service == identity.service
                && config.issuer == identity.issuer
                && config.resource == identity.resource
                && config.subject == identity.subject
                && config.hosted_client == identity.hosted_client
                && config.audience.as_deref().unwrap_or(&config.resource) == identity.audience
                && profile.requires_scope(scope)
        }) || self.local.as_ref().is_some_and(|local| {
            local.matches(identity) && local.server.scopes.iter().any(|s| s == scope)
        })
    }

    pub async fn verify(&self, token: &str) -> Result<VerifiedIdentity, Error> {
        if token.is_empty() || token.len() > 16_384 || token.chars().any(char::is_whitespace) {
            return Err(Error::InvalidToken);
        }
        let profile = if self.route_claims {
            let segments: Vec<_> = token.split('.').collect();
            let payload = if segments.len() == 3 {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(segments[1])
                    .ok()
            } else {
                None
            };
            let has_issuer = payload
                .as_deref()
                .and_then(|payload| serde_json::from_slice::<Value>(payload).ok())
                .is_some_and(|claims| claims.get("iss").is_some());
            if has_issuer {
                if segments.iter().any(|segment| segment.is_empty()) {
                    return Err(Error::InvalidToken);
                }
                let claims: RoutingClaims =
                    serde_json::from_slice(payload.as_deref().ok_or(Error::InvalidToken)?)
                        .map_err(|_| Error::InvalidToken)?;
                let client = claims.client()?;
                // Claims only select a configured provider; introspection establishes authority.
                self.profiles
                    .iter()
                    .find(|profile| {
                        claims.iss == profile.config.issuer
                            && client == profile.config.hosted_client
                            && exact_audience(
                                &claims.aud,
                                profile
                                    .config
                                    .audience
                                    .as_deref()
                                    .unwrap_or(&profile.config.resource),
                            )
                    })
                    .ok_or(Error::InvalidToken)?
            } else {
                if let Some(local) = &self.local {
                    if !crate::authorization_server::token_shape(token, "xgw_at_") {
                        return Err(Error::InvalidToken);
                    }
                    let local = local.clone();
                    let token = token.to_owned();
                    let subscriber = tracing::dispatcher::get_default(Clone::clone);
                    return tokio::task::spawn_blocking(move || {
                        tracing::dispatcher::with_default(&subscriber, || {
                            let store = local.server.store().map_err(local_error)?;
                            local.admit(&store, &token).map(|(identity, _)| identity)
                        })
                    })
                    .await
                    .map_err(|_| Error::Unavailable)?;
                }
                &self.profiles[self.opaque_default.ok_or(Error::InvalidToken)?]
            }
        } else {
            &self.profiles[0]
        };
        profile.verify(token).await
    }
}

struct ProfileVerifier {
    config: VerifierConfig,
    client: Client,
    secret: String,
}

fn secure_url(raw: &str) -> Result<Url, Error> {
    let url = Url::parse(raw).map_err(|_| Error::Configuration)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Configuration);
    }
    Ok(url)
}

impl ProfileVerifier {
    pub fn from_config(config: VerifierConfig) -> Result<Self, Error> {
        let endpoint = secure_url(&config.introspection_url)?;
        secure_url(&config.issuer)?;
        secure_url(&config.resource)?;
        if [
            &config.service,
            &config.subject,
            &config.hosted_client,
            &config.introspection_client,
        ]
        .iter()
        .any(|s| s.trim().is_empty())
            || config.audience.as_ref().is_some_and(|audience| {
                audience.is_empty() || audience.chars().any(char::is_whitespace)
            })
            || config.introspection_client.contains(':')
            || config.required_scopes.is_empty()
            || config
                .required_scopes
                .iter()
                .any(|s| s.is_empty() || s.chars().any(char::is_whitespace))
            || config.timeout_ms == 0
            || config.timeout_ms > 30_000
        {
            return Err(Error::Configuration);
        }
        let mut builder =
            crate::webhook::https_client_builder(Duration::from_millis(config.timeout_ms));
        if !config.provider_addresses.is_empty() {
            let host = endpoint.host_str().ok_or(Error::Configuration)?;
            if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
                if !config.provider_addresses.contains(&ip) {
                    return Err(Error::Configuration);
                }
            }
            let addresses: Vec<_> = config
                .provider_addresses
                .iter()
                .map(|ip| SocketAddr::new(*ip, endpoint.port_or_known_default().unwrap_or(443)))
                .collect();
            builder = builder.no_proxy().resolve_to_addrs(host, &addresses);
        }
        if let Some(file) = &config.root_certificate_file {
            let pem = fs::read(file).map_err(|_| Error::Configuration)?;
            builder = builder.add_root_certificate(
                Certificate::from_pem(&pem).map_err(|_| Error::Configuration)?,
            );
        }
        let metadata =
            fs::metadata(&config.client_secret_file).map_err(|_| Error::Configuration)?;
        if !metadata.is_file() || metadata.len() > 4096 {
            return Err(Error::Configuration);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::Configuration);
            }
        }
        let secret = fs::read_to_string(&config.client_secret_file)
            .map_err(|_| Error::Configuration)?
            .trim()
            .to_owned();
        if secret.is_empty() {
            return Err(Error::Configuration);
        }
        let client = builder.build().map_err(|_| Error::Configuration)?;
        Ok(Self {
            config,
            client,
            secret,
        })
    }

    pub fn requires_scope(&self, scope: &str) -> bool {
        self.config
            .required_scopes
            .iter()
            .any(|required| required == scope)
    }

    pub async fn verify(&self, token: &str) -> Result<VerifiedIdentity, Error> {
        if token.is_empty() || token.len() > 16_384 || token.chars().any(char::is_whitespace) {
            return Err(Error::InvalidToken);
        }
        let mut response = self
            .client
            .post(&self.config.introspection_url)
            .basic_auth(&self.config.introspection_client, Some(&self.secret))
            .form(&[("token", token), ("token_type_hint", "access_token")])
            .send()
            .await
            .map_err(|_| Error::Unavailable)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::Unavailable);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
            if body.len() as u64 + chunk.len() as u64 > MAX_RESPONSE {
                return Err(Error::Unavailable);
            }
            body.extend_from_slice(&chunk);
        }
        let claims: Value = serde_json::from_slice(&body).map_err(|_| Error::Unavailable)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Unavailable)?
            .as_secs();
        let exp = claims["exp"].as_u64().ok_or(Error::InvalidToken)?;
        let nbf = match claims.get("nbf") {
            Some(value) => value.as_u64().ok_or(Error::InvalidToken)?,
            None => 0,
        };
        let scope = claims["scope"].as_str().ok_or(Error::InvalidToken)?;
        let client = match (claims.get("client_id"), claims.get("azp")) {
            (Some(client), Some(azp)) if client.as_str().is_some() && client == azp => {
                client.as_str()
            }
            (Some(client), None) | (None, Some(client)) => client.as_str(),
            _ => None,
        };
        let audience = self
            .config
            .audience
            .as_deref()
            .unwrap_or(&self.config.resource);
        if claims["active"] != true
            || claims["iss"].as_str() != Some(&self.config.issuer)
            || !exact_audience(&claims["aud"], audience)
            || claims["sub"].as_str() != Some(&self.config.subject)
            || client != Some(self.config.hosted_client.as_str())
            || exp <= now
            || nbf > now
            || !self.config.required_scopes.iter().all(|required| {
                scope
                    .split_ascii_whitespace()
                    .any(|actual| actual == required)
            })
        {
            return Err(Error::InvalidToken);
        }
        Ok(VerifiedIdentity {
            service: self.config.service.clone(),
            issuer: self.config.issuer.clone(),
            resource: self.config.resource.clone(),
            subject: self.config.subject.clone(),
            hosted_client: self.config.hosted_client.clone(),
            expires_at: exp,
            audience: audience.to_owned(),
            token_family: None,
            admission: None,
            admission_policy: None,
        })
    }
}

pub(crate) struct LocalProfile {
    pub(crate) server: Arc<crate::authorization_server::Server>,
}
fn local_error(error: crate::authorization_server::Error) -> Error {
    match error {
        crate::authorization_server::Error::InvalidGrant => Error::InvalidToken,
        crate::authorization_server::Error::Denied => Error::Denied,
        _ => Error::Unavailable,
    }
}
impl LocalProfile {
    pub(crate) fn new(server: Arc<crate::authorization_server::Server>) -> Self {
        Self { server }
    }
    fn identity(
        &self,
        expires: i64,
        family: Option<String>,
        admission: Option<crate::grants::Authorization>,
    ) -> VerifiedIdentity {
        let binding = &self.server.binding;
        VerifiedIdentity {
            service: binding.service.clone(),
            issuer: binding.issuer.clone(),
            resource: binding.resource.clone(),
            subject: binding.subject.clone(),
            hosted_client: binding.hosted_client.clone(),
            audience: binding.resource.clone(),
            expires_at: expires.max(0) as u64,
            token_family: family,
            admission: admission.map(|authority| (authority.grant_id, authority.revision)),
            admission_policy: None,
        }
    }
    fn matches(&self, identity: &VerifiedIdentity) -> bool {
        let b = &self.server.binding;
        b.service == identity.service
            && b.issuer == identity.issuer
            && b.resource == identity.resource
            && b.subject == identity.subject
            && b.hosted_client == identity.hosted_client
            && identity.audience == b.resource
    }
    pub(crate) fn local_identity(
        &self,
        login: &VerifiedIdentity,
    ) -> Result<VerifiedIdentity, Error> {
        if login.subject() != self.server.binding.subject {
            return Err(Error::InvalidToken);
        }
        Ok(self.identity(self.server.clock.wall() + 60, None, None))
    }
    pub(crate) fn admit(
        &self,
        store: &crate::grants::Store,
        token: &str,
    ) -> Result<(VerifiedIdentity, crate::grants::Authorization), Error> {
        let admitted = self
            .server
            .admit_in_store(store, token)
            .map_err(local_error)?;
        let mut identity = self.identity(
            admitted.expires,
            Some(admitted.family),
            Some(admitted.authority.clone()),
        );
        identity.admission_policy = Some(admitted.policy);
        Ok((identity, admitted.authority))
    }
    pub(crate) fn verify_family(&self, id: &str) -> Result<VerifiedIdentity, Error> {
        let (family, expires) = self.server.verify_family(id).map_err(local_error)?;
        Ok(self.identity(expires, Some(family.id), None))
    }
}
impl Verifier {
    pub(crate) fn with_local(
        mut self,
        server: Arc<crate::authorization_server::Server>,
        advertised: bool,
    ) -> Result<Self, Error> {
        if self.local.is_some()
            || self.opaque_default.is_some()
            || self
                .bindings()
                .iter()
                .any(|binding| binding == &server.binding)
            || self.profiles.iter().any(|p| {
                p.config.service != server.binding.service
                    || p.config.resource != server.binding.resource
                    || (p.config.issuer == server.binding.issuer
                        && p.config.hosted_client == server.binding.hosted_client
                        && p.config.audience.as_deref().unwrap_or(&p.config.resource)
                            == server.binding.resource)
            })
        {
            return Err(Error::Configuration);
        }
        self.local = Some(Arc::new(LocalProfile::new(server)));
        self.local_advertised = advertised;
        self.route_claims = true;
        Ok(self)
    }
    pub(crate) fn local_only(
        server: Arc<crate::authorization_server::Server>,
        advertised: bool,
    ) -> Self {
        Self {
            profiles: vec![],
            route_claims: true,
            opaque_default: None,
            local: Some(Arc::new(LocalProfile::new(server))),
            advertised: vec![],
            local_advertised: advertised,
        }
    }
    pub(crate) fn set_advertised(&mut self, advertised: Vec<bool>) {
        self.advertised = advertised;
    }
    pub(crate) fn local_server(&self) -> Option<&Arc<crate::authorization_server::Server>> {
        self.local.as_ref().map(|l| &l.server)
    }
    pub(crate) fn verify_family(&self, id: &str) -> Result<VerifiedIdentity, Error> {
        self.local
            .as_ref()
            .ok_or(Error::InvalidToken)?
            .verify_family(id)
    }
}

impl VerifiedIdentity {
    pub(crate) fn custody_authority(
        &self,
        store: &crate::grants::Store,
    ) -> Result<crate::grants::Authorization, crate::grants::Error> {
        let current = store.authorize(self)?;
        if self
            .admitted_authority()
            .is_some_and(|captured| captured != current)
        {
            return Err(crate::grants::Error::Denied);
        }
        Ok(current)
    }
}
