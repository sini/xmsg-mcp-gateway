use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use reqwest::Client;
use reqwest::{Certificate, Url};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use crate::grants::exact_audience;

const MAX_RESPONSE: u64 = 65_536;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    #[error("identity provider unavailable")]
    Unavailable,
}

#[derive(Debug)]
pub struct VerifiedIdentity {
    service: String,
    issuer: String,
    resource: String,
    subject: String,
    hosted_client: String,
    expires_at: u64,
    audience: String,
}

impl VerifiedIdentity {
    pub fn service(&self) -> &str {
        &self.service
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn resource(&self) -> &str {
        &self.resource
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn hosted_client(&self) -> &str {
        &self.hosted_client
    }
    pub fn same_profile(&self, other: &Self) -> bool {
        self.service == other.service
            && self.issuer == other.issuer
            && self.resource == other.resource
            && self.subject == other.subject
            && self.hosted_client == other.hosted_client
            && self.audience == other.audience
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

pub const MAX_PROFILES: usize = 16;

pub struct Verifier {
    profiles: Vec<ProfileVerifier>,
    route_claims: bool,
    opaque_default: Option<usize>,
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
        Ok(Self {
            profiles: configs
                .into_iter()
                .map(ProfileVerifier::from_config)
                .collect::<Result<_, _>>()?,
            route_claims: true,
            opaque_default,
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
            .collect()
    }

    pub fn resource(&self) -> &str {
        &self.profiles[0].config.resource
    }

    pub fn issuers(&self) -> Vec<String> {
        let mut issuers = Vec::new();
        for profile in &self.profiles {
            if !issuers.contains(&profile.config.issuer) {
                issuers.push(profile.config.issuer.clone());
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
        scopes
    }

    pub fn max_timeout_ms(&self) -> u64 {
        self.profiles
            .iter()
            .map(|profile| profile.config.timeout_ms)
            .max()
            .unwrap()
    }

    pub fn requires_scope(&self, scope: &str) -> bool {
        self.profiles
            .iter()
            .all(|profile| profile.requires_scope(scope))
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
        })
    }
}
