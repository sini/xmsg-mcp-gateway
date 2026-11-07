use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    pub subject: String,
    pub hosted_client: String,
    pub introspection_url: String,
    pub introspection_client: String,
    pub client_secret_file: PathBuf,
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
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

pub struct Verifier {
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

impl Verifier {
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
            || config.introspection_client.contains(':')
            || config.provider_addresses.is_empty()
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
        let mut builder = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(config.timeout_ms))
            .resolve_to_addrs(host, &addresses);
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
        if claims["active"] != true
            || claims["iss"].as_str() != Some(&self.config.issuer)
            || !exact_audience(&claims["aud"], &self.config.resource)
            || claims["sub"].as_str() != Some(&self.config.subject)
            || claims["client_id"].as_str() != Some(&self.config.hosted_client)
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
        })
    }
}
