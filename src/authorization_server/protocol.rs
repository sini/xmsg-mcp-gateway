use super::{hash, private_text, random, ClientConfig, Error, Outcome, Server};
use base64::Engine;
use reqwest::Url;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub(crate) struct Pending {
    redirect: String,
    state: String,
    challenge: String,
    scope: String,
    resource: String,
    grant: crate::grants::Authorization,
    verifier: String,
    expires: i64,
    sequence: u64,
}
pub(crate) struct State {
    pending: HashMap<String, Pending>,
    sequence: u64,
    tokens: f64,
    refilled: i64,
}
impl State {
    pub fn new() -> Mutex<Self> {
        Mutex::new(Self {
            pending: HashMap::new(),
            sequence: 0,
            tokens: 10.0,
            refilled: 0,
        })
    }
}
pub struct Reply {
    pub status: u16,
    pub body: Value,
    pub location: Option<String>,
    pub retry: bool,
    pub basic: bool,
}
impl Reply {
    fn json(status: u16, body: Value) -> Self {
        Self {
            status,
            body,
            location: None,
            retry: false,
            basic: false,
        }
    }
    fn redirect(url: String) -> Self {
        Self {
            status: 302,
            body: json!({}),
            location: Some(url),
            retry: false,
            basic: false,
        }
    }
    fn failure(error: Error) -> Self {
        match error {
            Error::InvalidGrant | Error::Denied => {
                Self::json(400, json!({"error":"invalid_grant"}))
            }
            Error::RateLimited => Self {
                retry: true,
                ..Self::json(429, json!({"error":"temporarily_unavailable"}))
            },
            _ => Self {
                retry: true,
                ..Self::json(503, json!({"error":"temporarily_unavailable"}))
            },
        }
    }
}
fn secure(raw: &str) -> Result<Url, Error> {
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
pub(crate) fn client(config: &ClientConfig) -> Result<String, Error> {
    if config.id.is_empty()
        || config.id.len() > 2048
        || config.redirect_uris.is_empty()
        || config.redirect_uris.len() > 64
    {
        return Err(Error::Configuration);
    }
    let reserved = [
        "code",
        "state",
        "iss",
        "error",
        "error_description",
        "error_uri",
    ];
    for uri in &config.redirect_uris {
        let redirect = secure(uri)?;
        if redirect
            .query_pairs()
            .any(|(key, _)| reserved.contains(&key.as_ref()))
        {
            return Err(Error::Configuration);
        }
    }
    let secret = private_text(&config.secret_file)?;
    if secret.len() != 43
        || !secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
    {
        return Err(Error::Configuration);
    }
    Ok(secret)
}
pub(crate) fn validate_upstream(config: &super::Config) -> Result<(), Error> {
    let issuer = secure(&config.issuer)?;
    if issuer.path() != "/" || issuer.query().is_some() {
        return Err(Error::Configuration);
    }
    secure(&config.upstream.authorization_endpoint)?;
    secure(&config.upstream.token_endpoint)?;
    secure(&config.upstream.redirect_uri)?;
    if config.upstream.client_id.is_empty()
        || config.upstream.verify.hosted_client != config.upstream.client_id
        || config
            .upstream
            .verify
            .audience
            .as_deref()
            .unwrap_or(&config.upstream.verify.resource)
            != config.upstream.client_id
        || !config
            .upstream
            .verify
            .required_scopes
            .iter()
            .any(|s| s == "openid")
    {
        return Err(Error::Configuration);
    }
    Ok(())
}
fn form(raw: &str) -> Result<HashMap<String, String>, Error> {
    fn decode(raw: &str) -> Result<String, Error> {
        let mut bytes = Vec::new();
        let mut input = raw.bytes();
        while let Some(byte) = input.next() {
            bytes.push(match byte {
                b'+' => b' ',
                b'%' => {
                    let high = input.next().and_then(|b| (b as char).to_digit(16));
                    let low = input.next().and_then(|b| (b as char).to_digit(16));
                    match (high, low) {
                        (Some(h), Some(l)) => (h * 16 + l) as u8,
                        _ => return Err(Error::InvalidGrant),
                    }
                }
                b => b,
            });
        }
        String::from_utf8(bytes).map_err(|_| Error::InvalidGrant)
    }
    let mut fields = HashMap::new();
    if raw.is_empty() {
        return Ok(fields);
    }
    for pair in raw.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if fields.insert(decode(key)?, decode(value)?).is_some() {
            return Err(Error::InvalidGrant);
        }
    }
    Ok(fields)
}

fn field<'a>(fields: &'a HashMap<String, String>, key: &str) -> Result<&'a str, Error> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or(Error::InvalidGrant)
}
fn redirect(url: &str, state: &str, kind: &str, value: &str) -> Reply {
    match Url::parse(url) {
        Ok(mut url) => {
            url.query_pairs_mut()
                .append_pair(kind, value)
                .append_pair("state", state);
            Reply::redirect(url.into())
        }
        Err(_) => Reply::json(400, json!({"error":"invalid_request"})),
    }
}
impl Server {
    #[cfg(test)]
    pub(super) fn pending_count(&self) -> usize {
        self.runtime.lock().unwrap().pending.len()
    }

    pub(crate) fn metadata(&self) -> Value {
        json!({"issuer":self.config.issuer,"authorization_endpoint":format!("{}/oauth/authorize",self.config.issuer.trim_end_matches('/')),"token_endpoint":format!("{}/oauth/token",self.config.issuer.trim_end_matches('/')),"revocation_endpoint":format!("{}/oauth/revoke",self.config.issuer.trim_end_matches('/')),"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["client_secret_basic"],"revocation_endpoint_auth_methods_supported":["client_secret_basic"],"scopes_supported":self.scopes})
    }
    fn authenticated(&self, authorization: Option<&str>) -> bool {
        let Some((scheme, encoded)) = authorization.and_then(|s| s.split_once(' ')) else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("Basic") || encoded.len() > 8192 {
            return false;
        }
        let Ok(actual) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            return false;
        };
        let mut encoded_id = Url::parse("https://form.invalid").unwrap();
        encoded_id
            .query_pairs_mut()
            .append_pair("", &self.config.client.id);
        let id = &encoded_id.query().unwrap()[1..];
        let expected = format!("{id}:{}", self.client_secret);
        let expected = Sha256::digest(expected.as_bytes());
        let actual = Sha256::digest(&actual);
        expected
            .iter()
            .zip(actual.iter())
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
    }
    fn authorize(&self, raw: &str) -> Result<Reply, Error> {
        let fields = form(raw)?;
        let wall = self.clock.wall();
        let burst = if self.config.authorize_rate_per_min > 30 {
            self.config.authorize_rate_per_min
        } else {
            10
        };
        {
            let mut state = self.runtime.lock().map_err(|_| Error::Unavailable)?;
            if state.refilled == 0 {
                state.tokens = burst as f64;
                state.refilled = wall;
            }
            state.tokens = (state.tokens
                + wall.saturating_sub(state.refilled).max(0) as f64
                    * self.config.authorize_rate_per_min as f64
                    / 60.0)
                .min(burst as f64);
            state.refilled = wall;
            if state.tokens < 1.0 {
                return Err(Error::RateLimited);
            }
            state.tokens -= 1.0;
        }
        let client = field(&fields, "client_id")?;
        let uri = field(&fields, "redirect_uri")?;
        if client != self.config.client.id
            || !self.config.client.redirect_uris.iter().any(|u| u == uri)
        {
            return Ok(Reply::json(400, json!({"error":"invalid_request"})));
        }
        let state = fields.get("state").map(String::as_str).unwrap_or("");
        let checked = (|| {
            if state.len() > 512
                || field(&fields, "response_type")? != "code"
                || field(&fields, "resource")? != self.binding.resource
                || field(&fields, "code_challenge_method")? != "S256"
            {
                return Err(Error::InvalidGrant);
            }
            let challenge = field(&fields, "code_challenge")?;
            if challenge.len() != 43
                || !challenge
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(Error::InvalidGrant);
            }
            let scope = fields
                .get("scope")
                .cloned()
                .unwrap_or_else(|| self.scopes.join(" "));
            if scope
                .split_ascii_whitespace()
                .any(|s| !self.scopes.iter().any(|r| r == s))
            {
                return Err(Error::InvalidGrant);
            }
            let authority = self.local_authority()?;
            let kstate = random("")?;
            let verifier = random("")?;
            let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(verifier.as_bytes()));
            let mut destination = Url::parse(&self.config.upstream.authorization_endpoint)
                .map_err(|_| Error::Configuration)?;
            destination
                .query_pairs_mut()
                .append_pair("response_type", "code")
                .append_pair("client_id", &self.config.upstream.client_id)
                .append_pair("redirect_uri", &self.config.upstream.redirect_uri)
                .append_pair("scope", "openid")
                .append_pair("state", &kstate)
                .append_pair("code_challenge", &digest)
                .append_pair("code_challenge_method", "S256");
            let mut runtime = self.runtime.lock().map_err(|_| Error::Unavailable)?;
            runtime.pending.retain(|_, p| p.expires > wall);
            if runtime.pending.len() >= self.config.pending_max {
                if let Some(old) = runtime
                    .pending
                    .iter()
                    .min_by_key(|(_, p)| p.sequence)
                    .map(|(k, _)| k.clone())
                {
                    runtime.pending.remove(&old);
                }
            }
            runtime.sequence = runtime.sequence.checked_add(1).ok_or(Error::Unavailable)?;
            let sequence = runtime.sequence;
            runtime.pending.insert(
                hash(&kstate),
                Pending {
                    redirect: uri.into(),
                    state: state.into(),
                    challenge: challenge.into(),
                    scope,
                    resource: self.binding.resource.clone(),
                    grant: authority,
                    verifier,
                    expires: wall + 600,
                    sequence,
                },
            );
            Ok(Reply::redirect(destination.into()))
        })();
        Ok(match checked {
            Ok(reply) => reply,
            Err(Error::Denied) => redirect(uri, state, "error", "access_denied"),
            Err(Error::InvalidGrant) => redirect(uri, state, "error", "invalid_request"),
            Err(_) => redirect(uri, state, "error", "temporarily_unavailable"),
        })
    }
    async fn callback(self: &Arc<Self>, raw: &str) -> Result<Reply, Error> {
        let fields = form(raw)?;
        let state = field(&fields, "state")?;
        let pending = self
            .runtime
            .lock()
            .map_err(|_| Error::Unavailable)?
            .pending
            .remove(&hash(state))
            .ok_or(Error::InvalidGrant)?;
        if pending.expires <= self.clock.wall() {
            return Err(Error::InvalidGrant);
        }
        if fields.contains_key("error") {
            return Ok(redirect(
                &pending.redirect,
                &pending.state,
                "error",
                "access_denied",
            ));
        }
        let result = async {
            let code = field(&fields, "code")?;
            let mut response = self
                .upstream_client
                .post(&self.config.upstream.token_endpoint)
                .form(&[
                    ("grant_type", "authorization_code"),
                    ("client_id", self.config.upstream.client_id.as_str()),
                    ("code", code),
                    ("redirect_uri", self.config.upstream.redirect_uri.as_str()),
                    ("code_verifier", pending.verifier.as_str()),
                ])
                .send()
                .await
                .map_err(|_| Error::Unavailable)?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(if response.status().is_server_error() {
                    Error::Unavailable
                } else {
                    Error::InvalidGrant
                });
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
                if body.len() + chunk.len() > 65536 {
                    return Err(Error::Unavailable);
                }
                body.extend_from_slice(&chunk);
            }
            let value: Value = serde_json::from_slice(&body).map_err(|_| Error::Unavailable)?;
            let token = value
                .get("access_token")
                .and_then(Value::as_str)
                .ok_or(Error::InvalidGrant)?;
            let login =
                self.upstream_verifier
                    .verify(token)
                    .await
                    .map_err(|error| match error {
                        crate::auth::Error::InvalidToken => Error::InvalidGrant,
                        _ => Error::Unavailable,
                    })?;
            crate::auth::LocalProfile::new(self.clone())
                .local_identity(&login)
                .map_err(|_| Error::InvalidGrant)?;
            let store = self.store()?;
            let (start, _) = self.clock.mint(&store.connection)?;
            drop(store);
            tracing::debug!(target:"gateway_oauth_liveness",class="callback_started");
            match self.liveness.read(start).await {
                Outcome::Positive => {}
                Outcome::Negative => return Err(Error::Denied),
                _ => return Err(Error::Unavailable),
            }
            if pending.resource != self.binding.resource {
                return Err(Error::InvalidGrant);
            }
            self.issue_code(
                &pending.grant,
                &pending.redirect,
                &pending.challenge,
                &pending.scope,
                start,
            )
        }
        .await;
        Ok(match result {
            Ok(code) => redirect(&pending.redirect, &pending.state, "code", &code),
            Err(Error::InvalidGrant | Error::Denied) => {
                redirect(&pending.redirect, &pending.state, "error", "access_denied")
            }
            Err(_) => redirect(
                &pending.redirect,
                &pending.state,
                "error",
                "temporarily_unavailable",
            ),
        })
    }
    pub async fn handle(
        self: &Arc<Self>,
        route: &str,
        method: &str,
        query: &str,
        authorization: Option<&str>,
        body: &str,
    ) -> Reply {
        let result = match (route, method) {
            ("/.well-known/oauth-authorization-server", "GET") => {
                Ok(Reply::json(200, self.metadata()))
            }
            ("/oauth/authorize", "GET") => self.authorize(query),
            ("/oauth/callback", "GET") => self.callback(query).await,
            ("/oauth/token" | "/oauth/revoke", "POST") => {
                if !self.authenticated(authorization) {
                    tracing::info!(target: "gateway_oauth_authentication", class = "invalid_client", "OAuth authentication refused");
                    return Reply {
                        basic: true,
                        ..Reply::json(401, json!({"error":"invalid_client"}))
                    };
                }
                match form(body) {
                    Err(error) => Err(error),
                    Ok(fields) => {
                        if route == "/oauth/revoke" {
                            match fields.get("token") {
                                Some(token) => {
                                    self.revoke(token).map(|_| Reply::json(200, json!({})))
                                }
                                None => Err(Error::InvalidGrant),
                            }
                        } else {
                            let pair = match fields.get("grant_type").map(String::as_str) {
                                Some("authorization_code") => (|| {
                                    self.exchange(
                                        field(&fields, "code")?,
                                        field(&fields, "redirect_uri")?,
                                        field(&fields, "code_verifier")?,
                                        fields.get("resource").map(String::as_str),
                                    )
                                })(),
                                Some("refresh_token") => match fields.get("refresh_token") {
                                    Some(token) => self.refresh(token).await,
                                    None => Err(Error::InvalidGrant),
                                },
                                _ => {
                                    return Reply::json(
                                        400,
                                        json!({"error":"unsupported_grant_type"}),
                                    )
                                }
                            };
                            pair.map(|p| Reply::json(200, serde_json::to_value(p).unwrap()))
                        }
                    }
                }
            }
            _ => Ok(Reply::json(405, json!({"error":"invalid_request"}))),
        };
        result.unwrap_or_else(Reply::failure)
    }
}
