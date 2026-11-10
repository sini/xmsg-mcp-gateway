//! Bounded callback delivery. Callbacks never share the provider's private-network policy.
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use reqwest::{Client, ClientBuilder, Url};

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_RESPONSE_BYTES: usize = 65_536;
pub const MAX_EVENT_BYTES: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid_callback_destination")]
    Destination,
    #[error("callback_timeout")]
    Timeout,
    #[error("callback_transport_failed")]
    Transport,
    #[error("callback_response_too_large")]
    ResponseTooLarge,
    #[error("callback_payload_invalid")]
    Payload,
    #[error("invalid_signing_secret")]
    Secret,
    #[error("callback_challenge_failed")]
    Challenge,
    #[error("callback_randomness_unavailable")]
    Random,
}

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
    pub retry_after: Option<String>,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .field("retry_after_present", &self.retry_after.is_some())
            .finish()
    }
}

pub fn retry_after_seconds(value: &str, now: SystemTime) -> Option<u64> {
    if value.len() > 128 {
        return None;
    }
    let value = value.trim();
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return value.parse().ok();
    }
    let date = httpdate::parse_http_date(value).ok()?;
    Some(date.duration_since(now).unwrap_or(Duration::ZERO).as_secs())
}

pub type PostFuture<'a> = Pin<Box<dyn Future<Output = Result<Response, Error>> + Send + 'a>>;

/// Test fixtures implement this interface; production configuration always uses `PublicHttps`.
pub trait Transport: Send + Sync {
    fn post<'a>(&'a self, url: &'a str, headers: HeaderMap, body: Vec<u8>) -> PostFuture<'a>;
}

/// Native roots include SSL_CERT_FILE/SSL_CERT_DIR via rustls-native-certs.
pub fn https_client_builder(timeout: Duration) -> ClientBuilder {
    Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
}

pub fn pinned_https_client_builder(
    host: &str,
    addresses: &[SocketAddr],
    timeout: Duration,
) -> ClientBuilder {
    https_client_builder(timeout)
        .no_proxy()
        .resolve_to_addrs(host, addresses)
}

pub fn callback_url(raw: &str) -> Result<Url, Error> {
    if raw.len() > 4096 || raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(Error::Destination);
    }
    let url = Url::parse(raw).map_err(|_| Error::Destination)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || raw.split_once("://").is_some_and(|(_, rest)| {
            rest.split(['/', '?', '#'])
                .next()
                .is_some_and(|authority| authority.contains('@'))
        })
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host_str().is_some_and(|host| host.contains('%'))
    {
        return Err(Error::Destination);
    }
    Ok(url)
}

fn v4_prefix(ip: Ipv4Addr, network: [u8; 4], bits: u32) -> bool {
    let mask = u32::MAX << (32 - bits);
    u32::from(ip) & mask == u32::from(Ipv4Addr::from(network)) & mask
}

fn v6_prefix(ip: Ipv6Addr, network: u128, bits: u32) -> bool {
    let mask = u128::MAX << (128 - bits);
    u128::from(ip) & mask == network & mask
}

pub fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ![
            ([0, 0, 0, 0], 8),
            ([10, 0, 0, 0], 8),
            ([100, 64, 0, 0], 10),
            ([127, 0, 0, 0], 8),
            ([169, 254, 0, 0], 16),
            ([172, 16, 0, 0], 12),
            ([192, 0, 0, 0], 24),
            ([192, 0, 2, 0], 24),
            ([192, 88, 99, 0], 24),
            ([192, 168, 0, 0], 16),
            ([198, 18, 0, 0], 15),
            ([198, 51, 100, 0], 24),
            ([203, 0, 113, 0], 24),
            ([224, 0, 0, 0], 4),
            ([240, 0, 0, 0], 4),
        ]
        .iter()
        .any(|(network, bits)| v4_prefix(ip, *network, *bits)),
        IpAddr::V6(ip) => {
            // Restrict to global unicast; this excludes mapped/compatible, NAT64, ULA and site-local.
            v6_prefix(ip, 0x2000u128 << 112, 3)
                && !v6_prefix(ip, 0x2001u128 << 112, 23)
                && !v6_prefix(ip, 0x20010db8u128 << 96, 32)
                && !v6_prefix(ip, 0x2002u128 << 112, 16)
                && !v6_prefix(ip, 0x3fffu128 << 112, 20)
        }
    }
}

fn checked_addresses(addresses: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, Error> {
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| !public_address(address.ip()))
    {
        return Err(Error::Destination);
    }
    Ok(addresses)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PublicHttps;

impl PublicHttps {
    async fn send(&self, raw: &str, headers: HeaderMap, body: Vec<u8>) -> Result<Response, Error> {
        if body.len() > MAX_EVENT_BYTES {
            return Err(Error::Payload);
        }
        let url = callback_url(raw)?;
        let host = url
            .host_str()
            .ok_or(Error::Destination)?
            .trim_matches(['[', ']']);
        let port = url.port_or_known_default().ok_or(Error::Destination)?;
        let addresses = match host.parse::<IpAddr>() {
            Ok(ip) => vec![SocketAddr::new(ip, port)],
            Err(_) => tokio::net::lookup_host((host, port))
                .await
                .map_err(|_| Error::Destination)?
                .collect(),
        };
        let addresses = checked_addresses(addresses)?;
        let client = pinned_https_client_builder(host, &addresses, REQUEST_TIMEOUT)
            .build()
            .map_err(|_| Error::Transport)?;
        let mut response = client
            .post(url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    Error::Timeout
                } else {
                    Error::Transport
                }
            })?;
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.len() <= 128)
            .map(str::to_owned);
        if response
            .content_length()
            .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
        {
            return Err(Error::ResponseTooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Transport)? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(Error::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Response {
            status,
            body,
            retry_after,
        })
    }
}

impl Transport for PublicHttps {
    fn post<'a>(&'a self, url: &'a str, headers: HeaderMap, body: Vec<u8>) -> PostFuture<'a> {
        Box::pin(async move {
            tokio::time::timeout(REQUEST_TIMEOUT, self.send(url, headers, body))
                .await
                .map_err(|_| Error::Timeout)?
        })
    }
}

pub fn validate_secret(secret: &str) -> Result<(), Error> {
    let key = secret.strip_prefix("whsec_").ok_or(Error::Secret)?;
    if key.len() > 88 {
        return Err(Error::Secret);
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(|_| Error::Secret)?;
    if !(24..=64).contains(&decoded.len()) {
        return Err(Error::Secret);
    }
    Ok(())
}

pub fn signed_headers(
    event_id: &str,
    subscription_id: &str,
    timestamp: i64,
    body: &[u8],
    current: &str,
    previous: Option<&str>,
) -> Result<HeaderMap, Error> {
    if body.len() > MAX_EVENT_BYTES
        || timestamp < 0
        || event_id.is_empty()
        || subscription_id.is_empty()
    {
        return Err(Error::Payload);
    }
    let mut signatures = Vec::new();
    for key in std::iter::once(current).chain(previous) {
        validate_secret(key)?;
        let signer = standardwebhooks::Webhook::new(key).map_err(|_| Error::Secret)?;
        signatures.push(
            signer
                .sign(event_id, timestamp, body)
                .map_err(|_| Error::Payload)?,
        );
    }
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    for (name, value) in [
        ("webhook-id", event_id.to_owned()),
        ("webhook-timestamp", timestamp.to_string()),
        ("webhook-signature", signatures.join(" ")),
        ("x-mcp-subscription-id", subscription_id.to_owned()),
    ] {
        headers.insert(
            name,
            HeaderValue::from_str(&value).map_err(|_| Error::Payload)?,
        );
    }
    Ok(headers)
}

pub fn signing_time() -> Result<i64, Error> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Payload)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| Error::Payload)
}

pub async fn signed_post(
    transport: &dyn Transport,
    url: &str,
    body: Vec<u8>,
    event_id: &str,
    subscription_id: &str,
    current: &str,
    previous: Option<&str>,
) -> Result<Response, Error> {
    let headers = signed_headers(
        event_id,
        subscription_id,
        signing_time()?,
        &body,
        current,
        previous,
    )?;
    tokio::time::timeout(REQUEST_TIMEOUT, transport.post(url, headers, body))
        .await
        .map_err(|_| Error::Timeout)?
}

pub async fn verify_callback(
    transport: &dyn Transport,
    url: &str,
    subscription_id: &str,
    secret: &str,
) -> Result<(), Error> {
    callback_url(url)?;
    validate_secret(secret)?;
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::Random)?;
    let challenge = base64::engine::general_purpose::STANDARD.encode(bytes);
    let body =
        serde_json::to_vec(&serde_json::json!({"type":"verification","challenge":challenge}))
            .map_err(|_| Error::Payload)?;
    let verification_id = format!(
        "verification_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    );
    let response = signed_post(
        transport,
        url,
        body,
        &verification_id,
        subscription_id,
        secret,
        None,
    )
    .await?;
    if !(200..300).contains(&response.status) || response.body.len() > MAX_RESPONSE_BYTES {
        return Err(Error::Challenge);
    }
    let value: serde_json::Value =
        serde_json::from_slice(&response.body).map_err(|_| Error::Challenge)?;
    let echo = value
        .get("challenge")
        .and_then(|value| value.as_str())
        .ok_or(Error::Challenge)?;
    if echo.len() != challenge.len()
        || echo
            .bytes()
            .zip(challenge.bytes())
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            != 0
    {
        return Err(Error::Challenge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_dns_answers_must_be_public() {
        let public = "8.8.8.8:443".parse().unwrap();
        let private = "127.0.0.1:443".parse().unwrap();
        assert!(checked_addresses(vec![public]).is_ok());
        assert!(checked_addresses(vec![public, private]).is_err());
        assert!(checked_addresses(vec![]).is_err());
    }
}
