use super::{Error, LivenessConfig};
use reqwest::{Client, Url};
use serde_json::Value;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Positive,
    Negative,
    Unavailable,
    Indeterminate,
}
impl Outcome {
    pub(crate) fn text(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::Negative => "negative",
            Self::Unavailable => "unavailable",
            Self::Indeterminate => "indeterminate",
        }
    }
}
pub struct Liveness {
    client: Client,
    config: LivenessConfig,
    token: String,
}
#[derive(Clone, Debug)]
pub(crate) enum Attribute {
    Null,
    Strings(Vec<String>),
    Date(i64),
    Unavailable,
}
fn date(value: &str) -> Option<i64> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|d| d.unix_timestamp())
}
pub(crate) fn decision(
    owner: &[Attribute; 3],
    canary: &[Attribute; 2],
    entry_visible: bool,
    group: &str,
    now: i64,
) -> Outcome {
    if matches!(&owner[0],Attribute::Date(t) if *t>now)
        || matches!(&owner[1],Attribute::Date(t) if *t<=now)
        || matches!(&owner[2],Attribute::Strings(groups) if !groups.iter().any(|g|g==group))
    {
        return Outcome::Negative;
    }
    if owner
        .iter()
        .chain(canary.iter())
        .any(|a| matches!(a, Attribute::Unavailable))
    {
        return Outcome::Unavailable;
    }
    if !entry_visible
        || matches!(owner[2], Attribute::Null)
        || canary.iter().any(|a| !matches!(a, Attribute::Date(_)))
    {
        return Outcome::Indeterminate;
    }
    Outcome::Positive
}
impl Liveness {
    pub fn new(config: &LivenessConfig) -> Result<Self, Error> {
        Self::new_with_root(config, None)
    }
    pub(crate) fn new_with_root(
        config: &LivenessConfig,
        root: Option<&std::path::Path>,
    ) -> Result<Self, Error> {
        let url = Url::parse(&config.api_url).map_err(|_| Error::Configuration)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(url.path(), "" | "/")
            || config.person.is_empty()
            || config.canary_person.is_empty()
            || !config.group.contains('@')
            || config.timeout_ms == 0
            || config.timeout_ms > 30000
        {
            return Err(Error::Configuration);
        }
        let token = super::private_text(&config.token_file)?;
        let mut builder =
            crate::webhook::https_client_builder(Duration::from_millis(config.timeout_ms))
                .no_proxy();
        if let Some(file) = root {
            let pem = std::fs::read(file).map_err(|_| Error::Configuration)?;
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&pem).map_err(|_| Error::Configuration)?,
            );
        }
        let client = builder.build().map_err(|_| Error::Configuration)?;
        Ok(Self {
            client,
            config: config.clone(),
            token,
        })
    }
    async fn get(&self, person: &str, attr: Option<&str>) -> Result<Value, Error> {
        let mut url = Url::parse(&self.config.api_url).map_err(|_| Error::Configuration)?;
        {
            let mut p = url.path_segments_mut().map_err(|_| Error::Configuration)?;
            p.clear().push("v1").push("person").push(person);
            if let Some(a) = attr {
                p.push("_attr").push(a);
            }
        }
        let mut response = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|_| Error::Unavailable)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::Unavailable);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
            if body.len() + chunk.len() > 65536 {
                return Err(Error::Unavailable);
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| Error::Unavailable)
    }
    async fn attribute(&self, person: &str, name: &str) -> Attribute {
        match self.get(person, Some(name)).await {
            Ok(Value::Null) => Attribute::Null,
            Ok(Value::Array(v)) if name == "memberof" && v.iter().all(Value::is_string) => {
                Attribute::Strings(v.iter().map(|x| x.as_str().unwrap().to_owned()).collect())
            }
            Ok(Value::Array(v)) if v.len() == 1 => v[0]
                .as_str()
                .and_then(date)
                .map(Attribute::Date)
                .unwrap_or(Attribute::Unavailable),
            _ => Attribute::Unavailable,
        }
    }
    pub async fn read(&self, now: i64) -> Outcome {
        let (valid, expire, member, canary_valid, canary_expire) = tokio::join!(
            self.attribute(&self.config.person, "account_valid_from"),
            self.attribute(&self.config.person, "account_expire"),
            self.attribute(&self.config.person, "memberof"),
            self.attribute(&self.config.canary_person, "account_valid_from"),
            self.attribute(&self.config.canary_person, "account_expire")
        );
        let owner = [valid, expire, member];
        let canary = [canary_valid, canary_expire];
        decision(&owner, &canary, true, &self.config.group, now)
    }
}
