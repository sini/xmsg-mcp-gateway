use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use xmsg::client::{ClientError, ClientOptions, RegisteredService};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XmsgConfig {
    pub service: String,
    pub expected_node: String,
    pub daemon_uid: u32,
    pub register_socket: PathBuf,
    pub agent_socket: PathBuf,
    #[serde(default = "default_frame_bytes")]
    pub max_frame_bytes: usize,
    #[serde(default = "default_timeout_ms")]
    pub operation_timeout_ms: u64,
}

fn default_frame_bytes() -> usize {
    1_048_576
}

fn default_timeout_ms() -> u64 {
    15_000
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentManifest {
    pub reply_ttl_secs: u64,
    pub idempotency_ttl_secs: u64,
    pub svc_queue_cap: usize,
    pub dedup_lifetime_secs: u64,
    /// Complete framed message including the gateway preamble, in bytes.
    pub max_framed_bytes: usize,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("declared reply TTL differs from the registered node's effective limit")]
    ReplyTtl,
    #[error("declared idempotency TTL differs from the registered node's effective limit")]
    IdempotencyTtl,
    #[error("declared service queue capacity differs from the registered node's effective limit")]
    QueueCapacity,
    #[error("dedup lifetime must be positive and no greater than the node's idempotency TTL")]
    DedupLifetime,
    #[error("complete framed bound must fit within the pinned and effective node byte limits")]
    TextBound,
}

impl DeploymentManifest {
    pub fn check(
        &self,
        effective_reply_ttl: Option<u64>,
        effective_idempotency_ttl: Option<u64>,
        effective_queue_cap: Option<usize>,
        effective_max_body: Option<usize>,
    ) -> Result<(), ManifestError> {
        if self.reply_ttl_secs == 0 || effective_reply_ttl != Some(self.reply_ttl_secs) {
            return Err(ManifestError::ReplyTtl);
        }
        if self.idempotency_ttl_secs == 0
            || effective_idempotency_ttl != Some(self.idempotency_ttl_secs)
        {
            return Err(ManifestError::IdempotencyTtl);
        }
        if self.svc_queue_cap == 0 || effective_queue_cap != Some(self.svc_queue_cap) {
            return Err(ManifestError::QueueCapacity);
        }
        if self.dedup_lifetime_secs == 0
            || self.dedup_lifetime_secs > self.idempotency_ttl_secs
            || self.dedup_lifetime_secs > i64::MAX as u64
        {
            return Err(ManifestError::DedupLifetime);
        }
        if self.max_framed_bytes == 0
            || self.max_framed_bytes > 65536
            || effective_max_body.is_none_or(|bound| self.max_framed_bytes > bound)
        {
            return Err(ManifestError::TextBound);
        }
        Ok(())
    }
}

impl XmsgConfig {
    pub fn validate(&self) -> Result<(), ClientError> {
        xmsg::client::validate_service_name(&self.service)
            .map_err(|_| ClientError::Configuration)?;
        if self.expected_node.trim().is_empty() {
            return Err(ClientError::Configuration);
        }
        Ok(())
    }

    pub async fn register(&self) -> Result<RegisteredService, ClientError> {
        self.validate()?;
        RegisteredService::register(ClientOptions {
            service: self.service.clone(),
            expected_node: Some(self.expected_node.clone()),
            daemon_uid: self.daemon_uid,
            register_socket: self.register_socket.clone(),
            agent_socket: self.agent_socket.clone(),
            max_frame_bytes: self.max_frame_bytes,
            operation_timeout: Duration::from_millis(self.operation_timeout_ms),
        })
        .await
    }
}
