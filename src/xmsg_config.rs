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
    10_000
}

impl XmsgConfig {
    pub async fn register(&self) -> Result<RegisteredService, ClientError> {
        if self.expected_node.trim().is_empty() {
            return Err(ClientError::Configuration);
        }
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
