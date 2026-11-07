use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use xmsg_mcp_gateway::xmsg_config::XmsgConfig;

pub struct AgentStall {
    entered: Option<oneshot::Receiver<serde_json::Value>>,
    release: Option<oneshot::Sender<()>>,
    worker: Option<tokio::task::JoinHandle<()>>,
}

impl AgentStall {
    pub fn install(config: &XmsgConfig, action: &'static str) -> Self {
        let backend = config
            .agent_socket
            .with_file_name("agent.stall-backend.sock");
        std::fs::rename(&config.agent_socket, &backend).unwrap();
        let listener = UnixListener::bind(&config.agent_socket).unwrap();
        std::fs::set_permissions(&config.agent_socket, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let worker = tokio::spawn(async move {
            let mut entered = Some(entered_tx);
            let mut release = Some(release_rx);
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = BufReader::new(socket);
                let mut frame = String::new();
                socket.read_line(&mut frame).await.unwrap();
                let request: serde_json::Value = serde_json::from_str(&frame).unwrap();
                let mut upstream = BufReader::new(UnixStream::connect(&backend).await.unwrap());
                upstream
                    .get_mut()
                    .write_all(frame.as_bytes())
                    .await
                    .unwrap();
                let mut response = String::new();
                upstream.read_line(&mut response).await.unwrap();
                if request["action"] == action {
                    entered
                        .take()
                        .unwrap()
                        .send(serde_json::from_str(&response).unwrap())
                        .unwrap();
                    release.take().unwrap().await.unwrap();
                    return;
                }
                socket
                    .get_mut()
                    .write_all(response.as_bytes())
                    .await
                    .unwrap();
            }
        });
        Self {
            entered: Some(entered_rx),
            release: Some(release_tx),
            worker: Some(worker),
        }
    }

    pub async fn reached(&mut self) -> serde_json::Value {
        self.entered.take().unwrap().await.unwrap()
    }

    pub async fn finish(mut self) {
        self.release.take().unwrap().send(()).unwrap();
        self.worker.take().unwrap().await.unwrap();
    }
}

impl Drop for AgentStall {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
    }
}
