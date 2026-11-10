//! Unix-only real daemon fixture: no socket activation or unsafe pre-exec hook.
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use xmsg_mcp_gateway::xmsg_config::XmsgConfig;

pub fn pinned_binary() -> PathBuf {
    let revision = include_str!("../../ci/xmsg-pin.toml")
        .lines()
        .find_map(|line| line.strip_prefix("revision = "))
        .unwrap()
        .trim_matches('"');
    let binary = PathBuf::from(
        std::env::var_os("XMSG_GATEWAY_BIN").expect("required pinned xmsg binary missing"),
    );
    let result = Command::new(&binary).arg("--version").output().unwrap();
    assert!(result.status.success());
    assert_eq!(
        String::from_utf8(result.stdout).unwrap().trim(),
        format!("xmsg 0.1.0+{revision}")
    );
    binary
}
pub struct Node {
    pub config: XmsgConfig,
    child: Child,
    _directory: tempfile::TempDir,
}
fn private_file(file: &Path, bytes: &[u8]) {
    std::fs::write(file, bytes).unwrap();
    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
}
impl Node {
    pub async fn start(binary: &Path) -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let run = directory.path().join("run");
        let sessions = directory.path().join("sessions");
        for dir in [&run, &sessions] {
            std::fs::create_dir(dir).unwrap();
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            "spiffe://example.test/host/fixture/user/gateway"
                .try_into()
                .unwrap(),
        )];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let certificate = params.self_signed(&key).unwrap();
        let cert = directory.path().join("cert.pem");
        let secret = directory.path().join("key.pem");
        let peers = directory.path().join("peers.json");
        private_file(&cert, certificate.pem().as_bytes());
        private_file(&secret, key.serialize_pem().as_bytes());
        private_file(&peers, b"{\"peers\":{}}");
        let config = XmsgConfig {
            service: "gateway".into(),
            expected_node: "gateway.fixture".into(),
            daemon_uid: xmsg::client::current_uid(),
            register_socket: run.join("register.sock"),
            agent_socket: run.join("agent.sock"),
            max_frame_bytes: 1048576,
            operation_timeout_ms: 5000,
        };
        let log = std::fs::File::create(directory.path().join("daemon.log")).unwrap();
        let child = Command::new(binary)
            .env_clear()
            .env("XDG_CONFIG_HOME", directory.path())
            .env("XDG_DATA_HOME", directory.path())
            .env("XDG_RUNTIME_DIR", &run)
            .arg("serve")
            .args(["--reply-ttl", "604800", "--max-body", "65536", "--db-path"])
            .arg(directory.path().join("node.db"))
            .arg("--sessions-dir")
            .arg(sessions)
            .arg("--http-sock")
            .arg(run.join("http.sock"))
            .arg("--register-sock")
            .arg(&config.register_socket)
            .arg("--agent-sock")
            .arg(&config.agent_socket)
            .arg("--fed-cert")
            .arg(cert)
            .arg("--fed-key")
            .arg(secret)
            .arg("--peers-file")
            .arg(peers)
            .arg("--svc-exe")
            .arg(format!(
                "gateway={}",
                std::env::current_exe().unwrap().display()
            ))
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let mut node = Self {
            config,
            child,
            _directory: directory,
        };
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            while !node.config.agent_socket.exists() || !node.config.register_socket.exists() {
                assert!(
                    node.child.try_wait().unwrap().is_none(),
                    "fixture exited: {}",
                    std::fs::read_to_string(node._directory.path().join("daemon.log")).unwrap()
                );
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        node
    }
    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
    }
}
