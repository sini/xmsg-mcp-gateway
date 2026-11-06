use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use xmsg_mcp_gateway::xmsg_config::XmsgConfig;

pub struct Node {
    pub config: XmsgConfig,
    child: Child,
    _temp: tempfile::TempDir,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn private_file(file: &Path, body: &[u8]) {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(file)
        .unwrap()
        .write_all(body)
        .unwrap();
}

pub fn pinned_binary() -> PathBuf {
    let pin = include_str!("../../ci/xmsg-pin.toml");
    let revision = pin
        .lines()
        .find_map(|line| line.strip_prefix("revision = "))
        .expect("fixture revision missing")
        .trim_matches('"');
    let binary = PathBuf::from(
        std::env::var_os("XMSG_GATEWAY_BIN").expect("required pinned xmsg binary missing"),
    );
    assert!(binary.is_file(), "required pinned xmsg executable missing");
    let version = Command::new(&binary).arg("--version").output().unwrap();
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap().trim(),
        format!("xmsg 0.1.0+{revision}"),
        "wrong xmsg fixture revision"
    );
    binary
}

impl Node {
    pub async fn start(binary: &Path) -> Self {
        Self::start_with_service(binary, "gateway").await
    }

    pub async fn start_with_service(binary: &Path, service: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let run = temp.path().join("run");
        let sessions = temp.path().join("sessions");
        for directory in [&run, &sessions] {
            fs::create_dir(directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
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
        let cert_file = temp.path().join("node.pem");
        let key_file = temp.path().join("node-key.pem");
        private_file(&cert_file, certificate.pem().as_bytes());
        private_file(&key_file, key.serialize_pem().as_bytes());
        let config = XmsgConfig {
            service: service.into(),
            expected_node: "gateway.fixture".into(),
            daemon_uid: xmsg::client::current_uid(),
            register_socket: run.join("register.sock"),
            agent_socket: run.join("agent.sock"),
            max_frame_bytes: 1_048_576,
            operation_timeout_ms: 5000,
        };
        let child = Command::new(binary)
            .env_clear()
            .env("HOME", temp.path())
            .env("XDG_RUNTIME_DIR", &run)
            .env("RUST_LOG", "warn")
            .arg("serve")
            .arg("--db-path")
            .arg(temp.path().join("node.db"))
            .arg("--sessions-dir")
            .arg(sessions)
            .arg("--http-sock")
            .arg(run.join("http.sock"))
            .arg("--register-sock")
            .arg(&config.register_socket)
            .arg("--agent-sock")
            .arg(&config.agent_socket)
            .arg("--fed-cert")
            .arg(cert_file)
            .arg("--fed-key")
            .arg(key_file)
            .arg("--svc-exe")
            .arg(format!(
                "{service}={}",
                std::env::current_exe().unwrap().display()
            ))
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(temp.path().join("daemon.log"))
                    .unwrap(),
            ))
            .spawn()
            .unwrap();
        let mut node = Self {
            config,
            child,
            _temp: temp,
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        while !node.config.register_socket.exists() || !node.config.agent_socket.exists() {
            assert!(
                node.child.try_wait().unwrap().is_none(),
                "fixture daemon exited: {}",
                fs::read_to_string(node._temp.path().join("daemon.log")).unwrap()
            );
            assert!(
                Instant::now() < deadline,
                "fixture daemon readiness deadline"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        node
    }
}
