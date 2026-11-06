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
    federated: bool,
    port: u16,
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
    let revisions: Vec<_> = pin
        .lines()
        .filter_map(|line| {
            line.strip_prefix("revision = ")
                .or_else(|| line.strip_prefix("baseline_revision = "))
        })
        .map(|line| line.trim_matches('"'))
        .collect();
    let revision =
        std::env::var("XMSG_GATEWAY_REVISION").unwrap_or_else(|_| revisions[0].to_owned());
    assert!(
        revisions.contains(&revision.as_str()),
        "unapproved xmsg fixture revision"
    );
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

pub struct Authority {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    pem: String,
}
impl Authority {
    pub fn generate() -> Self {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let pem = params.self_signed(&key).unwrap().pem();
        Self { params, key, pem }
    }
}

pub struct Prepared {
    pub config: XmsgConfig,
    pub port: u16,
    pub uri: String,
    temp: tempfile::TempDir,
    federated: bool,
}
impl Prepared {
    pub fn create(service: &str, user: &str, authority: Option<&Authority>) -> Self {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let run = temp.path().join("run");
        let sessions = temp.path().join("sessions");
        for directory in [&run, &sessions] {
            fs::create_dir(directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let uri = format!("spiffe://example.test/host/fixture/user/{user}");
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::URI(uri.clone().try_into().unwrap())];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let certificate = match authority {
            Some(ca) => params
                .signed_by(&key, &rcgen::Issuer::from_params(&ca.params, &ca.key))
                .unwrap(),
            None => params.self_signed(&key).unwrap(),
        };
        private_file(&temp.path().join("node.pem"), certificate.pem().as_bytes());
        private_file(
            &temp.path().join("node-key.pem"),
            key.serialize_pem().as_bytes(),
        );
        if let Some(ca) = authority {
            private_file(&temp.path().join("ca.pem"), ca.pem.as_bytes());
        }
        let config = XmsgConfig {
            service: service.into(),
            expected_node: format!("{user}.fixture"),
            daemon_uid: xmsg::client::current_uid(),
            register_socket: run.join("register.sock"),
            agent_socket: run.join("agent.sock"),
            max_frame_bytes: 1_048_576,
            operation_timeout_ms: 5000,
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        Self {
            config,
            port,
            uri,
            temp,
            federated: authority.is_some(),
        }
    }
    pub fn peer(&self, other: &Self, grants: serde_json::Value) {
        let mut peer = serde_json::json!({"address":format!("127.0.0.1:{}",other.port),
            "ca":self.temp.path().join("ca.pem"), "identities":[other.uri],
            "allow":["list","send","reply"], "principals":[other.config.service],
            "targets":[self.config.service], "from":["127.0.0.1/32"]});
        for (key, value) in grants.as_object().unwrap() {
            peer[key] = value.clone();
        }
        let peers = serde_json::json!({"peers":{other.config.expected_node.clone():peer}});
        private_file(
            &self.temp.path().join("peers.json"),
            peers.to_string().as_bytes(),
        );
    }
    pub async fn launch(self, binary: &Path) -> Node {
        let mut launch = command(binary, self.temp.path(), self.federated, self.port);
        launch.arg("--svc-exe").arg(format!(
            "{}={}",
            self.config.service,
            std::env::current_exe().unwrap().display()
        ));
        let mut node = Node {
            config: self.config,
            child: launch.spawn().unwrap(),
            _temp: self.temp,
            federated: self.federated,
            port: self.port,
        };
        node.ready().await;
        node
    }
}

fn command(binary: &Path, directory: &Path, federated: bool, port: u16) -> Command {
    let run = directory.join("run");
    let mut command = Command::new(binary);
    command
        .env_clear()
        .env("HOME", directory)
        .env("XDG_RUNTIME_DIR", &run)
        .env("RUST_LOG", "warn")
        .arg("serve")
        .arg("--db-path")
        .arg(directory.join("node.db"))
        .arg("--sessions-dir")
        .arg(directory.join("sessions"))
        .arg("--http-sock")
        .arg(run.join("http.sock"))
        .arg("--register-sock")
        .arg(run.join("register.sock"))
        .arg("--agent-sock")
        .arg(run.join("agent.sock"))
        .arg("--fed-cert")
        .arg(directory.join("node.pem"))
        .arg("--fed-key")
        .arg(directory.join("node-key.pem"))
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(directory.join("daemon.log"))
                .unwrap(),
        ));
    if federated {
        command
            .arg("--peers-file")
            .arg(directory.join("peers.json"))
            .arg("--fed-listen")
            .arg(format!("127.0.0.1:{port}"));
    }
    command
}

impl Node {
    pub async fn start(binary: &Path) -> Self {
        Self::start_with_service(binary, "gateway").await
    }

    pub async fn start_with_service(binary: &Path, service: &str) -> Self {
        Prepared::create(service, "gateway", None)
            .launch(binary)
            .await
    }
    pub async fn restart(&mut self, binary: &Path) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        for name in ["register.sock", "agent.sock", "http.sock"] {
            let socket = self._temp.path().join("run").join(name);
            if socket.exists() {
                fs::remove_file(socket).unwrap();
            }
        }
        let mut launch = command(binary, self._temp.path(), self.federated, self.port);
        launch.arg("--svc-exe").arg(format!(
            "{}={}",
            self.config.service,
            std::env::current_exe().unwrap().display()
        ));
        self.child = launch.spawn().unwrap();
        self.ready().await;
    }
    async fn ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while !self.config.register_socket.exists() || !self.config.agent_socket.exists() {
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "fixture daemon exited: {}",
                fs::read_to_string(self._temp.path().join("daemon.log")).unwrap()
            );
            assert!(
                Instant::now() < deadline,
                "fixture daemon readiness deadline"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
