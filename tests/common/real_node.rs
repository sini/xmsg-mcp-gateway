use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use xmsg_mcp_gateway::xmsg_config::XmsgConfig;

pub struct Node {
    pub config: XmsgConfig,
    child: Child,
    _temp: tempfile::TempDir,
    listener: Option<std::net::TcpListener>,
    notify: Option<tokio::net::UnixDatagram>,
    reply_ttl_secs: u64,
    max_body_bytes: usize,
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
    listener: Option<std::net::TcpListener>,
    reply_ttl_secs: u64,
    max_body_bytes: usize,
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
        let listener = authority.map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap());
        let port = listener
            .as_ref()
            .map_or(0, |socket| socket.local_addr().unwrap().port());
        Self {
            config,
            port,
            uri,
            temp,
            listener,
            reply_ttl_secs: 604800,
            max_body_bytes: 65536,
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
        let baseline = include_str!("../../ci/xmsg-pin.toml")
            .lines()
            .find_map(|line| line.strip_prefix("baseline_revision = "))
            .unwrap()
            .trim_matches('"');
        let version = Command::new(binary).arg("--version").output().unwrap();
        assert!(version.status.success());
        let legacy =
            String::from_utf8(version.stdout).unwrap().trim() == format!("xmsg 0.1.0+{baseline}");
        assert!(
            !legacy || self.listener.is_none(),
            "baseline has only Unix-socket compatibility cells"
        );
        let notify = (!legacy).then(|| {
            tokio::net::UnixDatagram::bind(self.temp.path().join("run/notify.sock")).unwrap()
        });
        let mut launch = command(
            binary,
            self.temp.path(),
            self.listener.as_ref(),
            notify.is_some(),
            self.reply_ttl_secs,
            self.max_body_bytes,
        );
        launch.arg("--svc-exe").arg(format!(
            "{}={}",
            self.config.service,
            std::env::current_exe().unwrap().display()
        ));
        let mut node = Node {
            config: self.config,
            child: launch.spawn().unwrap(),
            _temp: self.temp,
            listener: self.listener,
            notify,
            reply_ttl_secs: self.reply_ttl_secs,
            max_body_bytes: self.max_body_bytes,
        };
        node.ready().await;
        node
    }
}

fn command(
    binary: &Path,
    directory: &Path,
    listener: Option<&std::net::TcpListener>,
    notify: bool,
    reply_ttl_secs: u64,
    max_body_bytes: usize,
) -> Command {
    let run = directory.join("run");
    let mut command = if listener.is_some() {
        let mut shell = Command::new("/bin/sh");
        shell
            .args([
                "-c",
                "LISTEN_PID=$$; export LISTEN_PID; exec \"$@\"",
                "gateway-test-node",
            ])
            .arg(binary);
        shell
    } else {
        Command::new(binary)
    };
    command
        .env_clear()
        .env("HOME", directory)
        .env("XDG_RUNTIME_DIR", &run)
        .env("RUST_LOG", "warn")
        .arg("serve")
        .arg("--reply-ttl")
        .arg(reply_ttl_secs.to_string())
        .arg("--max-body")
        .arg(max_body_bytes.to_string())
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
    if notify {
        command.env("NOTIFY_SOCKET", run.join("notify.sock"));
    }
    if let Some(listener) = listener {
        let descriptor = listener.as_raw_fd();
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(descriptor, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command
            .env("LISTEN_FDS", "1")
            .env("LISTEN_FDNAMES", "fed")
            .arg("--peers-file")
            .arg(directory.join("peers.json"))
            .arg("--fed-listen")
            .arg(listener.local_addr().unwrap().to_string());
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
    #[allow(dead_code)]
    pub async fn start_with_reply_ttl(binary: &Path, reply_ttl_secs: u64) -> Self {
        let mut prepared = Prepared::create("gateway", "gateway", None);
        prepared.reply_ttl_secs = reply_ttl_secs;
        prepared.launch(binary).await
    }
    #[allow(dead_code)]
    pub async fn start_with_max_body(binary: &Path, bytes: usize) -> Self {
        let mut prepared = Prepared::create("gateway", "gateway", None);
        prepared.max_body_bytes = bytes;
        prepared.launch(binary).await
    }
    #[allow(dead_code)]
    pub async fn restart_with_reply_ttl(&mut self, binary: &Path, seconds: u64) {
        self.reply_ttl_secs = seconds;
        self.restart(binary).await;
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
        let mut launch = command(
            binary,
            self._temp.path(),
            self.listener.as_ref(),
            self.notify.is_some(),
            self.reply_ttl_secs,
            self.max_body_bytes,
        );
        launch.arg("--svc-exe").arg(format!(
            "{}={}",
            self.config.service,
            std::env::current_exe().unwrap().display()
        ));
        self.child = launch.spawn().unwrap();
        self.ready().await;
    }
    async fn ready(&mut self) {
        if let Some(notify) = &self.notify {
            let mut message = [0; 4096];
            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    let count = notify.recv(&mut message).await.unwrap();
                    if message[..count]
                        .split(|byte| *byte == b'\n')
                        .any(|field| field == b"READY=1")
                    {
                        break;
                    }
                }
            })
            .await
            .expect("fixture daemon sd_notify readiness deadline");
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "fixture daemon exited after readiness"
            );
            return;
        }
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
