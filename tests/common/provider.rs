use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rcgen::generate_simple_self_signed;
use rustls::pki_types::PrivatePkcs8KeyDer;
use xmsg_mcp_gateway::auth::{VerifiedIdentity, Verifier, VerifierConfig};
use xmsg_mcp_gateway::grants::Binding;

pub fn claims(binding: &Binding) -> serde_json::Value {
    serde_json::json!({"active": true, "iss": binding.issuer, "aud": binding.resource,
        "sub": binding.subject, "client_id": binding.hosted_client,
        "exp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 300,
        "scope": "identity:read"})
}

pub fn verify_response(
    binding: &Binding,
    body: serde_json::Value,
    status: u16,
) -> Result<VerifiedIdentity, xmsg_mcp_gateway::auth::Error> {
    network_case(binding, body, status, false, Duration::ZERO, 2000).0
}

pub fn network_case(
    binding: &Binding,
    body: serde_json::Value,
    status: u16,
    redirect: bool,
    stall: Duration,
    timeout_ms: u64,
) -> (
    Result<VerifiedIdentity, xmsg_mcp_gateway::auth::Error>,
    usize,
    Duration,
) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let certificate = generate_simple_self_signed(vec!["provider.test".into()]).unwrap();
    let roots = temp.path().join("root.pem");
    std::fs::write(&roots, certificate.cert.pem()).unwrap();
    let secret = temp.path().join("secret");
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(&secret)
        .unwrap()
        .write_all(b"fixture-secret")
        .unwrap();
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let tls = Arc::new(tls);
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let target_port = target.local_addr().unwrap().port();
    target.set_nonblocking(true).unwrap();
    let stopped = Arc::new(AtomicBool::new(false));
    let target_stopped = stopped.clone();
    let target_tls = tls.clone();
    let target_body = body.to_string();
    let target_server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match target.accept() {
                Ok((socket, _)) => {
                    serve(
                        socket,
                        target_tls,
                        &target_body,
                        200,
                        None,
                        Duration::ZERO,
                        false,
                    );
                    return 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if target_stopped.load(Ordering::SeqCst) {
                        return 0;
                    }
                    assert!(Instant::now() < deadline, "target fixture deadline");
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("target accept: {error}"),
            }
        }
    });
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let body = body.to_string();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("fixture accept: {error}"),
            }
        };
        let location = redirect.then(|| format!("https://provider.test:{target_port}/introspect"));
        serve(socket, tls, &body, status, location.as_deref(), stall, true);
    });
    let config = VerifierConfig {
        service: binding.service.clone(),
        issuer: binding.issuer.clone(),
        resource: binding.resource.clone(),
        subject: binding.subject.clone(),
        hosted_client: binding.hosted_client.clone(),
        introspection_url: format!("https://provider.test:{port}/introspect"),
        introspection_client: "lookup-client".into(),
        client_secret_file: secret,
        provider_addresses: vec![Ipv4Addr::LOCALHOST.into()],
        required_scopes: vec!["identity:read".into()],
        timeout_ms,
        root_certificate_file: Some(roots),
    };
    let verifier = Verifier::from_config(config).unwrap();
    let started = Instant::now();
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(verifier.verify("fixture-token"));
    let elapsed = started.elapsed();
    stopped.store(true, Ordering::SeqCst);
    server.join().unwrap();
    let target_requests = target_server.join().unwrap();
    (result, target_requests, elapsed)
}

pub fn verified(binding: &Binding) -> VerifiedIdentity {
    verify_response(binding, claims(binding), 200).unwrap()
}

fn serve(
    socket: TcpStream,
    tls: Arc<rustls::ServerConfig>,
    body: &str,
    status: u16,
    location: Option<&str>,
    stall: Duration,
    strict_request: bool,
) {
    // Accepted sockets inherit the listener's nonblocking flag on macOS.
    socket.set_nonblocking(false).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(tls).unwrap(), socket);
    let mut reader = BufReader::new(&mut tls);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    if strict_request {
        assert_eq!(line, "POST /introspect HTTP/1.1\r\n");
    }
    let mut length = 0;
    let mut lookup_auth = false;
    loop {
        line.clear();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-length:") {
            length = value.trim().parse().unwrap();
        }
        if lower.starts_with("authorization:") {
            assert_eq!(
                line.trim(),
                "authorization: Basic bG9va3VwLWNsaWVudDpmaXh0dXJlLXNlY3JldA=="
            );
            lookup_auth = true;
        }
    }
    let mut request = vec![0; length];
    reader.read_exact(&mut request).unwrap();
    if strict_request {
        assert!(lookup_auth);
        assert_eq!(
            String::from_utf8(request).unwrap(),
            "token=fixture-token&token_type_hint=access_token"
        );
    }
    drop(reader);
    thread::sleep(stall);
    let location = location
        .map(|value| format!("Location: {value}\r\n"))
        .unwrap_or_default();
    let written = write!(tls, "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\n{location}Connection: close\r\nContent-Type: application/json\r\n\r\n{body}", body.len()).and_then(|_| tls.flush());
    if stall.is_zero() {
        written.unwrap();
    }
}
