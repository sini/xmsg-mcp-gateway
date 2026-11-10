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

pub struct TlsFixture {
    pub _directory: tempfile::TempDir,
    pub roots: std::path::PathBuf,
    pub secret: std::path::PathBuf,
    pub tls: Arc<rustls::ServerConfig>,
}

impl TlsFixture {
    pub fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let temp = tempfile::tempdir().unwrap();
        let certificate = generate_simple_self_signed(vec![
            "provider.test".into(),
            "localhost".into(),
            "127.0.0.1".into(),
        ])
        .unwrap();
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
        TlsFixture {
            _directory: temp,
            roots,
            secret,
            tls,
        }
    }
}

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
    network_case_audience(binding, body, status, redirect, stall, timeout_ms, None)
}

#[allow(dead_code)]
pub fn verify_response_with_audience(
    binding: &Binding,
    body: serde_json::Value,
    audience: &str,
) -> Result<VerifiedIdentity, xmsg_mcp_gateway::auth::Error> {
    network_case_audience(
        binding,
        body,
        200,
        false,
        Duration::ZERO,
        2000,
        Some(audience),
    )
    .0
}

fn network_case_audience(
    binding: &Binding,
    body: serde_json::Value,
    status: u16,
    redirect: bool,
    stall: Duration,
    timeout_ms: u64,
    audience: Option<&str>,
) -> (
    Result<VerifiedIdentity, xmsg_mcp_gateway::auth::Error>,
    usize,
    Duration,
) {
    let fixture = TlsFixture::new();
    let roots = fixture.roots.clone();
    let secret = fixture.secret.clone();
    let tls = fixture.tls.clone();
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
    let mut raw = serde_json::json!({
        "service":binding.service,"issuer":binding.issuer,"resource":binding.resource,
        "subject":binding.subject,"hosted_client":binding.hosted_client,
        "introspection_url":format!("https://provider.test:{port}/introspect"),
        "introspection_client":"lookup-client","client_secret_file":secret,
        "provider_addresses":["127.0.0.1"],"required_scopes":["identity:read"],
        "timeout_ms":timeout_ms,"root_certificate_file":roots
    });
    if let Some(audience) = audience {
        raw["audience"] = audience.into();
    }
    let verifier = Verifier::from_config(
        serde_json::from_value(raw).expect("audience configuration must deserialize"),
    )
    .unwrap();
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

#[allow(dead_code)]
pub fn verify_pin_and_proxy_policy(binding: &Binding) {
    let fixture = TlsFixture::new();
    let body = claims(binding).to_string();

    // 1. Unpinned provider authenticates directly (including IP literal / localhost).
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let tls = fixture.tls.clone();
    let response_body = body.clone();
    let server = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        serve(socket, tls, &response_body, 200, None, Duration::ZERO, true);
    });
    let unpinned_config = VerifierConfig {
        service: binding.service.clone(),
        issuer: binding.issuer.clone(),
        resource: binding.resource.clone(),
        audience: None,
        subject: binding.subject.clone(),
        hosted_client: binding.hosted_client.clone(),
        introspection_url: format!("https://127.0.0.1:{port}/introspect"),
        introspection_client: "lookup-client".into(),
        client_secret_file: fixture.secret.clone(),
        provider_addresses: Vec::new(),
        required_scopes: vec!["identity:read".into()],
        timeout_ms: 2000,
        root_certificate_file: Some(fixture.roots.clone()),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let unpinned = Verifier::from_config(unpinned_config).expect("unpinned config should load");
    let identity = runtime
        .block_on(unpinned.verify("fixture-token"))
        .expect("unpinned provider should authenticate");
    assert_eq!(identity.subject(), binding.subject);
    server.join().unwrap();

    // 2. Configured pin mismatch refuses connection even when the hostname resolves to a live listener.
    let mismatch_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mismatch_port = mismatch_listener.local_addr().unwrap().port();
    mismatch_listener.set_nonblocking(true).unwrap();
    let mismatch_stopped = Arc::new(AtomicBool::new(false));
    let mismatch_flag = mismatch_stopped.clone();
    let mismatch_tls = fixture.tls.clone();
    let mismatch_body = body.clone();
    let mismatch_server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match mismatch_listener.accept() {
                Ok((socket, _)) => {
                    serve(
                        socket,
                        mismatch_tls,
                        &mismatch_body,
                        200,
                        None,
                        Duration::ZERO,
                        true,
                    );
                    return 1usize;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if mismatch_flag.load(Ordering::SeqCst) {
                        return 0usize;
                    }
                    assert!(Instant::now() < deadline, "mismatch fixture deadline");
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("mismatch accept: {error}"),
            }
        }
    });
    let mismatch_config = VerifierConfig {
        service: binding.service.clone(),
        issuer: binding.issuer.clone(),
        resource: binding.resource.clone(),
        audience: None,
        subject: binding.subject.clone(),
        hosted_client: binding.hosted_client.clone(),
        introspection_url: format!("https://localhost:{mismatch_port}/introspect"),
        introspection_client: "lookup-client".into(),
        client_secret_file: fixture.secret.clone(),
        provider_addresses: vec![Ipv4Addr::new(127, 0, 0, 2).into()],
        required_scopes: vec!["identity:read".into()],
        timeout_ms: 500,
        root_certificate_file: Some(fixture.roots.clone()),
    };
    let mismatched = Verifier::from_config(mismatch_config).unwrap();
    let mismatch_result = runtime.block_on(mismatched.verify("fixture-token"));
    mismatch_stopped.store(true, Ordering::SeqCst);
    let mismatch_requests = mismatch_server.join().unwrap();
    assert!(
        matches!(
            mismatch_result,
            Err(xmsg_mcp_gateway::auth::Error::Unavailable)
        ) && mismatch_requests == 0,
        "accepted mismatched provider pin"
    );

    // 3. With no pins and HTTPS_PROXY set, provider request traverses the local fixture proxy;
    //    when pins ARE configured, .no_proxy() bypasses HTTPS_PROXY.
    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    let proxy_tls = fixture.tls.clone();
    let proxy_body = body.clone();
    let proxy_server = thread::spawn(move || {
        let (mut socket, _) = proxy_listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(&mut socket);
        let mut connect_line = String::new();
        reader.read_line(&mut connect_line).unwrap();
        assert!(
            connect_line.starts_with("CONNECT provider.test:443 HTTP/1.1"),
            "unexpected proxy request: {connect_line}"
        );
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).unwrap();
            if header == "\r\n" || header.is_empty() {
                break;
            }
        }
        drop(reader);
        socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        socket.flush().unwrap();
        serve(
            socket,
            proxy_tls,
            &proxy_body,
            200,
            None,
            Duration::ZERO,
            true,
        );
        1usize
    });

    let direct_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let direct_port = direct_listener.local_addr().unwrap().port();
    let direct_tls = fixture.tls.clone();
    let direct_body = body;
    let direct_server = thread::spawn(move || {
        let (socket, _) = direct_listener.accept().unwrap();
        serve(
            socket,
            direct_tls,
            &direct_body,
            200,
            None,
            Duration::ZERO,
            true,
        );
        1usize
    });

    let prev_https = std::env::var_os("HTTPS_PROXY");
    let prev_no = std::env::var_os("NO_PROXY");
    std::env::set_var("HTTPS_PROXY", format!("http://127.0.0.1:{proxy_port}"));
    std::env::remove_var("NO_PROXY");
    let proxied_unpinned = Verifier::from_config(VerifierConfig {
        service: binding.service.clone(),
        issuer: binding.issuer.clone(),
        resource: binding.resource.clone(),
        audience: None,
        subject: binding.subject.clone(),
        hosted_client: binding.hosted_client.clone(),
        introspection_url: "https://provider.test/introspect".into(),
        introspection_client: "lookup-client".into(),
        client_secret_file: fixture.secret.clone(),
        provider_addresses: Vec::new(),
        required_scopes: vec!["identity:read".into()],
        timeout_ms: 2000,
        root_certificate_file: Some(fixture.roots.clone()),
    });
    let pinned_direct = Verifier::from_config(VerifierConfig {
        service: binding.service.clone(),
        issuer: binding.issuer.clone(),
        resource: binding.resource.clone(),
        audience: None,
        subject: binding.subject.clone(),
        hosted_client: binding.hosted_client.clone(),
        introspection_url: format!("https://provider.test:{direct_port}/introspect"),
        introspection_client: "lookup-client".into(),
        client_secret_file: fixture.secret,
        provider_addresses: vec![Ipv4Addr::LOCALHOST.into()],
        required_scopes: vec!["identity:read".into()],
        timeout_ms: 2000,
        root_certificate_file: Some(fixture.roots),
    });
    match prev_https {
        Some(val) => std::env::set_var("HTTPS_PROXY", val),
        None => std::env::remove_var("HTTPS_PROXY"),
    }
    match prev_no {
        Some(val) => std::env::set_var("NO_PROXY", val),
        None => std::env::remove_var("NO_PROXY"),
    }

    let proxied_verifier = proxied_unpinned.expect("unpinned proxy config should build");
    let proxied_identity = runtime
        .block_on(proxied_verifier.verify("fixture-token"))
        .expect("unpinned provider request should succeed through HTTPS_PROXY");
    assert_eq!(proxied_identity.subject(), binding.subject);
    assert_eq!(
        proxy_server.join().unwrap(),
        1,
        "unpinned provider request did not traverse HTTPS_PROXY"
    );

    let direct_verifier = pinned_direct.expect("pinned config should build");
    let direct_identity = runtime
        .block_on(direct_verifier.verify("fixture-token"))
        .expect("pinned provider request should bypass HTTPS_PROXY and connect directly");
    assert_eq!(direct_identity.subject(), binding.subject);
    assert_eq!(
        direct_server.join().unwrap(),
        1,
        "pinned provider request did not connect directly"
    );
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
    let Some((mut tls, request)) = read_request(socket, tls, strict_request) else {
        return;
    };
    if strict_request {
        assert_eq!(request, "token=fixture-token&token_type_hint=access_token");
    }
    thread::sleep(stall);
    let location = location
        .map(|value| format!("Location: {value}\r\n"))
        .unwrap_or_default();
    let written = write!(tls, "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\n{location}Connection: close\r\nContent-Type: application/json\r\n\r\n{body}", body.len()).and_then(|_| tls.flush());
    if stall.is_zero() {
        written.unwrap();
    }
}

pub type TlsStream = rustls::StreamOwned<rustls::ServerConnection, TcpStream>;

pub fn read_request(
    socket: TcpStream,
    tls: Arc<rustls::ServerConfig>,
    strict_request: bool,
) -> Option<(TlsStream, String)> {
    // Accepted sockets inherit the listener's nonblocking flag on macOS.
    socket.set_nonblocking(false).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut first_byte = [0];
    match socket.peek(&mut first_byte) {
        Ok(0) => return None,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            return None
        }
        Ok(_) => {}
        Err(error) => panic!("provider fixture initial read failed: {error}"),
    }
    let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(tls).unwrap(), socket);
    let mut reader = BufReader::new(&mut tls);
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => return None,
        Err(error)
            if line.is_empty()
                && matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                ) =>
        {
            return None
        }
        Err(error) => panic!("provider fixture request line failed: {error}"),
        Ok(_) => {}
    }
    if strict_request {
        assert_eq!(line, "POST /introspect HTTP/1.1\r\n");
    }
    let mut length = 0;
    let mut lookup_auth = false;
    loop {
        line.clear();
        assert_ne!(
            reader.read_line(&mut line).unwrap(),
            0,
            "partial provider request ended during headers"
        );
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
    }
    drop(reader);
    Some((tls, String::from_utf8(request).unwrap()))
}
