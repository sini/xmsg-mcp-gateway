use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener};
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
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
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
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut tls = rustls::StreamOwned::new(
            rustls::ServerConnection::new(Arc::new(tls)).unwrap(),
            socket,
        );
        let mut reader = BufReader::new(&mut tls);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line, "POST /introspect HTTP/1.1\r\n");
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
        assert!(lookup_auth);
        let mut request = vec![0; length];
        reader.read_exact(&mut request).unwrap();
        assert_eq!(
            String::from_utf8(request).unwrap(),
            "token=fixture-token&token_type_hint=access_token"
        );
        drop(reader);
        let body = body.to_string();
        write!(tls, "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{body}", body.len()).unwrap();
        tls.flush().unwrap();
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
        timeout_ms: 2000,
        root_certificate_file: Some(roots),
    };
    let verifier = Verifier::from_config(config).unwrap();
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(verifier.verify("fixture-token"));
    server.join().unwrap();
    result
}

pub fn verified(binding: &Binding) -> VerifiedIdentity {
    verify_response(binding, claims(binding), 200).unwrap()
}
