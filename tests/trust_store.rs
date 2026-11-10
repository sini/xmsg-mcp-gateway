use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn roots_and_server() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    Arc<rustls::ServerConfig>,
) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let directory = tempfile::tempdir().unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["callback.test".into()]).unwrap();
    let root = directory.path().join("ca.pem");
    std::fs::write(&root, certificate.cert.pem()).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
    (directory, root, Arc::new(config))
}

fn serve(socket: TcpStream, config: Arc<rustls::ServerConfig>, redirect: bool) -> bool {
    socket.set_nonblocking(false).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), socket);
    let mut request = [0u8; 4096];
    let Ok(size) = tls.read(&mut request) else {
        return false;
    };
    if size == 0 {
        return false;
    }
    assert!(std::str::from_utf8(&request[..size])
        .unwrap()
        .contains("POST /probe"));
    if redirect {
        write!(tls,"HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:9/private\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").unwrap();
    } else {
        write!(
            tls,
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        )
        .unwrap();
    }
    tls.flush().unwrap();
    true
}

#[test]
fn native_roots_honor_file_and_directory_in_separate_processes() {
    let (directory, root, config) = roots_and_server();
    let (wrong_dir, wrong_root, _) = roots_and_server();
    for mode in ["file", "directory", "wrong-file", "native", "redirect"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let tls = config.clone();
        let thread = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(8);
            loop {
                match listener.accept() {
                    Ok((socket, _)) => return serve(socket, tls, mode == "redirect"),
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(error) => panic!("TLS accept: {error}"),
                }
            }
        });
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", "trust_store_child", "--nocapture"])
            .env("GATEWAY_TRUST_CHILD", mode)
            .env("GATEWAY_TRUST_PORT", address.port().to_string())
            .env_remove("SSL_CERT_FILE")
            .env_remove("SSL_CERT_DIR");
        match mode {
            "file" | "redirect" => {
                child.env("SSL_CERT_FILE", &root);
            }
            "directory" => {
                child.env("SSL_CERT_DIR", directory.path());
            }
            "wrong-file" => {
                child.env("SSL_CERT_FILE", &wrong_root);
            }
            _ => {}
        }
        let mut process = child.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(12);
        let status = loop {
            if let Some(status) = process.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                process.kill().unwrap();
                process.wait().unwrap();
                panic!("trust child exceeded budget");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success(), "{mode}");
        assert_eq!(
            thread.join().unwrap(),
            matches!(mode, "file" | "directory" | "redirect")
        );
    }
    drop(wrong_dir);
}

#[test]
fn trust_store_child() {
    let Ok(mode) = std::env::var("GATEWAY_TRUST_CHILD") else {
        return;
    };
    let port: u16 = std::env::var("GATEWAY_TRUST_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(async {
        let client = xmsg_mcp_gateway::webhook::pinned_https_client_builder(
            "callback.test",
            &[std::net::SocketAddr::from(([127, 0, 0, 1], port))],
            Duration::from_secs(3),
        )
        .build()
        .unwrap();
        client
            .post(format!("https://callback.test:{port}/probe"))
            .body("{}")
            .send()
            .await
    });
    assert_eq!(
        result.is_ok(),
        matches!(mode.as_str(), "file" | "directory" | "redirect"),
        "{mode}"
    );
    if mode == "redirect" {
        assert_eq!(result.unwrap().status(), reqwest::StatusCode::FOUND);
    }
}

#[test]
fn public_https_wires_the_shared_connection_pinning_seam() {
    let source = include_str!("../src/webhook.rs");
    let needle = "let client = pinned_https_client_builder(host, &addresses, REQUEST_TIMEOUT)";
    assert_eq!(
        source.matches(needle).count(),
        1,
        "PublicHttps must use the pinned connection builder exercised by the TLS fixture"
    );
}
