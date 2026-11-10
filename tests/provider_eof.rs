#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;
#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod serving_fixture;
use rustls::pki_types::pem::PemObject;
use std::io::Write;
fn exercise(partial: bool, stall: bool) {
    let fixture = serving_fixture::Fixture::new();
    let url = reqwest::Url::parse(
        fixture.config["verifier"]["introspection_url"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let cert = rustls::pki_types::CertificateDer::from_pem_slice(
        &std::fs::read(&fixture.keys.roots).unwrap(),
    )
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let conn = rustls::ClientConnection::new(
        std::sync::Arc::new(config),
        "provider.test".try_into().unwrap(),
    )
    .unwrap();
    let socket = std::net::TcpStream::connect(("127.0.0.1", url.port().unwrap())).unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    let mut tls = rustls::StreamOwned::new(conn, socket);

    let raw = if partial {
        "POST /introspect HTTP/1.1\r\nHost: provider.test\r\n"
    } else {
        "POST /introspect HTTP/1.1\r\nHost: provider.test\r\nauthorization: Basic bG9va3VwLWNsaWVudDpmaXh0dXJlLXNlY3JldA==\r\nContent-Length: 16\r\n\r\ntoken=good-token"
    };
    tls.write_all(raw.as_bytes()).unwrap();
    tls.flush().unwrap();
    if !stall {
        tls.conn.send_close_notify();
        tls.flush().unwrap();
    }

    if !partial {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while fixture.requests.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "complete TLS request did not reach the provider fixture"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert_eq!(
            fixture.requests.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }
    drop(fixture);
}

#[test]
#[should_panic(expected = "serving provider fixture worker panicked")]
fn partial_tls_eof_is_a_fixture_error() {
    exercise(true, false);
}

#[test]
#[should_panic(expected = "serving provider fixture worker panicked")]
fn partial_tls_stall_is_a_fixture_error() {
    exercise(true, true);
}

#[test]
fn complete_tls_request_releases_provider_fixture() {
    exercise(false, false);
}

#[test]
fn idle_cancelled_tls_connection_does_not_panic_the_provider_fixture() {
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::time::Duration;
    for close_without_bytes in [false, true] {
        let keys = provider::TlsFixture::new();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, _) = listener.accept().unwrap();
        let idle_client = if close_without_bytes {
            drop(client);
            None
        } else {
            Some(client)
        };
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            send.send(provider::read_request(socket, keys.tls.clone(), true).is_none())
                .unwrap();
        });
        assert!(receive
            .recv_timeout(Duration::from_secs(3))
            .expect("idle cancelled TLS connection panicked or failed to finish"));
        worker
            .join()
            .expect("provider fixture panicked on cancelled TLS");
        drop(idle_client);
    }
}
