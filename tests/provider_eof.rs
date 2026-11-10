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

    if partial {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let phase = *fixture.provider_phase.lock().unwrap();
            if phase == "exited" || (!stall && phase == "headers") {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "partial request did not reach its strict parser stage"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
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

#[test]
fn cancelled_tls_before_http_does_not_panic_or_delay_shutdown() {
    for graceful in [false, true] {
        let mut fixture = serving_fixture::Fixture::new();
        let url = reqwest::Url::parse(
            fixture.config["verifier"]["introspection_url"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let certificate = rustls::pki_types::CertificateDer::from_pem_slice(
            &std::fs::read(&fixture.keys.roots).unwrap(),
        )
        .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut connection = rustls::ClientConnection::new(
            std::sync::Arc::new(config),
            "provider.test".try_into().unwrap(),
        )
        .unwrap();
        let mut socket = std::net::TcpStream::connect(("127.0.0.1", url.port().unwrap())).unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        while connection.is_handshaking() {
            connection.complete_io(&mut socket).unwrap();
        }
        let started = std::time::Instant::now();
        if graceful {
            connection.send_close_notify();
            connection.write_tls(&mut socket).unwrap();
        }
        drop(socket);
        fixture.stop_provider();
        assert_eq!(
            fixture.requests.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "cancelled pre-request client delayed fixture shutdown"
        );
        eprintln!(
            "cancelled-provider-control: graceful={graceful} elapsed_us={}",
            started.elapsed().as_micros()
        );
    }
}

fn tls_client(
    keys: &provider::TlsFixture,
    address: std::net::SocketAddr,
) -> rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream> {
    let certificate =
        rustls::pki_types::CertificateDer::from_pem_slice(&std::fs::read(&keys.roots).unwrap())
            .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connection = rustls::ClientConnection::new(
        std::sync::Arc::new(config),
        "provider.test".try_into().unwrap(),
    )
    .unwrap();
    let socket = std::net::TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    rustls::StreamOwned::new(connection, socket)
}

#[test]
fn complete_request_cancelled_response_write_is_quiet() {
    use std::net::{Shutdown, TcpListener};
    let keys = provider::TlsFixture::new();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let tls = keys.tls.clone();
    let (read_tx, read_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let (mut stream, request) = provider::read_request(socket, tls, true).unwrap();
        assert_eq!(request, "token=good-token");
        read_tx.send(()).unwrap();
        release_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        // A peer close alone may not fail a small buffered write. Force the write side closed after the complete-read barrier.
        stream.sock.shutdown(Shutdown::Write).unwrap();
        assert!(
            !provider::write_complete_response(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
            ),
            "forced closed write-half did not reach response fault path"
        );
    });
    let mut client = tls_client(&keys, address);
    client.write_all(b"POST /introspect HTTP/1.1\r\nHost: provider.test\r\nauthorization: Basic bG9va3VwLWNsaWVudDpmaXh0dXJlLXNlY3JldA==\r\nContent-Length: 16\r\n\r\ntoken=good-token").unwrap();
    client.flush().unwrap();
    read_rx
        .recv_timeout(std::time::Duration::from_secs(3))
        .unwrap();
    client.sock.shutdown(Shutdown::Read).unwrap();
    release_tx.send(()).unwrap();
    worker
        .join()
        .expect("post-complete cancellation panicked in response write");
    drop(client);
    struct ErrorWriter(std::io::ErrorKind);
    impl std::io::Write for ErrorWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(self.0))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    for kind in [
        std::io::ErrorKind::TimedOut,
        std::io::ErrorKind::WouldBlock,
        std::io::ErrorKind::PermissionDenied,
    ] {
        assert!(
            std::panic::catch_unwind(|| provider::write_complete_response(
                &mut ErrorWriter(kind),
                b"complete fixture response"
            ))
            .is_err(),
            "unexpected response failure was ignored: {kind:?}"
        );
    }
}

#[test]
fn active_partial_body_stop_is_strict_without_teardown_timeout() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::time::{Duration, Instant};
    let mut fixture = serving_fixture::Fixture::new();
    let url = reqwest::Url::parse(
        fixture.config["verifier"]["introspection_url"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let mut client = tls_client(
        &fixture.keys,
        format!("127.0.0.1:{}", url.port().unwrap())
            .parse()
            .unwrap(),
    );
    client.write_all(b"POST /introspect HTTP/1.1\r\nHost: provider.test\r\nauthorization: Basic bG9va3VwLWNsaWVudDpmaXh0dXJlLXNlY3JldA==\r\nContent-Length: 1024\r\n\r\nt").unwrap();
    client.flush().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while *fixture.provider_phase.lock().unwrap() != "body" {
        assert!(
            Instant::now() < deadline,
            "partial body did not reach read stage"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    let stop = Arc::new(AtomicBool::new(false));
    let client_stop = stop.clone();
    let writer = std::thread::spawn(move || {
        while !client_stop.load(Ordering::SeqCst) {
            if client.write_all(b"x").and_then(|_| client.flush()).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    let started = Instant::now();
    let outcome =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fixture.stop_provider()));
    let elapsed = started.elapsed();
    stop.store(true, Ordering::SeqCst);
    writer.join().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while *fixture.provider_phase.lock().unwrap() != "exited" {
        assert!(
            Instant::now() < deadline,
            "owned provider worker was left running"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    let panic = outcome.expect_err("partial HTTP body was silently accepted on stop");
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or("non-string panic");
    eprintln!(
        "active-provider-stop: stage=body elapsed_us={} panic={message}",
        elapsed.as_micros()
    );
    assert!(
        message.contains("serving provider fixture worker panicked"),
        "active I/O exceeded teardown instead of strict partial failure: {message}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "active I/O delayed teardown past existing bound"
    );
}
