use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::{json, Value};
use xmsg_mcp_gateway::auth::{Error, ProfileConfig, Verifier, VerifierConfig, MAX_PROFILES};

#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;

struct Server {
    fixture: provider::TlsFixture,
    port: u16,
    calls: Arc<AtomicUsize>,
    headers: Arc<Mutex<Vec<String>>>,
    response: Arc<Mutex<(u16, Value)>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

fn configure_fixture_socket(socket: &TcpStream) {
    socket.set_nonblocking(false).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
}

#[cfg(unix)]
#[test]
fn accepted_fixture_socket_waits_for_delayed_bytes_with_inherited_nonblocking_flag() {
    use std::os::fd::AsRawFd;
    use std::sync::mpsc::{self, RecvTimeoutError};
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut socket, _) = listener.accept().unwrap();
    socket.set_nonblocking(true).unwrap();
    let flags = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFL) };
    assert!(
        flags >= 0 && flags & libc::O_NONBLOCK != 0,
        "forced nonblocking control failed"
    );
    configure_fixture_socket(&socket);
    let flags = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFL) };
    assert!(
        flags >= 0 && flags & libc::O_NONBLOCK == 0,
        "accepted fixture socket retained inherited nonblocking mode"
    );
    let (started_tx, started_rx) = mpsc::sync_channel(0);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        started_tx.send(()).unwrap();
        let mut byte = [0];
        done_tx
            .send(socket.read_exact(&mut byte).map(|()| byte))
            .unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(matches!(
        done_rx.recv_timeout(Duration::from_millis(20)),
        Err(RecvTimeoutError::Timeout)
    ));
    client.write_all(b"x").unwrap();
    assert_eq!(
        done_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap(),
        *b"x"
    );
    reader.join().unwrap();
}

impl Server {
    fn new(issuer: &str, client: &str, audience: &str) -> Self {
        let fixture = provider::TlsFixture::new();
        std::fs::write(&fixture.secret, format!("fixture-secret-{client}")).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let headers = Arc::new(Mutex::new(Vec::new()));
        let response = Arc::new(Mutex::new((200, claims(issuer, client, audience))));
        let stop = Arc::new(AtomicBool::new(false));
        let tls = fixture.tls.clone();
        let (thread_calls, thread_headers, thread_response, thread_stop) = (
            calls.clone(),
            headers.clone(),
            response.clone(),
            stop.clone(),
        );
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                let socket = match listener.accept() {
                    Ok((socket, _)) => socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                };
                configure_fixture_socket(&socket);
                let connection = rustls::ServerConnection::new(tls.clone()).unwrap();
                let stream = rustls::StreamOwned::new(connection, socket);
                let mut stream = BufReader::new(stream);
                let mut headers = String::new();
                loop {
                    let mut line = String::new();
                    stream.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    assert!(!line.is_empty(), "fixture request headers truncated");
                    headers.push_str(&line);
                }
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                thread_headers.lock().unwrap().push(headers);
                thread_calls.fetch_add(1, Ordering::SeqCst);
                let (status, body) = thread_response.lock().unwrap().clone();
                let body = body.to_string();
                write!(stream.get_mut(), "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                stream.get_mut().flush().unwrap();
            }
        });
        Self {
            fixture,
            port,
            calls,
            headers,
            response,
            stop,
            handle: Some(handle),
        }
    }

    fn config(&self, issuer: &str, client: &str, audience: &str) -> VerifierConfig {
        serde_json::from_value(json!({
            "service":"gateway", "issuer":issuer, "resource":"https://gateway.example/mcp",
            "audience":audience,"subject":"owner","hosted_client":client,
            "introspection_url":format!("https://provider.test:{}/token",self.port),
            "introspection_client":client,"client_secret_file":self.fixture.secret,
            "provider_addresses":["127.0.0.1"],"required_scopes":["identity:read"],
            "timeout_ms":1000,"root_certificate_file":self.fixture.roots
        }))
        .unwrap()
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.handle.take().unwrap().join().unwrap();
    }
}

fn claims(issuer: &str, client: &str, audience: &str) -> Value {
    json!({"active":true,"iss":issuer,"client_id":client,"aud":audience,"sub":"owner",
        "scope":"identity:read", "exp":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()+300})
}

fn token(claims: &Value) -> String {
    format!(
        "e30.{}.signature",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn exact_profile_routes_one_provider_and_keeps_credentials_and_scopes_separate() {
    let a = Server::new("https://issuer-a.example", "client-a", "aud-a");
    let b = Server::new("https://issuer-b.example", "client-b", "aud-b");
    let ca = a.config("https://issuer-a.example", "client-a", "aud-a");
    let mut cb = b.config("https://issuer-b.example", "client-b", "aud-b");
    cb.required_scopes.push("messages:send".into());
    b.response.lock().unwrap().1["scope"] = json!("identity:read messages:send");
    let verifier = Verifier::from_profiles(vec![ca, cb]).unwrap();
    let rt = runtime();
    let ia = rt
        .block_on(verifier.verify(&token(&claims(
            "https://issuer-a.example",
            "client-a",
            "aud-a",
        ))))
        .unwrap();
    assert_eq!(
        (a.calls(), b.calls()),
        (1, 0),
        "profile A reached another provider"
    );
    assert!(
        !verifier.requires_scope_for(&ia, "messages:send"),
        "profiles merged their required scopes"
    );
    let ib = rt
        .block_on(verifier.verify(&token(&claims(
            "https://issuer-b.example",
            "client-b",
            "aud-b",
        ))))
        .unwrap();
    assert_eq!(
        (a.calls(), b.calls()),
        (1, 1),
        "profile B reached another provider"
    );
    assert_eq!(ib.issuer(), "https://issuer-b.example");
    assert_eq!(ib.audience(), "aud-b");
    assert!(verifier.requires_scope_for(&ib, "messages:send"));
    for (server, client) in [(&a, "client-a"), (&b, "client-b")] {
        let expected = format!(
            "basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{client}:fixture-secret-{client}"))
        );
        assert!(
            server.headers.lock().unwrap()[0]
                .to_ascii_lowercase()
                .contains(&expected.to_ascii_lowercase()),
            "profile credentials were merged"
        );
    }
}

#[test]
fn unknown_or_malformed_issuer_claims_refuse_without_opaque_fallback() {
    let a = Server::new("https://issuer-a.example", "client-a", "aud-a");
    let verifier = Verifier::from_profile_configs(vec![ProfileConfig {
        config: a.config("https://issuer-a.example", "client-a", "aud-a"),
        opaque_default: true,
    }])
    .unwrap();
    let rt = runtime();
    let good = claims("https://issuer-a.example", "client-a", "aud-a");
    let mut bad_tokens = Vec::new();
    for (field, value) in [
        ("iss", json!("https://unknown.example")),
        ("iss", Value::Null),
        ("client_id", json!("other")),
        ("aud", json!("other")),
        ("aud", json!(["aud-a", "extra"])),
        ("azp", json!("other")),
    ] {
        let mut bad = good.clone();
        bad[field] = value;
        bad_tokens.push(token(&bad));
    }
    for bad in bad_tokens {
        assert!(
            matches!(rt.block_on(verifier.verify(&bad)), Err(Error::InvalidToken)),
            "accepted unknown/malformed profile: {bad}"
        );
    }
    assert_eq!(a.calls(), 0, "unknown JWS probed opaque default");
    assert!(rt.block_on(verifier.verify("opaque-fixture")).is_ok());
    assert_eq!(a.calls(), 1, "opaque default positive control failed");
    let mut no_issuer = good.clone();
    no_issuer.as_object_mut().unwrap().remove("iss");
    assert!(
        rt.block_on(verifier.verify(&token(&no_issuer))).is_ok(),
        "JWS without issuer did not use explicit opaque default"
    );
    assert_eq!(a.calls(), 2);
    assert!(
        rt.block_on(verifier.verify("header.invalid.signature"))
            .is_ok(),
        "unreadable payload did not use explicit opaque default"
    );
    assert_eq!(a.calls(), 3);
}

#[test]
fn opaque_requires_explicit_default_and_never_falls_through() {
    let a = Server::new("https://issuer-a.example", "client-a", "aud-a");
    let b = Server::new("https://issuer-b.example", "client-b", "aud-b");
    let rt = runtime();
    let verifier = Verifier::from_profiles(vec![
        a.config("https://issuer-a.example", "client-a", "aud-a"),
        b.config("https://issuer-b.example", "client-b", "aud-b"),
    ])
    .unwrap();
    assert!(matches!(
        rt.block_on(verifier.verify("opaque-fixture")),
        Err(Error::InvalidToken)
    ));
    assert_eq!((a.calls(), b.calls()), (0, 0));
    let verifier = Verifier::from_profile_configs(vec![
        ProfileConfig {
            config: a.config("https://issuer-a.example", "client-a", "aud-a"),
            opaque_default: true,
        },
        ProfileConfig {
            config: b.config("https://issuer-b.example", "client-b", "aud-b"),
            opaque_default: false,
        },
    ])
    .unwrap();
    a.response.lock().unwrap().0 = 503;
    assert!(matches!(
        rt.block_on(verifier.verify("opaque-fixture")),
        Err(Error::Unavailable)
    ));
    assert_eq!(
        (a.calls(), b.calls()),
        (1, 0),
        "provider error triggered fallback"
    );
}

#[test]
fn selected_provider_must_revalidate_every_authoritative_claim() {
    let a = Server::new("https://issuer-a.example", "client-a", "aud-a");
    let verifier = Verifier::from_profiles(vec![a.config(
        "https://issuer-a.example",
        "client-a",
        "aud-a",
    )])
    .unwrap();
    let rt = runtime();
    let good = claims("https://issuer-a.example", "client-a", "aud-a");
    let bearer = token(&good);
    assert!(rt.block_on(verifier.verify(&bearer)).is_ok());
    for (field, value) in [
        ("iss", json!("https://issuer-b.example")),
        ("client_id", json!("client-b")),
        ("aud", json!("aud-b")),
        ("sub", json!("other")),
        ("scope", json!("other")),
        ("active", json!(false)),
        ("exp", json!(0)),
        ("nbf", json!(u64::MAX)),
        ("azp", json!("other")),
    ] {
        let mut bad = good.clone();
        bad[field] = value;
        *a.response.lock().unwrap() = (200, bad);
        assert!(
            matches!(
                rt.block_on(verifier.verify(&bearer)),
                Err(Error::InvalidToken)
            ),
            "authoritative claim {field} was not revalidated"
        );
    }
}

#[test]
fn profile_configuration_rejects_ambiguity_and_preserves_legacy_opaque() {
    let a = Server::new("https://issuer-a.example", "client-a", "aud-a");
    let ca = || a.config("https://issuer-a.example", "client-a", "aud-a");
    assert!(Verifier::from_profiles(Vec::new()).is_err());
    assert!(
        Verifier::from_profiles(
            (0..=MAX_PROFILES)
                .map(|index| {
                    let mut config = ca();
                    config.issuer = format!("https://issuer-{index}.example");
                    config
                })
                .collect()
        )
        .is_err(),
        "profile bound accepted seventeen distinct profiles"
    );
    let mut same_route = ca();
    same_route.subject = "another-owner".into();
    assert!(
        Verifier::from_profiles(vec![ca(), same_route]).is_err(),
        "duplicate routing key accepted"
    );
    let mut same_grant = ca();
    same_grant.audience = Some("different-audience".into());
    assert!(
        Verifier::from_profiles(vec![ca(), same_grant]).is_err(),
        "two profiles share a grant binding"
    );
    let mut other_resource = ca();
    other_resource.resource = "https://other.example/mcp".into();
    other_resource.issuer = "https://other.example".into();
    assert!(
        Verifier::from_profiles(vec![ca(), other_resource]).is_err(),
        "mixed resource accepted"
    );
    let mut other_service = ca();
    other_service.service = "different-service".into();
    other_service.issuer = "https://other.example".into();
    assert!(
        Verifier::from_profiles(vec![ca(), other_service]).is_err(),
        "mixed service accepted"
    );
    let mut second_default = ca();
    second_default.issuer = "https://another.example".into();
    assert!(Verifier::from_profile_configs(vec![
        ProfileConfig {
            config: ca(),
            opaque_default: true
        },
        ProfileConfig {
            config: second_default,
            opaque_default: true
        }
    ])
    .is_err());
    let value = serde_json::json!({"service":"gateway","issuer":"https://issuer-a.example","resource":"https://gateway.example/mcp","subject":"owner","hosted_client":"client-a","audience":"aud-a","introspection_url":format!("https://provider.test:{}/token",a.port),"introspection_client":"client-a","client_secret_file":a.fixture.secret,"provider_addresses":["127.0.0.1"],"required_scopes":["identity:read"],"timeout_ms":1000,"root_certificate_file":a.fixture.roots,"opaque_default":true});
    assert!(
        serde_json::from_value::<ProfileConfig>(value.clone()).is_ok(),
        "flattened profile config refused"
    );
    let mut unknown = value;
    unknown["unexpected"] = json!(true);
    assert!(serde_json::from_value::<ProfileConfig>(unknown).is_err());
    let legacy = Verifier::from_config(ca()).unwrap();
    assert!(runtime()
        .block_on(legacy.verify("legacy-opaque-fixture"))
        .is_ok());
}

#[test]
fn azp_alias_routes_only_when_unambiguous() {
    let a = Server::new("https://issuer-a.example", "client-a", "aud-a");
    let verifier = Verifier::from_profiles(vec![a.config(
        "https://issuer-a.example",
        "client-a",
        "aud-a",
    )])
    .unwrap();
    let mut alias = claims("https://issuer-a.example", "client-a", "aud-a");
    alias.as_object_mut().unwrap().remove("client_id");
    alias["azp"] = json!("client-a");
    *a.response.lock().unwrap() = (200, alias.clone());
    assert!(runtime().block_on(verifier.verify(&token(&alias))).is_ok());
}
