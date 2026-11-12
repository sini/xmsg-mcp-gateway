use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type Arrival = Arc<Mutex<Option<Arc<dyn Fn(&str) + Send + Sync>>>>;

pub(super) struct Fake {
    pub(super) keys: crate::provider_fixture::TlsFixture,
    pub(super) origin: String,
    pub(super) routes: Arc<Mutex<HashMap<String, (u16, Value)>>>,
    pub(super) requests: Arc<Mutex<Vec<String>>>,
    pub(super) forms: Arc<Mutex<Vec<String>>>,
    pub(super) arrival: Arrival,
    pub(super) delays: Arc<Mutex<HashMap<String, Duration>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl Fake {
    pub(super) fn new() -> Self {
        let keys = crate::provider_fixture::TlsFixture::new();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let routes = Arc::new(Mutex::new(HashMap::from([
            (
                "/introspect".into(),
                (
                    200,
                    json!({"active":true,"iss":"https://provider.example/issuer","aud":"login","client_id":"login","sub":"owner","scope":"openid","exp":now+3600}),
                ),
            ),
            (
                "/token".into(),
                (
                    200,
                    json!({"access_token":"fixture-access","id_token":"fixture-id","refresh_token":"fixture-refresh"}),
                ),
            ),
            ("/v1/person/owner".into(), (200, json!({"attrs":{}}))),
            ("/v1/person/canary".into(), (200, json!({"attrs":{}}))),
            (
                "/v1/person/owner/_attr/account_valid_from".into(),
                (200, Value::Null),
            ),
            (
                "/v1/person/owner/_attr/account_expire".into(),
                (200, Value::Null),
            ),
            (
                "/v1/person/owner/_attr/memberof".into(),
                (200, json!(["login.access@test"])),
            ),
            (
                "/v1/person/canary/_attr/account_valid_from".into(),
                (200, json!(["2000-01-01T00:00:00Z"])),
            ),
            (
                "/v1/person/canary/_attr/account_expire".into(),
                (200, json!(["2099-12-31T00:00:00Z"])),
            ),
        ])));
        let requests = Arc::new(Mutex::new(vec![]));
        let forms = Arc::new(Mutex::new(vec![]));
        let arrival: Arrival = Arc::new(Mutex::new(None));
        let delays = Arc::new(Mutex::new(HashMap::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (worker_routes, worker_requests, worker_stop, tls) = (
            routes.clone(),
            requests.clone(),
            stop.clone(),
            keys.tls.clone(),
        );
        let worker_forms = forms.clone();
        let worker_arrival = arrival.clone();
        let worker_delays = delays.clone();
        let worker = thread::spawn(move || {
            let mut children = Vec::new();
            while !worker_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        let routes = worker_routes.clone();
                        let requests = worker_requests.clone();
                        let forms = worker_forms.clone();
                        let arrival = worker_arrival.clone();
                        let delays = worker_delays.clone();
                        let tls = tls.clone();
                        children.push(thread::spawn(move || {
                            Self::serve(socket, tls, routes, requests, forms, arrival, delays)
                        }));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(e) => panic!("local fixture accept failed: {e}"),
                }
            }
            let deadline = Instant::now() + Duration::from_secs(4);
            for child in children {
                while !child.is_finished() {
                    assert!(Instant::now() < deadline, "local fixture did not stop");
                    thread::sleep(Duration::from_millis(2));
                }
                child.join().unwrap();
            }
        });
        Self {
            keys,
            origin: format!("https://127.0.0.1:{port}"),
            routes,
            requests,
            forms,
            arrival,
            delays,
            stop,
            worker: Some(worker),
        }
    }
    fn serve(
        socket: TcpStream,
        tls: Arc<rustls::ServerConfig>,
        routes: Arc<Mutex<HashMap<String, (u16, Value)>>>,
        requests: Arc<Mutex<Vec<String>>>,
        forms: Arc<Mutex<Vec<String>>>,
        arrival: Arrival,
        delays: Arc<Mutex<HashMap<String, Duration>>>,
    ) {
        // Accepted sockets inherit the listener's nonblocking flag on macOS.
        socket.set_nonblocking(false).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut stream = BufReader::new(rustls::StreamOwned::new(
            rustls::ServerConnection::new(tls).unwrap(),
            socket,
        ));
        let mut request = String::new();
        if stream.read_line(&mut request).is_err() {
            return;
        }
        let Some(route) = request.split_whitespace().nth(1).map(str::to_owned) else {
            return;
        };
        let mut length = 0;
        loop {
            let mut line = String::new();
            if stream.read_line(&mut line).is_err() || line.is_empty() {
                return;
            }
            if line == "\r\n" {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                if key.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse().unwrap();
                }
            }
        }
        let mut body = vec![0; length];
        if stream.read_exact(&mut body).is_err() {
            return;
        }
        requests.lock().unwrap().push(route.clone());
        let delay = delays.lock().unwrap().get(&route).copied();
        if let Some(delay) = delay {
            std::thread::sleep(delay);
        }
        let hook = arrival.lock().unwrap().clone();
        if let Some(hook) = hook {
            hook(&route);
        }
        if route == "/token" {
            let form = String::from_utf8(body).unwrap();
            forms.lock().unwrap().push(form.clone());
            let mut parsed = reqwest::Url::parse("https://form.invalid").unwrap();
            parsed.set_query(Some(&form));
            let verifier = parsed
                .query_pairs()
                .find(|(k, _)| k == "code_verifier")
                .map(|(_, v)| v.into_owned());
            if verifier.as_ref().is_none_or(|v| v.len() != 43) {
                let _ = stream.get_mut().write_all(
                    b"HTTP/1.1 400 Invalid\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                return;
            }
        }

        let (status, body) = routes
            .lock()
            .unwrap()
            .get(&route)
            .cloned()
            .unwrap_or((404, json!({})));
        let body = body.to_string();
        let response=format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
        let _ = stream.get_mut().write_all(response.as_bytes());
        let _ = stream.get_mut().flush();
    }
    pub(super) fn set(&self, route: &str, status: u16, body: Value) {
        let mut routes = self.routes.lock().unwrap();
        if route.starts_with("/v1/person/") && !route.contains("/_attr/") && body.is_null() {
            let prefix = format!("{route}/_attr/");
            for (key, value) in routes.iter_mut() {
                if key.starts_with(&prefix) {
                    *value = (status, Value::Null);
                }
            }
        }
        routes.insert(route.into(), (status, body));
    }
}
impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[tokio::test]
async fn nonblocking_socket_is_reset_before_tls_request() {
    let fake = Fake::new();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let tls = fake.keys.tls.clone();
    let routes = fake.routes.clone();
    let requests = fake.requests.clone();
    let forms = fake.forms.clone();
    let arrival = fake.arrival.clone();
    let delays = fake.delays.clone();
    let worker = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket.set_nonblocking(true).unwrap();
        Fake::serve(socket, tls, routes, requests, forms, arrival, delays);
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(&fake.keys.roots).unwrap()).unwrap(),
        )
        .build()
        .unwrap();
    let response = client
        .get(format!("https://{address}/v1/person/owner/_attr/memberof"))
        .send()
        .await;
    worker.join().unwrap();
    let body = response
        .expect("forced nonblocking socket did not serve HTTPS")
        .text()
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!(["login.access@test"])
    );
    assert_eq!(fake.requests.lock().unwrap().len(), 1);
}
