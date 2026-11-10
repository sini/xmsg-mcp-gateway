use std::collections::HashMap;
use std::io::Write;
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;
use tracing::instrument::WithSubscriber;
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};
use xmsg_mcp_gateway::grants::{Binding, Store};
use xmsg_mcp_gateway::serving::Serving;

use super::provider;

pub const HAPPY_DISPATCH_TIMEOUT_MS: u64 = 5000;

pub struct Fixture {
    pub started: Instant,
    pub keys: provider::TlsFixture,
    pub binding: Binding,
    pub store_file: PathBuf,
    pub config_file: PathBuf,
    pub config: Value,
    pub tokens: Arc<Mutex<HashMap<String, Value>>>,
    pub requests: Arc<AtomicUsize>,
    pub response_status: Arc<AtomicUsize>,
    pub provider_timing: Arc<Mutex<Vec<(String, u128)>>>,
    pub provider_phase: Arc<Mutex<&'static str>>,
    stopped: Arc<AtomicBool>,
    active: Arc<Mutex<Option<TcpStream>>>,
    worker: Option<thread::JoinHandle<()>>,
}

pub fn private_file(file: &Path, bytes: &[u8]) {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(file).unwrap().write_all(bytes).unwrap();
}

impl Fixture {
    pub fn new() -> Self {
        let started = Instant::now();
        // A registered default prevents Interest::never when a lone inactive probe hits a callsite.
        static TRACING: std::sync::Once = std::sync::Once::new();
        TRACING.call_once(|| {
            let _ = tracing::subscriber::set_global_default(
                tracing::subscriber::NoSubscriber::default(),
            );
        });
        let keys = provider::TlsFixture::new();
        let binding = Binding {
            service: "gateway".into(),
            issuer: "https://issuer.example/".into(),
            resource: "https://gateway.example/mcp".into(),
            subject: "owner".into(),
            hosted_client: "hosted-client".into(),
        };
        let store_file = keys._directory.path().join("grants.db");
        let mut store = Store::initialize(&store_file).unwrap();
        store.enroll("grant", &binding).unwrap();
        store.set_enabled("grant", 1, true).unwrap();
        drop(store);
        let tokens = Arc::new(Mutex::new(HashMap::from([
            ("good-token".into(), provider::claims(&binding)),
            ("foreign-token".into(), {
                let mut claims = provider::claims(&binding);
                claims["client_id"] = json!("unapproved-client");
                claims
            }),
        ])));
        let requests = Arc::new(AtomicUsize::new(0));
        let response_status = Arc::new(AtomicUsize::new(200));
        let worker_status = response_status.clone();
        let stopped = Arc::new(AtomicBool::new(false));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let tls = keys.tls.clone();
        let worker_tokens = tokens.clone();
        let worker_requests = requests.clone();
        let worker_stopped = stopped.clone();
        let active = Arc::new(Mutex::new(None::<TcpStream>));
        let worker_active = active.clone();
        let provider_timing = Arc::new(Mutex::new(Vec::new()));
        let timing = provider_timing.clone();
        let provider_phase = Arc::new(Mutex::new("starting"));
        let phase = provider_phase.clone();
        let worker = thread::spawn(move || {
            struct Exit(Arc<Mutex<&'static str>>);
            impl Drop for Exit {
                fn drop(&mut self) {
                    *self.0.lock().unwrap_or_else(|error| error.into_inner()) = "exited";
                }
            }
            let _exit = Exit(phase.clone());
            *phase.lock().unwrap() = "accept";
            timing
                .lock()
                .unwrap()
                .push(("ready".into(), started.elapsed().as_micros()));
            while !worker_stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        {
                            let mut active = worker_active.lock().unwrap();
                            if worker_stopped.load(Ordering::SeqCst) {
                                let _ = socket.shutdown(Shutdown::Both);
                                break;
                            }
                            *active = Some(socket.try_clone().unwrap());
                        }
                        timing
                            .lock()
                            .unwrap()
                            .push(("accepted".into(), started.elapsed().as_micros()));
                        let Some((mut stream, request)) =
                            provider::read_request_with_phase(socket, tls.clone(), true, |stage| {
                                *phase.lock().unwrap() = stage;
                            })
                        else {
                            timing
                                .lock()
                                .unwrap()
                                .push(("idle-closed".into(), started.elapsed().as_micros()));
                            worker_active.lock().unwrap().take();
                            *phase.lock().unwrap() = "accept";
                            continue;
                        };
                        timing
                            .lock()
                            .unwrap()
                            .push(("request-read".into(), started.elapsed().as_micros()));
                        worker_requests.fetch_add(1, Ordering::SeqCst);
                        let token = request
                            .strip_prefix("token=")
                            .unwrap()
                            .split('&')
                            .next()
                            .unwrap();
                        let claims = worker_tokens
                            .lock()
                            .unwrap()
                            .get(token)
                            .cloned()
                            .unwrap_or(json!({"active":false}))
                            .to_string();
                        *phase.lock().unwrap() = "response-write-or-flush";
                        let response=format!("HTTP/1.1 {} fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{claims}", worker_status.load(Ordering::SeqCst), claims.len());
                        let written =
                            provider::write_complete_response(&mut stream, response.as_bytes());
                        worker_active.lock().unwrap().take();
                        *phase.lock().unwrap() = "accept";
                        timing.lock().unwrap().push((
                            if written {
                                "response-written"
                            } else {
                                "response-cancelled"
                            }
                            .into(),
                            started.elapsed().as_micros(),
                        ));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => panic!("provider fixture: {error}"),
                }
            }
        });
        let config_file = keys._directory.path().join("serving.json");
        let config = json!({
            "bind":"127.0.0.1:0", "grant_store":store_file, "request_timeout_ms":10000,
            "allowed_hosts":["gateway.example", "127.0.0.1"], "allowed_origins":["https://gateway.example"],
            "verifier": {"service":binding.service, "issuer":binding.issuer, "resource":binding.resource,
                "subject":binding.subject, "hosted_client":binding.hosted_client,
                "introspection_url":format!("https://provider.test:{port}/introspect"),
                "introspection_client":"lookup-client", "client_secret_file":keys.secret,
                "provider_addresses":["127.0.0.1"], "required_scopes":["identity:read"],
                "timeout_ms":2000, "root_certificate_file":keys.roots}
        });
        private_file(&config_file, &serde_json::to_vec(&config).unwrap());
        Self {
            started,
            keys,
            binding,
            store_file,
            config_file,
            config,
            tokens,
            requests,
            response_status,
            provider_timing,
            provider_phase,
            stopped,
            active,
            worker: Some(worker),
        }
    }
    fn request_stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(socket) = self.active.lock().unwrap().take() {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
    pub fn stop_provider(&mut self) {
        self.request_stop();
        if let Some(worker) = self.worker.take() {
            join_provider(worker, &self.provider_phase);
        }
    }
    pub async fn serving(&self) -> Serving {
        Serving::from_owner_file(&self.config_file).await.unwrap()
    }
    pub fn call() -> Value {
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"xmsg_identity","arguments":{}}})
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.request_stop();
        if let Some(worker) = self.worker.take() {
            join_provider(worker, &self.provider_phase);
        }
    }
}

fn join_provider(worker: thread::JoinHandle<()>, phase: &Mutex<&'static str>) {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !worker.is_finished() {
        let current_phase = *phase.lock().unwrap();
        assert!(
            std::time::Instant::now() < deadline,
            "serving provider fixture worker did not exit within 3 seconds; phase={current_phase}"
        );
        thread::sleep(Duration::from_millis(10));
    }
    worker
        .join()
        .expect("serving provider fixture worker panicked");
}

#[derive(Clone, Default)]
pub struct Probe {
    pub response: Arc<Mutex<Option<(u16, String, u128)>>>,
    pub opens: Arc<AtomicUsize>,
    pub dispatches: Arc<AtomicUsize>,
    pub registrations: Arc<AtomicUsize>,
    pub health_samples: Arc<AtomicUsize>,
    pub link_observations: Arc<AtomicUsize>,
}
impl Subscriber for Probe {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        matches!(
            metadata.target(),
            "gateway_policy_store"
                | "gateway_dispatch"
                | "gateway_registration"
                | "gateway_bus_health"
                | "gateway_bus_observation"
        )
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        match event.metadata().target() {
            "gateway_policy_store" => {
                self.opens.fetch_add(1, Ordering::SeqCst);
            }
            "gateway_dispatch" => {
                struct Start(bool);
                impl tracing::field::Visit for Start {
                    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                        if field.name() == "message" {
                            self.0 = value == "dispatch";
                        }
                    }
                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        if field.name() == "message" {
                            self.0 = format!("{value:?}") == "dispatch";
                        }
                    }
                }
                let mut start = Start(false);
                event.record(&mut start);
                if start.0 {
                    self.dispatches.fetch_add(1, Ordering::SeqCst);
                }
            }
            "gateway_bus_observation" => {
                self.link_observations.fetch_add(1, Ordering::SeqCst);
            }
            "gateway_bus_health" => {
                self.health_samples.fetch_add(1, Ordering::SeqCst);
            }
            "gateway_registration" => {
                self.registrations.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
    }
}

pub async fn request(serving: &Serving, token: &str, body: Value) -> (StatusCode, Value, Probe) {
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "gateway.example")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    raw_request(serving, request).await
}

pub async fn raw_request(serving: &Serving, request: Request<Body>) -> (StatusCode, Value, Probe) {
    let probe = Probe::default();
    let started = Instant::now();
    let response = serving
        .router()
        .oneshot(request)
        .with_subscriber(probe.clone())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 100_000).await.unwrap();
    *probe.response.lock().unwrap() = Some((
        status.as_u16(),
        String::from_utf8_lossy(&bytes).into_owned(),
        started.elapsed().as_micros(),
    ));
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body, probe)
}
