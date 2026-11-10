//! A real local TLS receiver; only Rust test injection bypasses public-destination admission.
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{json, Value};
use xmsg_mcp_gateway::webhook::{self, Transport};

use super::provider::TlsFixture;

pub struct Received {
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub value: Value,
}

pub struct CallbackFixture {
    pub transport: Arc<dyn Transport>,
    pub url: String,
    pub received: Arc<Mutex<Vec<Received>>>,
    /// Receiver-accepted signed event requests, never consumer observation or task completion.
    pub acked: Arc<AtomicUsize>,
    pub rejected: Arc<AtomicUsize>,
    pub statuses: Arc<Mutex<VecDeque<u16>>>,
    stopped: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    _tls: TlsFixture,
}

struct FixtureTransport {
    client: reqwest::Client,
    url: String,
}
impl Transport for FixtureTransport {
    fn post<'a>(
        &'a self,
        url: &'a str,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> webhook::PostFuture<'a> {
        Box::pin(async move {
            if url != self.url {
                return Err(webhook::Error::Destination);
            }
            let response = self
                .client
                .post(url)
                .headers(headers)
                .body(body)
                .send()
                .await
                .map_err(|_| webhook::Error::Transport)?;
            let status = response.status().as_u16();
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let body = response
                .bytes()
                .await
                .map_err(|_| webhook::Error::Transport)?
                .to_vec();
            Ok(webhook::Response {
                status,
                body,
                retry_after,
            })
        })
    }
}

impl CallbackFixture {
    pub fn roots(&self) -> &std::path::Path {
        &self._tls.roots
    }
    pub fn new(secret: &str) -> Self {
        webhook::validate_secret(secret).unwrap();
        let tls = TlsFixture::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("https://provider.test:{}/events", address.port());
        let transport = transport_for(&url, &tls.roots);
        let received = Arc::new(Mutex::new(Vec::new()));
        let acked = Arc::new(AtomicUsize::new(0));
        let rejected = Arc::new(AtomicUsize::new(0));
        let statuses = Arc::new(Mutex::new(VecDeque::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let worker_stopped = stopped.clone();
        let worker_received = received.clone();
        let worker_acked = acked.clone();
        let worker_rejected = rejected.clone();
        let worker_statuses = statuses.clone();
        let server_config = tls.tls.clone();
        let secret = secret.to_owned();
        let worker = thread::spawn(move || {
            let verifier = standardwebhooks::Webhook::new(&secret).unwrap();
            while !worker_stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        let Some((mut stream, headers, body)) = read(socket, server_config.clone())
                        else {
                            continue;
                        };
                        let value = serde_json::from_slice::<Value>(&body).ok();
                        let verified = verifier.verify(&body, &headers).is_ok()
                            && headers
                                .get("x-mcp-subscription-id")
                                .is_some_and(|value| !value.is_empty());
                        let (status, reply, event) = if !verified {
                            worker_rejected.fetch_add(1, Ordering::SeqCst);
                            (401, json!({"error":"invalid_signature"}), false)
                        } else if let Some(value) = value {
                            if value["type"] == "verification"
                                && value["challenge"].as_str().is_some()
                            {
                                (200, json!({"challenge":value["challenge"]}), false)
                            } else if value["eventId"].as_str()
                                == headers
                                    .get("webhook-id")
                                    .and_then(|value| value.to_str().ok())
                                && value["name"] == xmsg_mcp_gateway::events::EVENT_NAME
                            {
                                let status =
                                    worker_statuses.lock().unwrap().pop_front().unwrap_or(200);
                                worker_received.lock().unwrap().push(Received {
                                    headers,
                                    body,
                                    value,
                                });
                                (
                                    status,
                                    json!({"accepted":(200..300).contains(&status)}),
                                    true,
                                )
                            } else {
                                (400, json!({"error":"invalid_event"}), false)
                            }
                        } else {
                            (400, json!({"error":"invalid_json"}), false)
                        };
                        // Record receiver acceptance before its response can reach the client.
                        if event && (200..300).contains(&status) {
                            worker_acked.fetch_add(1, Ordering::SeqCst);
                        }
                        let reply = reply.to_string();
                        let _written = write!(stream,"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",reply.len()).and_then(|_|stream.flush());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("fixture callback listener: {error}"),
                }
            }
        });
        Self {
            transport,
            url,
            received,
            acked,
            rejected,
            statuses,
            stopped,
            worker: Some(worker),
            _tls: tls,
        }
    }
}
impl Drop for CallbackFixture {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let deadline = Instant::now() + Duration::from_secs(4);
            while !worker.is_finished() {
                assert!(
                    Instant::now() < deadline,
                    "callback fixture did not exit within budget"
                );
                thread::sleep(Duration::from_millis(5));
            }
            worker.join().expect("callback fixture panicked");
        }
    }
}

fn read(
    socket: TcpStream,
    config: Arc<rustls::ServerConfig>,
) -> Option<(super::provider::TlsStream, HeaderMap, Vec<u8>)> {
    socket.set_nonblocking(false).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), socket);
    let mut reader = BufReader::new(&mut tls);
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    assert_eq!(line, "POST /events HTTP/1.1\r\n");
    let mut headers = HeaderMap::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        if line == "\r\n" {
            break;
        }
        let (name, value) = line.split_once(':')?;
        headers.append(
            HeaderName::from_bytes(name.as_bytes()).ok()?,
            HeaderValue::from_str(value.trim()).ok()?,
        );
    }
    let length = headers
        .get("content-length")?
        .to_str()
        .ok()?
        .parse::<usize>()
        .ok()?;
    assert!(length <= webhook::MAX_EVENT_BYTES);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    drop(reader);
    Some((tls, headers, body))
}

/// Test-only connector for a child process using an already running local TLS receiver.
pub fn transport_for(url: &str, roots: &std::path::Path) -> Arc<dyn Transport> {
    let endpoint = reqwest::Url::parse(url).unwrap();
    let client = webhook::pinned_https_client_builder(
        endpoint.host_str().unwrap(),
        &[SocketAddr::from((
            [127, 0, 0, 1],
            endpoint.port_or_known_default().unwrap(),
        ))],
        Duration::from_secs(2),
    )
    .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(roots).unwrap()).unwrap())
    .build()
    .unwrap();
    Arc::new(FixtureTransport {
        client,
        url: url.into(),
    })
}
