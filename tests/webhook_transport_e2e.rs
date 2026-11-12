//! Linux-only isolated binary; macOS does not pass the socket-shim control.
#![cfg(target_os = "linux")]

use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use xmsg_mcp_gateway::webhook::{PublicHttps, Transport};

const FIRST: &str = "first.callback.test";
const SECOND: &str = "second.callback.test";
const CONTROL: &str = "unrelated.callback.test";
const PUBLIC: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const SECOND_PUBLIC: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

struct Shim {
    mode: String,
    first_port: u16,
    second_port: u16,
    trap_port: u16,
    first_lookups: usize,
    second_lookups: usize,
    control_lookups: usize,
    control_connects: usize,
    destinations: Vec<(Ipv4Addr, u16)>,
}
static SHIM: OnceLock<Mutex<Shim>> = OnceLock::new();

type GetAddrInfo = unsafe extern "C" fn(
    *const libc::c_char,
    *const libc::c_char,
    *const libc::addrinfo,
    *mut *mut libc::addrinfo,
) -> libc::c_int;
type Connect =
    unsafe extern "C" fn(libc::c_int, *const libc::sockaddr, libc::socklen_t) -> libc::c_int;

fn real_getaddrinfo() -> GetAddrInfo {
    static SYMBOL: OnceLock<usize> = OnceLock::new();
    let symbol = *SYMBOL
        .get_or_init(|| unsafe { libc::dlsym(libc::RTLD_NEXT, c"getaddrinfo".as_ptr()) as usize });
    assert_ne!(symbol, 0, "libc getaddrinfo is unavailable");
    unsafe { std::mem::transmute::<usize, GetAddrInfo>(symbol) }
}
fn real_connect() -> Connect {
    static SYMBOL: OnceLock<usize> = OnceLock::new();
    let symbol = *SYMBOL
        .get_or_init(|| unsafe { libc::dlsym(libc::RTLD_NEXT, c"connect".as_ptr()) as usize });
    assert_ne!(symbol, 0, "libc connect is unavailable");
    unsafe { std::mem::transmute::<usize, Connect>(symbol) }
}

#[unsafe(export_name = "getaddrinfo")]
unsafe extern "C" fn fixture_getaddrinfo(
    node: *const libc::c_char,
    service: *const libc::c_char,
    hints: *const libc::addrinfo,
    result: *mut *mut libc::addrinfo,
) -> libc::c_int {
    let replacement = if node.is_null() {
        None
    } else if let Some(shim) = SHIM.get() {
        let host = unsafe { CStr::from_ptr(node) }.to_bytes();
        let mut state = shim.lock().unwrap();
        if host == FIRST.as_bytes() {
            state.first_lookups += 1;
            Some(if state.mode == "pin" && state.first_lookups > 1 {
                "127.0.0.1"
            } else {
                "8.8.8.8"
            })
        } else if host == SECOND.as_bytes() {
            state.second_lookups += 1;
            Some("1.1.1.1")
        } else if host == CONTROL.as_bytes() {
            state.control_lookups += 1;
            Some("9.9.9.9")
        } else {
            None
        }
    } else {
        None
    };
    let replacement = replacement.map(|host| CString::new(host).unwrap());
    unsafe {
        real_getaddrinfo()(
            replacement.as_ref().map_or(node, |host| host.as_ptr()),
            service,
            hints,
            result,
        )
    }
}

#[unsafe(export_name = "connect")]
unsafe extern "C" fn fixture_connect(
    fd: libc::c_int,
    address: *const libc::sockaddr,
    length: libc::socklen_t,
) -> libc::c_int {
    let mut replacement = None;
    if !address.is_null()
        && length as usize >= std::mem::size_of::<libc::sockaddr_in>()
        && unsafe { (*address).sa_family as libc::c_int } == libc::AF_INET
    {
        if let Some(shim) = SHIM.get() {
            let original = unsafe { *(address.cast::<libc::sockaddr_in>()) };
            let ip = Ipv4Addr::from(original.sin_addr.s_addr.to_ne_bytes());
            let port = u16::from_be(original.sin_port);
            let mut state = shim.lock().unwrap();
            state.destinations.push((ip, port));
            let target = if ip == PUBLIC && port == state.trap_port {
                Some(state.first_port)
            } else if ip == SECOND_PUBLIC && port == state.second_port {
                Some(state.second_port)
            } else if ip == Ipv4Addr::LOCALHOST && port == state.second_port {
                state.control_connects += 1;
                Some(state.first_port)
            } else {
                None
            };
            if let Some(port) = target {
                let mut mapped = original;
                mapped.sin_addr.s_addr = u32::from_ne_bytes(Ipv4Addr::LOCALHOST.octets());
                mapped.sin_port = port.to_be();
                replacement = Some(mapped);
            }
        }
    }
    unsafe {
        real_connect()(
            fd,
            replacement
                .as_ref()
                .map_or(address, |mapped| std::ptr::from_ref(mapped).cast()),
            length,
        )
    }
}

struct Servers {
    stop: Arc<AtomicBool>,
    workers: Vec<std::thread::JoinHandle<()>>,
    requests: [Arc<AtomicUsize>; 3],
    _directory: tempfile::TempDir,
    root: std::path::PathBuf,
    ports: [u16; 3],
}
impl Servers {
    fn new(mode: &str) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certificate = rcgen::generate_simple_self_signed(vec![
            FIRST.into(),
            SECOND.into(),
            "127.0.0.1".into(),
        ])
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("callback-ca.pem");
        std::fs::write(&root, certificate.cert.pem()).unwrap();
        let tls = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(
                        certificate.signing_key.serialize_der(),
                    )
                    .into(),
                )
                .unwrap(),
        );
        let listeners: Vec<_> = (0..3)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let ports: Vec<_> = listeners
            .iter()
            .map(|socket| socket.local_addr().unwrap().port())
            .collect();
        let ports: [u16; 3] = ports.try_into().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests: [Arc<AtomicUsize>; 3] =
            std::array::from_fn(|_| Arc::new(AtomicUsize::new(0)));
        let workers = listeners
            .into_iter()
            .enumerate()
            .map(|(hop, listener)| {
                listener.set_nonblocking(true).unwrap();
                let tls = tls.clone();
                let stop = stop.clone();
                let requests = requests[hop].clone();
                let mode = mode.to_owned();
                std::thread::spawn(move || {
                    let deadline = Instant::now() + Duration::from_secs(25);
                    while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
                        match listener.accept() {
                            Ok((socket, _)) => {
                                serve(socket, tls.clone(), hop, &mode, ports, &requests)
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(5))
                            }
                            Err(error) => panic!("fixture accept failed: {error}"),
                        }
                    }
                })
            })
            .collect();
        Self {
            stop,
            workers,
            requests,
            _directory: directory,
            root,
            ports,
        }
    }
}
impl Drop for Servers {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for worker in self.workers.drain(..) {
            worker.join().unwrap();
        }
    }
}
fn serve(
    socket: TcpStream,
    tls: Arc<rustls::ServerConfig>,
    hop: usize,
    mode: &str,
    ports: [u16; 3],
    requests: &AtomicUsize,
) {
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut stream = rustls::StreamOwned::new(rustls::ServerConnection::new(tls).unwrap(), socket);
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 1024];
    while bytes.len() < 8192 && !bytes.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(size) => bytes.extend_from_slice(&chunk[..size]),
        }
    }
    let Some(header_end) = bytes
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .map(|at| at + 4)
    else {
        return;
    };
    let length = String::from_utf8_lossy(&bytes[..header_end])
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    if header_end + length > 8192 {
        return;
    }
    while bytes.len() < header_end + length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(size) => bytes.extend_from_slice(&chunk[..size]),
        }
    }
    let text = String::from_utf8_lossy(&bytes);
    let control = text.lines().next().unwrap_or("").contains(" /control ");
    let (status, location, body) = if control && hop == 0 {
        (200, None, "CONTROL_PLANTED")
    } else if hop == 0 && mode == "pin" {
        requests.fetch_add(1, Ordering::SeqCst);
        (200, None, "APPROVED_SINK")
    } else if hop == 0 {
        requests.fetch_add(1, Ordering::SeqCst);
        (
            302,
            Some(format!("https://{SECOND}:{}/second", ports[1])),
            "FIRST_REDIRECT",
        )
    } else if hop == 1 {
        if !control {
            requests.fetch_add(1, Ordering::SeqCst);
        }
        (
            302,
            Some(format!("https://127.0.0.1:{}/private", ports[2])),
            "SECOND_REDIRECT",
        )
    } else {
        requests.fetch_add(1, Ordering::SeqCst);
        (200, None, "PRIVATE_TRAP")
    };
    let location = location.map_or(String::new(), |location| {
        format!("Location: {location}\r\n")
    });
    let reply = format!("HTTP/1.1 {status} Fixture\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    let _ = stream.write_all(reply.as_bytes());
    let _ = stream.flush();
}

fn run_child(mode: &str) {
    let servers = Servers::new(mode);
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "callback_transport_child", "--nocapture"])
        .env("WEBHOOK_E2E_MODE", mode)
        .env(
            "WEBHOOK_E2E_PORTS",
            format!(
                "{},{},{}",
                servers.ports[0], servers.ports[1], servers.ports[2]
            ),
        )
        .env("SSL_CERT_FILE", &servers.root)
        .env_remove("SSL_CERT_DIR")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("callback fixture child exceeded its budget");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    let counts: Vec<_> = servers
        .requests
        .iter()
        .map(|count| count.load(Ordering::SeqCst))
        .collect();
    let diagnostics = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.starts_with("dns first="))
        .collect::<Vec<_>>()
        .join("\n");
    println!("mode={mode} requests={counts:?}\n{diagnostics}");
    assert!(
        output.status.success(),
        "callback child failed: {}\n{}\nrequests={counts:?}",
        diagnostics,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        counts,
        [1, 0, 0],
        "callback followed an unvalidated destination"
    );
}

#[test]
fn public_https_pins_validation_dns_answer() {
    run_child("pin");
}
#[test]
fn public_https_stops_before_redirect_chain() {
    run_child("redirect");
}

#[test]
fn callback_transport_child() {
    let Ok(mode) = std::env::var("WEBHOOK_E2E_MODE") else {
        return;
    };
    let ports: Vec<u16> = std::env::var("WEBHOOK_E2E_PORTS")
        .unwrap()
        .split(',')
        .map(|port| port.parse().unwrap())
        .collect();
    SHIM.set(Mutex::new(Shim {
        mode: mode.clone(),
        first_port: ports[0],
        second_port: ports[1],
        trap_port: ports[2],
        first_lookups: 0,
        second_lookups: 0,
        control_lookups: 0,
        control_connects: 0,
        destinations: vec![],
    }))
    .unwrap_or_else(|_| panic!("shim already installed"));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let control: Vec<_> = tokio::net::lookup_host((CONTROL, 443))
            .await
            .expect("resolver shim positive control failed")
            .collect();
        assert_eq!(
            control[0].ip(),
            "9.9.9.9".parse::<std::net::IpAddr>().unwrap(),
            "resolver shim did not return planted answer"
        );
        let control = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap()
            .get(format!("https://127.0.0.1:{}/control", ports[1]))
            .send()
            .await
            .expect("socket shim positive control failed")
            .text()
            .await
            .unwrap();
        assert_eq!(
            control, "CONTROL_PLANTED",
            "socket shim did not reach planted sink"
        );
        assert_eq!(SHIM.get().unwrap().lock().unwrap().control_connects, 1);
        let response = PublicHttps
            .post(
                &format!("https://{FIRST}:{}/event", ports[2]),
                reqwest::header::HeaderMap::new(),
                b"{}".to_vec(),
            )
            .await
            .unwrap();
        let state = SHIM.get().unwrap().lock().unwrap();
        println!(
            "dns first={} second={} control={} intended={:?} status={} body={}",
            state.first_lookups,
            state.second_lookups,
            state.control_lookups,
            state.destinations,
            response.status,
            String::from_utf8_lossy(&response.body)
        );
        if mode == "pin" {
            assert_eq!(
                response.body, b"APPROVED_SINK",
                "DNS rebinding reached the private trap instead of the pinned sink"
            );
            assert_eq!(
                state.first_lookups, 1,
                "connection performed a second DNS lookup"
            );
        } else {
            assert_eq!(response.status, 302, "callback followed the redirect chain");
            assert_eq!(response.body, b"FIRST_REDIRECT");
            assert_eq!(
                state.second_lookups, 0,
                "redirect caused a second-host lookup"
            );
        }
        assert!(
            state.destinations.contains(&(PUBLIC, ports[2])),
            "validated public destination was not passed to connect"
        );
        assert!(
            !state
                .destinations
                .contains(&(Ipv4Addr::LOCALHOST, ports[2])),
            "private trap was dialed"
        );
    });
}
