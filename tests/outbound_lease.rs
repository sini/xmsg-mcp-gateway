use xmsg_mcp_gateway::grants::Store;
#[allow(dead_code)]
#[path = "common/custody_crash.rs"]
mod crash;

#[test]
fn operation_lease_is_per_service_and_nonblocking() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("authority.db");
    let first = Store::initialize(&file).unwrap();
    let second = Store::open(&file).unwrap();
    let held = first.try_operation_lease("gateway").unwrap().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        tx.send(second.try_operation_lease("gateway").unwrap().is_none())
            .unwrap();
    });
    assert!(rx
        .recv_timeout(std::time::Duration::from_millis(500))
        .expect("lease acquisition blocked instead of returning pending"));
    waiter.join().unwrap();
    assert!(first.try_operation_lease("other").unwrap().is_some());
    drop(held);
    assert!(first.try_operation_lease("gateway").unwrap().is_some());
}

#[cfg(unix)]
#[test]
fn operation_lease_is_private_and_refuses_symlinks() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let temp = tempfile::tempdir().unwrap();
    let store = Store::initialize(&temp.path().join("authority.db")).unwrap();
    let held = store.try_operation_lease("gateway").unwrap().unwrap();
    let files: Vec<_> = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|file| file.extension().is_some_and(|ext| ext == "lease"))
        .collect();
    assert_eq!(files.len(), 1);
    let lease = &files[0];
    assert_eq!(
        std::fs::metadata(lease).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(held);
    std::fs::set_permissions(lease, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        store.try_operation_lease("gateway").is_err(),
        "lease file with public permissions was accepted"
    );
    std::fs::set_permissions(lease, std::fs::Permissions::from_mode(0o600)).unwrap();
    let target = temp.path().join("target");
    std::fs::rename(lease, &target).unwrap();
    symlink(&target, lease).unwrap();
    assert!(store.try_operation_lease("gateway").is_err());
}

#[test]
fn disable_timeout_refuses_without_a_partial_write() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    use xmsg_mcp_gateway::grants::Binding;
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("authority.db");
    let mut store = Store::initialize(&file).unwrap();
    store
        .enroll(
            "grant",
            &Binding {
                service: "gateway".into(),
                issuer: "issuer".into(),
                resource: "resource".into(),
                subject: "owner".into(),
                hosted_client: "hosted".into(),
            },
        )
        .unwrap();
    store.set_enabled("grant", 1, true).unwrap();
    let _held = store.try_operation_lease("gateway").unwrap().unwrap();
    let log = temp.path().join("disable.log");
    let started = Instant::now();
    let mut child = crash::Worker(
        Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
            .arg("--state")
            .arg(&file)
            .args(["disable", "grant", "2"])
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .unwrap(),
    );
    let deadline = started + Duration::from_secs(35);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "disable exceeded its published wait bound"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(
        !status.success(),
        "disable committed without acquiring the lease after timeout"
    );
    assert!(started.elapsed() >= Duration::from_secs(29));
    assert!(std::fs::read_to_string(log)
        .unwrap()
        .contains("operation is still in progress"));
    let sql = rusqlite::Connection::open(file).unwrap();
    let state: (bool, i64) = sql
        .query_row("SELECT enabled,revision FROM grants", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(
        state,
        (true, 2),
        "disable timeout left a partial authority write"
    );
}
