use std::path::Path;
use std::process::{Command, Output};

use xmsg_mcp_gateway::grants::{Binding, Error, Store};

fn run(state: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
        .arg("--state")
        .arg(state)
        .args(args)
        .output()
        .unwrap()
}

fn binding() -> Binding {
    Binding {
        service: "gateway".into(),
        issuer: "https://issuer.example/".into(),
        resource: "https://gateway.example/mcp".into(),
        subject: "owner".into(),
        hosted_client: "hosted-client".into(),
    }
}

#[test]
fn local_owner_commands_preserve_disabled_enrollment_and_revisions() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("grants.db");
    let input = temp.path().join("binding.json");
    std::fs::write(&input, r#"{"service":"gateway","issuer":"https://issuer.example/","resource":"https://gateway.example/mcp","subject":"owner","hosted_client":"hosted-client"}"#).unwrap();
    assert!(run(&state, &["init"]).status.success());
    assert!(run(&state, &["enroll", "grant", input.to_str().unwrap()])
        .status
        .success());
    assert!(matches!(
        Store::open(&state).unwrap().authorize(&binding()),
        Err(Error::Denied)
    ));
    assert!(run(&state, &["enable", "grant", "1"]).status.success());
    assert_eq!(
        Store::open(&state)
            .unwrap()
            .authorize(&binding())
            .unwrap()
            .revision,
        2
    );
    assert!(run(&state, &["disable", "grant", "2"]).status.success());
    assert!(matches!(
        Store::open(&state).unwrap().authorize(&binding()),
        Err(Error::Denied)
    ));
}

#[test]
fn unknown_stale_and_unchanged_ids_exit_nonzero_and_change_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("grants.db");
    let mut store = Store::initialize(&state).unwrap();
    store.enroll("grant", &binding()).unwrap();
    for args in [
        ["enable", "unknown", "1"],
        ["enable", "grant", "0"],
        ["disable", "grant", "1"],
    ] {
        let result = run(&state, &args);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(matches!(store.authorize(&binding()), Err(Error::Denied)));
    }
    assert_eq!(store.set_enabled("grant", 1, true).unwrap(), 2);
    let result = run(&state, &["disable", "grant", "1"]);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(store.authorize(&binding()).unwrap().revision, 2);
}

#[test]
fn missing_state_is_not_initialized_by_enable() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("missing.db");
    assert!(!run(&state, &["enable", "grant", "1"]).status.success());
    assert!(!state.exists());
}
