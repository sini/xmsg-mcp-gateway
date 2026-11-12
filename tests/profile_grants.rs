#[path = "common/provider.rs"]
mod provider;

use std::process::Command;
use xmsg_mcp_gateway::grants::{Binding, Error, Migration, Store};

fn binding() -> Binding {
    Binding {
        service: "gateway".into(),
        issuer: "https://issuer.example/".into(),
        resource: "https://gateway.example/mcp".into(),
        subject: "owner".into(),
        hosted_client: "client-a".into(),
    }
}

#[test]
fn migration_preserves_authority_and_exact_bindings_can_coexist() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    let mut store = Store::initialize(&file).unwrap();
    let first = binding();
    store.enroll("first", &first).unwrap();
    assert_eq!(store.set_enabled("first", 1, true).unwrap(), 2);
    assert!(store.require_profiles_ready().is_err());
    assert!(store
        .validate_profiles(std::slice::from_ref(&first))
        .is_err());
    store.migrate_profiles().unwrap();
    store.require_profiles_ready().unwrap();
    assert!(store.migration_applied(Migration::Profiles).unwrap());
    assert!(store.migrate_profiles().is_err());
    assert_eq!(
        store
            .authorize(&provider::verified(&first))
            .unwrap()
            .revision,
        2
    );
    let mut profiles = vec![first.clone()];
    for field in 0..5 {
        let mut other = first.clone();
        match field {
            0 => other.service = "other-service".into(),
            1 => other.issuer = "https://issuer-b.example/".into(),
            2 => other.resource = "https://gateway-b.example/mcp".into(),
            3 => other.subject = "other-owner".into(),
            _ => other.hosted_client = "client-b".into(),
        }
        let id = format!("other-{field}");
        store.enroll(&id, &other).unwrap();
        assert_eq!(store.set_enabled(&id, 1, true).unwrap(), 2);
        assert_eq!(
            store
                .authorize(&provider::verified(&other))
                .unwrap()
                .grant_id,
            id
        );
        profiles.push(other);
    }
    store.validate_profiles(&profiles).unwrap();
    store.enroll("duplicate", &first).unwrap();
    assert!(matches!(
        store.set_enabled("duplicate", 1, true),
        Err(Error::Conflict)
    ));
    drop(store);
    let store = Store::open_readonly(&file).unwrap();
    store.validate_profiles(&profiles).unwrap();
    assert_eq!(
        store
            .authorize(&provider::verified(&first))
            .unwrap()
            .revision,
        2
    );
}

#[test]
fn configured_profile_membership_is_exact_including_disabled_clients() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::initialize(&dir.path().join("state.db")).unwrap();
    let first = binding();
    store.enroll("first", &first).unwrap();
    store.migrate_profiles().unwrap();
    store
        .validate_profiles(std::slice::from_ref(&first))
        .unwrap();
    assert!(store.validate_profiles(&[]).is_err());
    for field in 0..5 {
        let mut wrong = first.clone();
        match field {
            0 => wrong.service.push('x'),
            1 => wrong.issuer.push('x'),
            2 => wrong.resource.push('x'),
            3 => wrong.subject.push('x'),
            _ => wrong.hosted_client.push('x'),
        }
        assert!(matches!(
            store.validate_profiles(&[wrong]),
            Err(Error::ProfileMismatch)
        ));
    }
    let mut disabled = first.clone();
    disabled.hosted_client = "disabled-client".into();
    store.enroll("disabled", &disabled).unwrap();
    assert!(store.validate_profile(&first).is_ok());
    assert!(matches!(
        store.validate_profiles(std::slice::from_ref(&first)),
        Err(Error::ProfileMismatch)
    ));
    store.validate_profiles(&[first, disabled]).unwrap();
}

#[test]
fn cli_migration_is_idempotent_and_readback_is_readonly() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    Store::initialize(&file).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
            .arg("--state")
            .arg(&file)
            .args(args)
            .output()
            .unwrap()
    };
    let before = std::fs::read(&file).unwrap();
    let pending = run(&["migrations-pending"]);
    assert_eq!(pending.status.code(), Some(10));
    assert!(String::from_utf8_lossy(&pending.stdout)
        .lines()
        .any(|s| s == "migrate-profiles"));
    assert_eq!(std::fs::read(&file).unwrap(), before);
    let migrate = run(&["migrate-profiles", "--if-needed"]);
    assert!(
        migrate.status.success(),
        "{}",
        String::from_utf8_lossy(&migrate.stderr)
    );
    assert_eq!(migrate.stdout, b"exact grant binding uniqueness migrated\n");
    let after = std::fs::read(&file).unwrap();
    let again = run(&["migrate-profiles", "--if-needed"]);
    assert!(again.status.success());
    assert_eq!(again.stdout, b"already migrated\n");
    assert_eq!(std::fs::read(&file).unwrap(), after);
    let pending = run(&["migrations-pending"]);
    assert_eq!(pending.status.code(), Some(10));
    assert!(!String::from_utf8_lossy(&pending.stdout)
        .lines()
        .any(|s| s == "migrate-profiles"));
    assert_eq!(std::fs::read(&file).unwrap(), after);
}

#[test]
fn readiness_rejects_partial_or_weakened_uniqueness_schema() {
    let dir = tempfile::tempdir().unwrap();
    for (name, sql) in [
        ("marker", "DROP TABLE grant_profiles_schema"),
        ("index", "DROP INDEX one_enabled_per_binding"),
        ("weak", "DROP INDEX one_enabled_per_binding; CREATE UNIQUE INDEX one_enabled_per_binding ON grants(service,issuer,resource,subject,hosted_client) WHERE enabled = 0"),
    ] {
        let file = dir.path().join(name);
        let mut store = Store::initialize(&file).unwrap();
        store.migrate_profiles().unwrap();
        drop(store);
        rusqlite::Connection::open(&file).unwrap().execute_batch(sql).unwrap();
        let store = Store::open(&file).unwrap();
        assert!(store.require_profiles_ready().is_err(), "accepted {name}");
        assert!(store.migration_applied(Migration::Profiles).is_err());
    }
}

#[test]
fn profile_migration_preserves_the_remaining_migration_chain() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    let key = dir.path().join("event-key");
    std::fs::write(&key, [7u8; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut store = Store::initialize(&file).unwrap();
    store.migrate_profiles().unwrap();
    store.migrate_custody().unwrap();
    store.migrate_outbound().unwrap();
    store.migrate_retirement().unwrap();
    store
        .migrate_events(&xmsg_mcp_gateway::event_store::EventKey::load(&key).unwrap())
        .unwrap();
    store.require_profiles_ready().unwrap();
    assert!(store.pending_migrations().unwrap().is_empty());
}
