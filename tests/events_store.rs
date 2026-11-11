use rusqlite::{params, Connection};
use std::os::unix::fs::PermissionsExt;
use xmsg_mcp_gateway::event_store::EventKey;
use xmsg_mcp_gateway::grants::{Binding, Store};

fn binding() -> Binding {
    Binding {
        service: "gateway".into(),
        issuer: "https://issuer.example/".into(),
        resource: "https://gateway.example/mcp".into(),
        subject: "owner".into(),
        hosted_client: "hosted".into(),
    }
}
fn key(dir: &std::path::Path, name: &str, value: u8) -> EventKey {
    let file = dir.join(name);
    std::fs::write(&file, [value; 32]).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    EventKey::load(&file).unwrap()
}
fn base() -> (tempfile::TempDir, Store, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("store.db");
    let mut store = Store::initialize(&file).unwrap();
    store.migrate_custody().unwrap();
    store.migrate_outbound().unwrap();
    store.migrate_retirement().unwrap();
    (dir, store, file)
}
fn seed(db: &Connection, id: &str, revision: i64, class: &str) {
    db.execute("INSERT INTO custody_items(bus,upstream_id,event_id,grant_id,grant_revision,mailbox,owner,origin,text,envelope,fingerprint,received_at,expires_at,held) VALUES ('bus',?1,?1,'grant',?2,'gateway@bus','owner','{}','body','envelope',?1,1,9999999999,1)",params![id,revision]).unwrap();
    db.execute(
        "INSERT INTO custody_outbox(event_id,state) VALUES (?1,'held')",
        [id],
    )
    .unwrap();
    db.execute("INSERT INTO event_authorizations(event_id,acceptance_class,acceptance_enabled,acceptance_ever_enabled,dispatch_revision) VALUES (?1,?2,0,?3,NULL)",params![id,class,if class=="never_enabled" {Some(0i64)} else {None}]).unwrap();
    db.execute("INSERT INTO event_occurrences(event_id) VALUES (?1)", [id])
        .unwrap();
}
#[test]
fn first_enable_releases_only_proven_never_enabled_and_preserves_acceptance_revision() {
    let (dir, mut store, file) = base();
    let key = key(dir.path(), "key", 1);
    store.migrate_events(&key).unwrap();
    store.enroll("grant", &binding()).unwrap();
    let db = Connection::open(file).unwrap();
    seed(&db, "first", 1, "never_enabled");
    seed(&db, "ambiguous", 1, "unknown");
    assert_eq!(store.set_enabled("grant", 1, true).unwrap(), 2);
    let row:(i64,Option<i64>,String)=db.query_row("SELECT c.grant_revision,a.dispatch_revision,a.acceptance_class FROM custody_items c JOIN event_authorizations a USING(event_id) WHERE c.event_id='first'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    assert_eq!(row, (1, Some(2), "never_enabled".into()));
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM event_release_audit WHERE event_id='first'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        db.query_row(
            "SELECT dispatch_revision FROM event_authorizations WHERE event_id='ambiguous'",
            [],
            |r| r.get::<_, Option<i64>>(0)
        )
        .unwrap(),
        None
    );
    assert_eq!(store.set_enabled("grant", 2, false).unwrap(), 3);
    assert_eq!(store.set_enabled("grant", 3, true).unwrap(), 4);
    assert_eq!(
        db.query_row(
            "SELECT dispatch_revision FROM event_authorizations WHERE event_id='first'",
            [],
            |r| r.get::<_, Option<i64>>(0)
        )
        .unwrap(),
        Some(2)
    );
}
#[test]
fn migrated_disabled_grant_history_is_unknown_not_never_enabled() {
    let (dir, mut store, file) = base();
    store.enroll("grant", &binding()).unwrap();
    let key = key(dir.path(), "key", 2);
    store.migrate_events(&key).unwrap();
    let db = Connection::open(file).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT ever_enabled FROM grants_event_history WHERE grant_id='grant'",
            [],
            |r| r.get::<_, Option<i64>>(0)
        )
        .unwrap(),
        None
    );
    seed(&db, "ambiguous", 1, "unknown");
    store.set_enabled("grant", 1, true).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT dispatch_revision FROM event_authorizations",
            [],
            |r| r.get::<_, Option<i64>>(0)
        )
        .unwrap(),
        None
    );
}
#[test]
fn migration_is_explicit_atomic_and_key_bound() {
    let (dir, mut store, file) = base();
    let key1 = key(dir.path(), "key1", 3);
    let key2 = key(dir.path(), "key2", 4);
    assert!(store.require_events_ready(&key1).is_err());
    let db = Connection::open(file).unwrap();
    db.execute_batch("CREATE TABLE event_observations(forced INTEGER);")
        .unwrap();
    assert!(store.migrate_events(&key1).is_err());
    assert_eq!(
        db.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name='grants_event_history'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    db.execute_batch("DROP TABLE event_observations;").unwrap();
    store.migrate_events(&key1).unwrap();
    assert!(store.migrate_events(&key1).is_err());
    assert!(store.require_events_ready(&key2).is_err());
    store.require_events_ready(&key1).unwrap();
    let encrypted = key1
        .seal("owner/subscription/secret", b"secret-value")
        .unwrap();
    assert!(!encrypted.windows(12).any(|part| part == b"secret-value"));
    assert_eq!(
        key1.open("owner/subscription/secret", &encrypted).unwrap(),
        b"secret-value"
    );
    assert!(key1
        .open("other-owner/subscription/secret", &encrypted)
        .is_err());
    assert!(key2.open("owner/subscription/secret", &encrypted).is_err());
    let mut changed = encrypted;
    changed[20] ^= 1;
    assert!(key1.open("owner/subscription/secret", &changed).is_err());
}

#[test]
fn migration_holds_legacy_custody_even_when_original_revision_is_current() {
    let (dir, mut store, file) = base();
    store.enroll("grant", &binding()).unwrap();
    store.set_enabled("grant", 1, true).unwrap();
    let db = Connection::open(file).unwrap();
    db.execute("INSERT INTO custody_items(bus,upstream_id,event_id,grant_id,grant_revision,mailbox,owner,origin,text,envelope,fingerprint,received_at,expires_at,held) VALUES ('bus','legacy','legacy','grant',2,'gateway@bus','owner','{}','body','envelope','legacy',1,9999999999,1)",[]).unwrap();
    db.execute("INSERT INTO custody_outbox VALUES ('legacy','held')", [])
        .unwrap();
    let key = key(dir.path(), "key", 5);
    store.migrate_events(&key).unwrap();
    assert_eq!(
        db.query_row("SELECT ever_enabled FROM grants_event_history", [], |r| {
            r.get::<_, Option<i64>>(0)
        })
        .unwrap(),
        Some(1)
    );
    let legacy: (String, Option<i64>) = db
        .query_row(
            "SELECT acceptance_class,dispatch_revision FROM event_authorizations",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(legacy, ("unknown".into(), None));
    assert_eq!(
        db.query_row("SELECT state FROM custody_outbox", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "held"
    );
}

#[test]
fn encryption_key_requires_owner_only_file_and_authenticated_ciphertext() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("key");
    std::fs::write(&file, [7u8; 32]).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(EventKey::load(&file).is_err());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let key = EventKey::load(&file).unwrap();
    let a = key.seal("same-owner", b"same plaintext").unwrap();
    let b = key.seal("same-owner", b"same plaintext").unwrap();
    assert_ne!(a, b, "fresh encryptions reused the same nonce");
    assert!(key.open("same-owner", &a[..25]).is_err());
    std::fs::write(&file, [7u8; 31]).unwrap();
    assert!(EventKey::load(&file).is_err());
}

#[test]
fn policy_revision_carries_only_current_authority_without_mutating_wakes_or_subscriptions() {
    let (dir, mut store, file) = base();
    let key = key(dir.path(), "key", 12);
    store.migrate_events(&key).unwrap();
    store.enroll("grant", &binding()).unwrap();
    store.enroll("foreign", &binding()).unwrap();
    store.set_enabled("grant", 1, true).unwrap();
    let db = Connection::open(file).unwrap();
    for (id, revision) in [
        ("pending", Some(2i64)),
        ("dispatching", Some(2)),
        ("older", Some(1)),
        ("never", None),
        ("foreign", Some(2)),
    ] {
        seed(&db, id, 2, "current");
        db.execute(
            "UPDATE event_authorizations SET dispatch_revision=?2 WHERE event_id=?1",
            params![id, revision],
        )
        .unwrap();
    }
    db.execute(
        "UPDATE custody_items SET grant_id='foreign' WHERE event_id='foreign'",
        [],
    )
    .unwrap();
    db.execute(
        "UPDATE custody_outbox SET state=event_id WHERE event_id IN ('pending','dispatching')",
        [],
    )
    .unwrap();
    db.execute("UPDATE custody_outbox SET attempts=2,next_attempt=77,body=x'010203',last_error='retry',subscription_generation=8",[]).unwrap();
    for (id, grant, revision) in [
        ("current", "grant", 2),
        ("older", "grant", 1),
        ("foreign", "foreign", 2),
    ] {
        db.execute("INSERT INTO event_subscriptions(id,owner_key,service,issuer,resource,subject,hosted_client,bus,mailbox,grant_id,grant_revision,generation,expires,url,secret,old_secret,bearer,status,rotation_until,callback_cursor,observation_checkpoint) VALUES (?1,?1,'gateway','issuer','resource','owner','hosted','bus','gateway@bus',?2,?3,8,9999999999,x'00',x'01',x'02',x'03','active',99,4,3)",params![id,grant,revision]).unwrap();
    }
    let snapshot = |query: &str| {
        let mut statement = db.prepare(query).unwrap();
        let count = statement.column_count();
        statement
            .query_map([], |row| {
                Ok((0..count)
                    .map(|i| format!("{:?}", row.get_ref(i).unwrap()))
                    .collect::<Vec<_>>())
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    let wakes = snapshot("SELECT * FROM custody_outbox ORDER BY event_id");
    let subscriptions=snapshot("SELECT id,status,generation,expires,url,secret,old_secret,bearer,rotation_until,callback_cursor,observation_checkpoint FROM event_subscriptions ORDER BY id");
    assert_eq!(
        store
            .set_outbound_policy("grant", 2, &Default::default())
            .unwrap(),
        3
    );
    assert_eq!(
        snapshot("SELECT * FROM custody_outbox ORDER BY event_id"),
        wakes,
        "policy edit fenced or reset retained wakes"
    );
    assert_eq!(snapshot("SELECT id,status,generation,expires,url,secret,old_secret,bearer,rotation_until,callback_cursor,observation_checkpoint FROM event_subscriptions ORDER BY id"),subscriptions,"policy edit mutated subscription lifecycle");
    for (id, expected) in [
        ("pending", Some(3i64)),
        ("dispatching", Some(3)),
        ("older", Some(1)),
        ("never", None),
        ("foreign", Some(2)),
    ] {
        assert_eq!(
            db.query_row(
                "SELECT dispatch_revision FROM event_authorizations WHERE event_id=?1",
                [id],
                |row| row.get::<_, Option<i64>>(0)
            )
            .unwrap(),
            expected,
            "policy promoted NULL, older or foreign authority: {id}"
        );
    }
    for (id, expected) in [("current", 3i64), ("older", 1), ("foreign", 2)] {
        assert_eq!(
            db.query_row(
                "SELECT grant_revision FROM event_subscriptions WHERE id=?1",
                [id],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            expected,
            "policy promoted stale or foreign subscription"
        );
    }
    assert_eq!(
        db.query_row("SELECT MIN(grant_revision) FROM custody_items", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        2
    );
}
