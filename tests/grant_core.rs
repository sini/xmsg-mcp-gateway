#[path = "common/provider.rs"]
mod provider;

use serde_json::json;
use xmsg_mcp_gateway::grants::{exact_audience, Binding, Error, Store};

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
fn exact_resource_audience() {
    let resource = "https://gateway.example/mcp";
    for value in [json!(resource), json!([resource])] {
        assert!(exact_audience(&value, resource));
    }
    for value in [
        json!("kanidm-client"),
        json!([resource, "other"]),
        json!([]),
        json!(null),
    ] {
        assert!(!exact_audience(&value, resource));
    }
}

#[test]
fn enrollment_is_disabled_and_restart_keeps_revision() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("grants.db");
    let mut store = Store::initialize(&db).unwrap();
    store.enroll("grant", &binding()).unwrap();
    assert!(matches!(
        store.authorize(&provider::verified(&binding())),
        Err(Error::Denied)
    ));
    assert_eq!(store.set_enabled("grant", 1, true).unwrap(), 2);
    assert_eq!(
        store
            .authorize(&provider::verified(&binding()))
            .unwrap()
            .revision,
        2
    );
    drop(store);
    let mut store = Store::open(&db).unwrap();
    assert_eq!(
        store
            .authorize(&provider::verified(&binding()))
            .unwrap()
            .revision,
        2
    );
    assert_eq!(store.set_enabled("grant", 2, false).unwrap(), 3);
    assert!(matches!(
        store.authorize(&provider::verified(&binding())),
        Err(Error::Denied)
    ));
    assert_eq!(store.set_enabled("grant", 3, true).unwrap(), 4);
    assert_eq!(
        store
            .authorize(&provider::verified(&binding()))
            .unwrap()
            .revision,
        4
    );
}

#[test]
fn all_binding_fields_are_required() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::initialize(&temp.path().join("grants.db")).unwrap();
    store.enroll("grant", &binding()).unwrap();
    store.set_enabled("grant", 1, true).unwrap();
    assert!(store.authorize(&provider::verified(&binding())).is_ok());
    for field in 0..5 {
        let mut foreign = binding();
        match field {
            0 => foreign.service = "hindsight".into(),
            1 => foreign.issuer = "https://foreign.example/".into(),
            2 => foreign.resource = "https://foreign.example/mcp".into(),
            3 => foreign.subject = "other-owner".into(),
            _ => foreign.hosted_client = "introspection-client".into(),
        }
        assert!(matches!(
            store.authorize(&provider::verified(&foreign)),
            Err(Error::Denied)
        ));
    }
}

#[test]
fn unknown_stale_and_noop_mutations_fail_without_changes() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::initialize(&temp.path().join("grants.db")).unwrap();
    store.enroll("grant", &binding()).unwrap();
    assert!(matches!(
        store.set_enabled("unknown", 1, true),
        Err(Error::NoChange)
    ));
    assert!(matches!(
        store.set_enabled("grant", 0, true),
        Err(Error::NoChange)
    ));
    assert!(matches!(
        store.set_enabled("grant", 1, false),
        Err(Error::NoChange)
    ));
    assert_eq!(store.set_enabled("grant", 1, true).unwrap(), 2);
    assert!(matches!(
        store.set_enabled("grant", 1, false),
        Err(Error::NoChange)
    ));
    assert_eq!(
        store
            .authorize(&provider::verified(&binding()))
            .unwrap()
            .revision,
        2
    );
}

#[test]
fn one_enabled_binding_per_service() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::initialize(&temp.path().join("grants.db")).unwrap();
    store.enroll("first", &binding()).unwrap();
    let mut other = binding();
    other.hosted_client = "other-client".into();
    store.enroll("second", &other).unwrap();
    store.set_enabled("first", 1, true).unwrap();
    assert!(matches!(
        store.set_enabled("second", 1, true),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        store.authorize(&provider::verified(&other)),
        Err(Error::Denied)
    ));
    store.set_enabled("first", 2, false).unwrap();
    assert_eq!(store.set_enabled("second", 1, true).unwrap(), 2);
    assert!(matches!(
        store.authorize(&provider::verified(&binding())),
        Err(Error::Denied)
    ));
}

#[test]
fn missing_or_unknown_database_is_not_recreated() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("missing.db");
    assert!(Store::open(&db).is_err());
    assert!(!db.exists());
    std::fs::write(&db, "not a database").unwrap();
    assert!(Store::open(&db).is_err());
}

#[test]
fn initialize_is_explicit_and_never_resets_authority() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("grants.db");
    let mut store = Store::initialize(&db).unwrap();
    store.enroll("grant", &binding()).unwrap();
    store.set_enabled("grant", 1, true).unwrap();
    assert!(Store::initialize(&db).is_err());
    assert!(store.enroll("grant", &binding()).is_err());
    assert_eq!(
        store
            .authorize(&provider::verified(&binding()))
            .unwrap()
            .revision,
        2
    );
}

#[test]
fn foreign_store_metadata_is_refused_without_reinitialization() {
    let temp = tempfile::tempdir().unwrap();
    for pragma in ["application_id", "user_version"] {
        let db = temp.path().join(pragma);
        drop(Store::initialize(&db).unwrap());
        let connection = rusqlite::Connection::open(&db).unwrap();
        let original: i64 = connection
            .pragma_query_value(None, pragma, |row| row.get(0))
            .unwrap();
        let invalid_versions = if pragma == "user_version" {
            vec![
                xmsg_mcp_gateway::grants::MAX_SUPPORTED_SCHEMA_VERSION + 1,
                -1,
            ]
        } else {
            vec![original + 1]
        };
        for invalid in invalid_versions {
            connection.pragma_update(None, pragma, invalid).unwrap();
            assert!(matches!(Store::open(&db), Err(Error::InvalidStore)));
            let remaining: i64 = connection
                .pragma_query_value(None, pragma, |row| row.get(0))
                .unwrap();
            assert_eq!(remaining, invalid);
        }
    }
}

#[test]
fn empty_and_whitespace_binding_fields_never_write_rows() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("grants.db");
    let mut store = Store::initialize(&db).unwrap();
    store.enroll("known", &binding()).unwrap();
    for blank in ["", " \t\n"] {
        for field in 0..6 {
            let mut invalid = binding();
            let id = if field == 0 { blank } else { "candidate" };
            match field {
                0 => {}
                1 => invalid.service = blank.into(),
                2 => invalid.issuer = blank.into(),
                3 => invalid.resource = blank.into(),
                4 => invalid.subject = blank.into(),
                _ => invalid.hosted_client = blank.into(),
            }
            assert!(matches!(
                store.enroll(id, &invalid),
                Err(Error::InvalidBinding)
            ));
            let rows: i64 = rusqlite::Connection::open(&db)
                .unwrap()
                .query_row("SELECT count(*) FROM grants", [], |row| row.get(0))
                .unwrap();
            assert_eq!(rows, 1);
        }
    }
    assert_eq!(store.set_enabled("known", 1, true).unwrap(), 2);
    assert_eq!(
        store
            .authorize(&provider::verified(&binding()))
            .unwrap()
            .revision,
        2
    );
}
