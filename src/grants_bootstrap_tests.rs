use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn authority_rows(connection: &Connection) -> BTreeMap<String, Vec<[u8; 32]>> {
    let names: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let mut result = BTreeMap::new();
    for table in names {
        let sql = format!("SELECT * FROM \"{}\"", table.replace('"', "\"\""));
        let mut statement = connection.prepare(&sql).unwrap();
        let columns = statement.column_count();
        let mut rows: Vec<[u8; 32]> = statement
            .query_map([], |row| {
                let values = (0..columns)
                    .map(|i| row.get::<_, rusqlite::types::Value>(i))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Sha256::digest(format!("{values:?}").as_bytes()).into())
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        rows.sort();
        result.insert(table, rows);
    }
    result
}

#[tokio::test]
async fn exact_enrollment_preserves_callbacks_policies_and_all_authority_history() {
    let setup = crate::events_test_support::Setup::new();
    let mut store = Store::open(&setup.provider.store_file).unwrap();
    let revision = store
        .set_outbound_policy(
            "grant",
            2,
            &crate::outbound::Policy {
                send: Some(crate::outbound::Permission {
                    targets: ["receiver@peer".into()].into(),
                    required_scope: "messages:send".into(),
                }),
                reply: None,
            },
        )
        .unwrap();
    assert_eq!(revision, 3);
    drop(store);
    setup.subscribe().await;
    setup.seed("retained-event", "dot@bus", revision, i64::MAX);
    let mut store = Store::open(&setup.provider.store_file).unwrap();
    if !store.migration_applied(Migration::Retirement).unwrap() {
        store.migrate_retirement().unwrap();
    }
    if !store.migration_applied(Migration::Profiles).unwrap() {
        store.migrate_profiles().unwrap();
    }
    if !store.migration_applied(Migration::Attachments).unwrap() {
        store.migrate_attachments().unwrap();
    }
    if !store
        .migration_applied(Migration::AuthorizationServer)
        .unwrap()
    {
        store.migrate_authorization_server().unwrap();
    }
    let before = authority_rows(&store.connection);
    for table in [
        "outbound_policy",
        "grants_event_history",
        "event_subscriptions",
        "event_authorizations",
        "event_occurrences",
        "custody_items",
        "custody_outbox",
    ] {
        assert!(
            !before[table].is_empty(),
            "fixture authority table {table} must be populated"
        );
    }
    let record: (i64, bool) = store
        .connection
        .query_row(
            "SELECT revision,enabled FROM grants WHERE id='grant'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let result = store
        .enroll_if_needed("grant", &setup.provider.binding)
        .unwrap();
    assert_eq!(
        authority_rows(&store.connection),
        before,
        "exact enrollment changed callback, policy or authority history"
    );
    assert_eq!(
        result,
        EnrollmentResult {
            created: false,
            revision: record.0,
            enabled: record.1
        }
    );
    for field in ["service", "issuer", "resource", "subject", "hosted_client"] {
        let mut binding = setup.provider.binding.clone();
        match field {
            "service" => binding.service = "other".into(),
            "issuer" => binding.issuer = "other".into(),
            "resource" => binding.resource = "other".into(),
            "subject" => binding.subject = "other".into(),
            "hosted_client" => binding.hosted_client = "other".into(),
            _ => unreachable!(),
        }
        let result = store.enroll_if_needed("grant", &binding);
        assert_eq!(
            authority_rows(&store.connection),
            before,
            "binding mismatch {field} changed authority history"
        );
        assert!(
            matches!(result, Err(Error::EnrollmentConflict)),
            "binding mismatch field {field} was accepted or misclassified"
        );
    }
}
