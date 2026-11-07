use xmsg_mcp_gateway::grants::{Binding, Error as GrantError, Store};
use xmsg_mcp_gateway::outbound::{Error, Permission, Policy};

#[test]
fn migration_is_explicit_and_policy_is_owner_revision_checked() {
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
    let policy = Policy {
        send: Some(Permission {
            targets: ["receiver@node".into()].into(),
            required_scope: "send:write".into(),
        }),
        reply: None,
    };
    assert!(matches!(
        store.set_outbound_policy("grant", 1, &policy),
        Err(Error::MigrationRequired)
    ));
    assert!(store.migrate_outbound().is_err());
    store.migrate_custody().unwrap();
    drop(store);
    let mut store = Store::open(&file).unwrap();
    store.migrate_outbound().unwrap();
    assert!(store.migrate_outbound().is_err());
    assert_eq!(store.set_outbound_policy("grant", 1, &policy).unwrap(), 2);
    assert!(matches!(
        store.set_outbound_policy("grant", 1, &Policy::default()),
        Err(Error::Authority(GrantError::NoChange))
    ));
    assert!(matches!(
        store.set_outbound_policy("unknown", 1, &policy),
        Err(Error::Authority(GrantError::NoChange))
    ));
    assert!(matches!(
        store.set_outbound_policy("grant", 2, &policy),
        Err(Error::Authority(GrantError::NoChange))
    ));
    let sql = rusqlite::Connection::open(&file).unwrap();
    let (version, enabled): (i64, bool) = (
        sql.pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap(),
        sql.query_row("SELECT enabled FROM grants", [], |r| r.get(0))
            .unwrap(),
    );
    assert_eq!(version, 3);
    assert!(!enabled, "writing policy enabled a grant");
    drop(store);
    Store::open(&file).unwrap();
}
