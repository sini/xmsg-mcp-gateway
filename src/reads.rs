use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::named_params;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::VerifiedIdentity;
use crate::grants::{Authorization, Store};

pub(crate) const INBOX_DEFAULT: usize = 20;
pub(crate) const INBOX_MAX: usize = 100;
pub(crate) const READ_MAX: usize = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InboxArguments {
    pub(crate) after: Option<String>,
    pub(crate) limit: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReadArguments {
    pub(crate) message_id: String,
    pub(crate) offset: Option<usize>,
    pub(crate) limit: Option<usize>,
}

pub(crate) enum Request {
    Inbox(InboxArguments),
    Read(ReadArguments),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("invalid read arguments or unavailable cursor")]
    Arguments,
    #[error(transparent)]
    Authority(#[from] crate::grants::Error),
    #[error("custody read unavailable")]
    Database(#[from] rusqlite::Error),
    #[error("custody record encoding unavailable")]
    Encoding(#[from] serde_json::Error),
}

const OWNED: &str = "c.bus=:bus AND c.mailbox=:mailbox AND c.owner=:owner
    AND g.service=:service AND g.issuer=:issuer AND g.resource=:resource
    AND g.hosted_client=:client AND g.subject=:owner AND g.enabled=1
    AND c.grant_id=:grant AND c.grant_revision=:revision
    AND c.text IS NOT NULL AND c.expires_at>:now";

struct Scope<'a> {
    bus: &'a str,
    mailbox: &'a str,
    identity: &'a VerifiedIdentity,
    authority: Authorization,
}

impl Scope<'_> {
    fn cursor(&self, event_id: &str) -> String {
        let digest = crate::custody::fingerprint(&[
            self.bus,
            self.mailbox,
            self.identity.service(),
            self.identity.issuer(),
            self.identity.resource(),
            self.identity.subject(),
            self.identity.hosted_client(),
            &self.authority.grant_id,
            &self.authority.revision.to_string(),
            event_id,
        ]);
        format!("{event_id}.{digest}")
    }
}

pub(crate) fn dispatch(
    store: Store,
    identity: &VerifiedIdentity,
    bus: &str,
    mailbox: &str,
    request: Request,
) -> Result<Value, Error> {
    // One read transaction pins authorization and content to the same grant revision.
    let _transaction = store.connection.unchecked_transaction()?;
    let scope = Scope {
        bus,
        mailbox,
        identity,
        authority: store.authorize(identity)?,
    };
    let version: i64 = store
        .connection
        .pragma_query_value(None, "user_version", |r| r.get(0))?;
    let owned = if version >= crate::grants::EVENTS_SCHEMA_VERSION {
        OWNED.replace("c.grant_revision=:revision", "EXISTS(SELECT 1 FROM event_authorizations ea WHERE ea.event_id=c.event_id AND ea.dispatch_revision=:revision)")
    } else {
        OWNED.to_owned()
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Arguments)?
        .as_secs();
    let now = i64::try_from(now).map_err(|_| Error::Arguments)?;
    let parameters = named_params! {
        ":bus":scope.bus, ":mailbox":scope.mailbox, ":owner":scope.identity.subject(),
        ":service":scope.identity.service(), ":issuer":scope.identity.issuer(),
        ":resource":scope.identity.resource(), ":client":scope.identity.hosted_client(),
        ":grant":scope.authority.grant_id, ":revision":scope.authority.revision, ":now":now,
    };
    let refs_column = if crate::attachment_store::ready(&store.connection)? {
        "c.attachments"
    } else {
        "'[]'"
    };
    let result: Result<Value, Error> = match request {
        Request::Read(args) => {
            let limit = args.limit.unwrap_or(READ_MAX);
            if limit == 0
                || limit > READ_MAX
                || args.message_id.is_empty()
                || args.message_id.len() > 4096
            {
                return Err(Error::Arguments);
            }
            let sql = format!("SELECT c.upstream_id,c.mailbox,c.origin,c.in_reply_to,c.received_at,c.text,{refs_column}
                FROM custody_items c JOIN grants g ON g.id=c.grant_id WHERE {owned} AND c.upstream_id=:id");
            let mut query = store.connection.prepare(&sql)?;
            query.raw_bind_parameter(query.parameter_index(":id")?.unwrap(), &args.message_id)?;
            for (name, value) in parameters {
                query.raw_bind_parameter(query.parameter_index(name)?.unwrap(), *value)?;
            }
            let mut rows = query.raw_query();
            let Some(row) = rows.next()? else {
                return Ok(json!({"state":"not_found"}));
            };
            let body: String = row.get(5)?;
            let offset = args.offset.unwrap_or(0);
            let mut characters = body.chars().skip(offset);
            let text: String = characters.by_ref().take(limit).collect();
            let next = characters.next().map(|_| offset + text.chars().count());
            Ok(
                json!({"state":"found","message_id":row.get::<_,String>(0)?,"mailbox":row.get::<_,String>(1)?,
                "origin":serde_json::from_str::<Value>(&row.get::<_,String>(2)?)?,
                "in_reply_to":row.get::<_,Option<String>>(3)?,"received_at":row.get::<_,i64>(4)?,
                "offset":offset,"text":text,"next_offset":next,"attachments":serde_json::from_str::<Vec<xmsg::client::AttachmentRef>>(&row.get::<_,String>(6)?)?}),
            )
        }
        Request::Inbox(args) => {
            let limit = args.limit.unwrap_or(INBOX_DEFAULT);
            if limit == 0 || limit > INBOX_MAX {
                return Err(Error::Arguments);
            }
            let mut after = 0i64;
            if let Some(cursor) = args.after {
                if cursor.len() > 256 {
                    return Err(Error::Arguments);
                }
                let (event_id, _) = cursor.split_once('.').ok_or(Error::Arguments)?;
                if scope.cursor(event_id) != cursor {
                    return Err(Error::Arguments);
                }
                let sql = format!(
                    "SELECT c.rowid FROM custody_items c JOIN grants g ON g.id=c.grant_id
                    WHERE {owned} AND c.event_id=:anchor"
                );
                let mut query = store.connection.prepare(&sql)?;
                query.raw_bind_parameter(query.parameter_index(":anchor")?.unwrap(), event_id)?;
                for (name, value) in parameters {
                    query.raw_bind_parameter(query.parameter_index(name)?.unwrap(), *value)?;
                }
                after = query
                    .raw_query()
                    .next()?
                    .map(|row| row.get(0))
                    .transpose()?
                    .ok_or(Error::Arguments)?;
            }
            let sql = format!("SELECT c.upstream_id,c.mailbox,c.origin,c.in_reply_to,c.received_at,c.text,c.event_id,{refs_column}
                FROM custody_items c JOIN grants g ON g.id=c.grant_id WHERE {owned} AND c.rowid>:after
                ORDER BY c.rowid LIMIT :limit");
            let mut query = store.connection.prepare(&sql)?;
            query.raw_bind_parameter(query.parameter_index(":after")?.unwrap(), after)?;
            query.raw_bind_parameter(
                query.parameter_index(":limit")?.unwrap(),
                (limit + 1) as i64,
            )?;
            for (name, value) in parameters {
                query.raw_bind_parameter(query.parameter_index(name)?.unwrap(), *value)?;
            }
            let mut rows = query.raw_query();
            let mut items = Vec::new();
            let mut last = None;
            let mut next = None;
            while let Some(row) = rows.next()? {
                if items.len() == limit {
                    next = last;
                    break;
                }
                let body: String = row.get(5)?;
                items.push(json!({"message_id":row.get::<_,String>(0)?,"mailbox":row.get::<_,String>(1)?,
                    "origin":serde_json::from_str::<Value>(&row.get::<_,String>(2)?)?,
                    "in_reply_to":row.get::<_,Option<String>>(3)?,"received_at":row.get::<_,i64>(4)?,
                    "preview":body.chars().take(256).collect::<String>(),"body_available":true,"attachments":serde_json::from_str::<Vec<xmsg::client::AttachmentRef>>(&row.get::<_,String>(7)?)?}));
                last = Some(scope.cursor(&row.get::<_, String>(6)?));
            }
            Ok(json!({"items":items,"next":next}))
        }
    };
    let mut value = result?;
    if version >= crate::grants::EVENTS_SCHEMA_VERSION {
        let owner = crate::events::owner_key(identity, bus, mailbox, &scope.authority.grant_id);
        let state = crate::event_status::subscription_state(&store.connection, &owner, now)?;
        let mut subscription = json!({"state":state});
        crate::event_status::add_renewal_reason(&mut subscription, state);
        value["events_status"] = json!({"subscription":subscription});
    }
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn correlated(
    store: &Store,
    identity: &VerifiedIdentity,
    authority: &Authorization,
    bus: &str,
    mailbox: &str,
    correlation: &str,
    service: &str,
    node: &str,
    max_bytes: usize,
) -> Result<(Vec<String>, bool), crate::outbound::Error> {
    let version: i64 = store
        .connection
        .pragma_query_value(None, "user_version", |r| r.get(0))?;
    let owned = if version >= crate::grants::EVENTS_SCHEMA_VERSION {
        OWNED.replace("c.grant_revision=:revision", "EXISTS(SELECT 1 FROM event_authorizations ea WHERE ea.event_id=c.event_id AND ea.dispatch_revision=:revision)")
    } else {
        OWNED.to_owned()
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| crate::outbound::Error::Configuration)?
        .as_secs()
        .min(i64::MAX as u64) as i64;
    let owned = owned.replace("AND c.text IS NOT NULL AND c.expires_at>:now", "");
    let sql=format!("SELECT c.origin,CASE WHEN c.expires_at>:now AND length(CAST(c.text AS BLOB))<=:max_bytes THEN c.text ELSE NULL END FROM custody_items c JOIN grants g ON g.id=c.grant_id WHERE {owned} AND c.in_reply_to=:correlation ORDER BY c.rowid");
    let mut query = store.connection.prepare(&sql)?;
    let rows=query.query_map(named_params!{":bus":bus,":mailbox":mailbox,":owner":identity.subject(),":service":identity.service(),":issuer":identity.issuer(),":resource":identity.resource(),":client":identity.hosted_client(),":grant":authority.grant_id,":revision":authority.revision,":now":now,":correlation":correlation,":max_bytes":max_bytes as i64},|r|Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?)))?;
    let mut result = Vec::new();
    let mut unavailable = false;
    for row in rows {
        let (raw, text) = row?;
        let Ok(origin) = serde_json::from_str::<xmsg::client::Origin>(&raw) else {
            continue;
        };
        if origin.id.is_none() && origin.service.as_deref() == Some(service) && origin.node == node
        {
            if let Some(text) = text {
                result.push(text);
            } else {
                unavailable = true;
            }
        }
    }
    Ok((result, unavailable))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn owned_attachment(
    store: &Store,
    identity: &VerifiedIdentity,
    bus: &str,
    mailbox: &str,
    message_id: &str,
    index: usize,
) -> Result<Option<xmsg::client::AttachmentRef>, Error> {
    use rusqlite::OptionalExtension;
    if message_id.is_empty() || message_id.len() > 4096 || index >= 8 {
        return Err(Error::Arguments);
    }
    let _transaction = store.connection.unchecked_transaction()?;
    let authority = store.authorize(identity)?;
    let version: i64 = store
        .connection
        .pragma_query_value(None, "user_version", |r| r.get(0))?;
    let owned = if version >= crate::grants::EVENTS_SCHEMA_VERSION {
        OWNED.replace("c.grant_revision=:revision","EXISTS(SELECT 1 FROM event_authorizations ea WHERE ea.event_id=c.event_id AND ea.dispatch_revision=:revision)")
    } else {
        OWNED.to_string()
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Arguments)?
        .as_secs();
    let now = i64::try_from(now).map_err(|_| Error::Arguments)?;
    let column = if crate::attachment_store::ready(&store.connection)? {
        "c.attachments"
    } else {
        "'[]'"
    };
    let sql=format!("SELECT {column} FROM custody_items c JOIN grants g ON g.id=c.grant_id WHERE {owned} AND c.upstream_id=:id");
    let refs:Option<String>=store.connection.query_row(&sql,named_params!{
        ":bus":bus,":mailbox":mailbox,":owner":identity.subject(),":service":identity.service(),
        ":issuer":identity.issuer(),":resource":identity.resource(),":client":identity.hosted_client(),
        ":grant":authority.grant_id,":revision":authority.revision,":now":now,":id":message_id,
    },|r|r.get(0)).optional()?;
    refs.map(|refs| {
        serde_json::from_str::<Vec<xmsg::client::AttachmentRef>>(&refs)
            .map(|refs| refs.get(index).cloned())
    })
    .transpose()
    .map_err(Error::Encoding)
    .map(Option::flatten)
}

#[cfg(all(test, unix))]
mod attachment_ownership_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn attachment_selection_uses_full_ownership_and_events_dispatch_revision() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = directory.path().join("authority.db");
        let mut store = Store::initialize(&file).unwrap();
        let binding = crate::grants::Binding {
            service: "gateway".into(),
            issuer: "https://issuer.example/".into(),
            resource: "https://gateway.example/mcp".into(),
            subject: "owner".into(),
            hosted_client: "client".into(),
        };
        let identity = crate::provider_fixture::verify_response(
            &binding,
            crate::provider_fixture::claims(&binding),
            200,
        )
        .unwrap();
        store.enroll("grant", &binding).unwrap();
        store.migrate_custody().unwrap();
        store.migrate_outbound().unwrap();
        store.set_enabled("grant", 1, true).unwrap();
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 600;
        store.connection.execute("INSERT INTO custody_items VALUES ('bus','item','event','grant',2,'gateway@node','owner','{}','text','envelope',NULL,'fingerprint',1,?1,1)",[expiry]).unwrap();
        assert!(
            owned_attachment(&store, &identity, "bus", "gateway@node", "item", 0)
                .unwrap()
                .is_none()
        );
        store.migrate_attachments().unwrap();
        let reference = xmsg::client::AttachmentRef {
            name: "file.txt".into(),
            size: 4,
            media_type: "text/plain".into(),
            sha256: "a".repeat(64),
        };
        store
            .connection
            .execute(
                "UPDATE custody_items SET attachments=?1",
                [serde_json::to_string(&vec![reference.clone()]).unwrap()],
            )
            .unwrap();
        assert_eq!(
            owned_attachment(&store, &identity, "bus", "gateway@node", "item", 0).unwrap(),
            Some(reference.clone())
        );
        for (bus, mailbox, id, index) in [
            ("other", "gateway@node", "item", 0),
            ("bus", "other@node", "item", 0),
            ("bus", "gateway@node", "missing", 0),
            ("bus", "gateway@node", "item", 1),
        ] {
            assert!(
                owned_attachment(&store, &identity, bus, mailbox, id, index)
                    .unwrap()
                    .is_none(),
                "foreign custody scope leaked attachment"
            );
        }
        assert!(owned_attachment(&store, &identity, "bus", "gateway@node", "item", 8).is_err());
        for (assignment, restore) in [
            ("owner='other'", "owner='owner'"),
            ("grant_revision=1", "grant_revision=2"),
            ("text=NULL", "text='text'"),
            ("expires_at=0", ""),
        ] {
            store
                .connection
                .execute(&format!("UPDATE custody_items SET {assignment}"), [])
                .unwrap();
            assert!(
                owned_attachment(&store, &identity, "bus", "gateway@node", "item", 0)
                    .unwrap()
                    .is_none(),
                "stale/redacted/foreign row leaked attachment"
            );
            if restore.is_empty() {
                store
                    .connection
                    .execute("UPDATE custody_items SET expires_at=?1", [expiry])
                    .unwrap();
            } else {
                store
                    .connection
                    .execute(&format!("UPDATE custody_items SET {restore}"), [])
                    .unwrap();
            }
        }
        let message = dispatch(
            Store::open(&file).unwrap(),
            &identity,
            "bus",
            "gateway@node",
            Request::Read(ReadArguments {
                message_id: "item".into(),
                offset: None,
                limit: None,
            }),
        )
        .unwrap();
        assert_eq!(message["attachments"][0]["name"], "file.txt");
        let inbox = dispatch(
            Store::open(&file).unwrap(),
            &identity,
            "bus",
            "gateway@node",
            Request::Inbox(InboxArguments {
                after: None,
                limit: None,
            }),
        )
        .unwrap();
        assert_eq!(
            inbox["items"][0]["attachments"][0]["sha256"],
            reference.sha256
        );
        let keyfile = directory.path().join("events.key");
        std::fs::write(&keyfile, [7u8; 32]).unwrap();
        std::fs::set_permissions(&keyfile, std::fs::Permissions::from_mode(0o600)).unwrap();
        store
            .migrate_events(&crate::event_store::EventKey::load(&keyfile).unwrap())
            .unwrap();
        store
            .connection
            .execute("UPDATE custody_items SET grant_revision=1", [])
            .unwrap();
        assert!(
            owned_attachment(&store, &identity, "bus", "gateway@node", "item", 0)
                .unwrap()
                .is_none()
        );
        store
            .connection
            .execute("UPDATE event_authorizations SET dispatch_revision=2", [])
            .unwrap();
        assert_eq!(
            owned_attachment(&store, &identity, "bus", "gateway@node", "item", 0).unwrap(),
            Some(reference)
        );
        store
            .connection
            .execute("UPDATE event_authorizations SET dispatch_revision=3", [])
            .unwrap();
        assert!(
            owned_attachment(&store, &identity, "bus", "gateway@node", "item", 0)
                .unwrap()
                .is_none()
        );
        store.set_enabled("grant", 2, false).unwrap();
        assert!(matches!(
            owned_attachment(&store, &identity, "bus", "gateway@node", "item", 0),
            Err(Error::Authority(crate::grants::Error::Denied))
        ));
    }
}
