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
    match request {
        Request::Read(args) => {
            let limit = args.limit.unwrap_or(READ_MAX);
            if limit == 0
                || limit > READ_MAX
                || args.message_id.is_empty()
                || args.message_id.len() > 4096
            {
                return Err(Error::Arguments);
            }
            let sql = format!("SELECT c.upstream_id,c.mailbox,c.origin,c.in_reply_to,c.received_at,c.text
                FROM custody_items c JOIN grants g ON g.id=c.grant_id WHERE {OWNED} AND c.upstream_id=:id");
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
                "offset":offset,"text":text,"next_offset":next}),
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
                    WHERE {OWNED} AND c.event_id=:anchor"
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
            let sql = format!("SELECT c.upstream_id,c.mailbox,c.origin,c.in_reply_to,c.received_at,c.text,c.event_id
                FROM custody_items c JOIN grants g ON g.id=c.grant_id WHERE {OWNED} AND c.rowid>:after
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
                    "preview":body.chars().take(256).collect::<String>(),"body_available":true}));
                last = Some(scope.cursor(&row.get::<_, String>(6)?));
            }
            Ok(json!({"items":items,"next":next}))
        }
    }
}
