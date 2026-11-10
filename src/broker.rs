//! Gist broker transport through the existing outbound reservation and owned custody.
use crate::auth::VerifiedIdentity;
use crate::grants::{Authorization, Store};
use crate::outbound::{Policy, RequestId, SendArguments};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::{json, Value};

pub(crate) const NAMES: [&str; 4] = ["gist", "gist_read", "gist_update", "gist_comment"];
const MAX_RESULT_BYTES: usize = 65_536;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) destination: String,
}
impl Config {
    pub(crate) fn origin(&self) -> Option<(&str, &str)> {
        let (service, node) = self.destination.split_once('@')?;
        if xmsg::client::validate_service_name(service).is_err()
            || node.is_empty()
            || node.contains('@')
            || node.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return None;
        }
        Some((service, node))
    }
    pub(crate) fn permitted(
        &self,
        policy: &Policy,
        grant: &Authorization,
        selected: &str,
        verifier: &crate::auth::Verifier,
    ) -> bool {
        grant.grant_id == selected
            && policy.send.as_ref().is_some_and(|p| {
                p.targets.contains(&self.destination) && verifier.requires_scope(&p.required_scope)
            })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid gist broker arguments")]
pub struct Arguments;

fn gist_id(value: &str) -> Option<String> {
    let valid =
        |s: &str| !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
    if value.len() > 4096 || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    if valid(value) {
        return Some(value.to_ascii_lowercase());
    }
    let url = reqwest::Url::parse(value).ok()?;
    if url.scheme() != "https"
        || url.host_str() != Some("gist.github.com")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    let authority = value.split_once("://")?.1.split(['/', '?', '#']).next()?;
    if authority.contains(['@', ':']) {
        return None;
    }
    let gist_path = url.path().strip_prefix('/')?;
    let gist_path = gist_path.strip_suffix('/').unwrap_or(gist_path);
    let parts: Vec<_> = gist_path.split('/').collect();
    let id = match parts.as_slice() {
        [id] => *id,
        [owner, id]
            if !owner.is_empty()
                && owner.len() <= 39
                && owner
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && owner.as_bytes()[0].is_ascii_alphanumeric() =>
        {
            *id
        }
        _ => return None,
    };
    valid(id).then(|| id.to_ascii_lowercase())
}
fn files(value: &Value) -> bool {
    value.as_object().is_some_and(|files| {
        !files.is_empty()
            && files.iter().all(|(name, value)| {
                !name.is_empty()
                    && !name.starts_with(['/', '-'])
                    && !name.contains(['\0', '\\', '/'])
                    && name != "."
                    && name != ".."
                    && value.is_string()
            })
    })
}
fn proposal(kind: &str, value: &Value) -> bool {
    let Some(fields) = value.as_object() else {
        return false;
    };
    let (allowed, required): (&[&str], &[&str]) = match kind {
        "gist" => (
            &["kind", "title", "body", "files", "public"],
            &["title", "body", "files"],
        ),
        "gist_read" => (&["kind", "id"], &["id"]),
        "gist_update" => (&["kind", "id", "title", "files"], &["id", "files"]),
        "gist_comment" => (&["kind", "id", "body"], &["id", "body"]),
        _ => return false,
    };
    fields.keys().all(|key| allowed.contains(&key.as_str()))
        && required.iter().all(|key| fields.contains_key(*key))
        && value["kind"] == kind
        && fields
            .get("id")
            .is_none_or(|id| id.as_str().and_then(gist_id).is_some())
        && fields.get("files").is_none_or(files)
        && fields.get("public").is_none_or(Value::is_boolean)
        && fields.get("title").is_none_or(|s| {
            s.as_str().is_some_and(|s| {
                if kind == "gist" {
                    !s.is_empty()
                } else {
                    !s.trim().is_empty()
                }
            })
        })
        && fields.get("body").is_none_or(|s| {
            s.as_str()
                .is_some_and(|s| kind != "gist_comment" || !s.trim().is_empty())
        })
}
/// Validate typed MCP arguments and serialize only the existing Proposal, never a caller destination.
pub fn parse(
    kind: &str,
    mut arguments: Value,
    destination: &str,
) -> Result<SendArguments, Arguments> {
    let fields = arguments.as_object_mut().ok_or(Arguments)?;
    let request_id = fields
        .remove("request_id")
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or(Arguments)?;
    if fields.contains_key("kind") {
        return Err(Arguments);
    }
    fields.insert("kind".into(), json!(kind));
    if !proposal(kind, &arguments) {
        return Err(Arguments);
    }
    Ok(SendArguments {
        request_id: RequestId::parse(&request_id).map_err(|_| Arguments)?,
        to: destination.to_owned(),
        text: serde_json::to_string(&arguments).map_err(|_| Arguments)?,
    })
}

pub(crate) fn catalog() -> Vec<Value> {
    NAMES.into_iter().map(|name| {
        let mut properties=json!({"request_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}});
        let mut required=vec!["request_id"];
        if name!="gist" { properties["id"]=json!({"type":"string","minLength":1,"maxLength":4096});required.push("id"); }
        if matches!(name,"gist"|"gist_update") {properties["files"]=json!({"type":"object","minProperties":1,"additionalProperties":{"type":"string"}});required.push("files");properties["title"]=json!({"type":"string","minLength":1});}
        if name=="gist" { required.extend(["title","body"]);properties["public"]=json!({"type":"boolean","default":false}); }
        if matches!(name,"gist"|"gist_comment") {properties["body"]=json!({"type":"string"});if name=="gist_comment"{required.push("body");}}
        json!({"name":name,"description":"Call the configured gist broker using a durable request_id. Retrying requires identical arguments and the same request_id; a pending or unknown submission does not prove completion.","inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},"annotations":{"readOnlyHint":name=="gist_read","destructiveHint":false,"openWorldHint":true,"idempotentHint":true}})
    }).collect()
}

fn action(text: &str, expected: &Value) -> Option<Value> {
    if text.len() > MAX_RESULT_BYTES {
        return None;
    }
    let value: Value = serde_json::from_str(text).ok()?;
    let fields = value.as_object()?;
    if fields.keys().any(|key| {
        !["thread", "acted", "reason", "redactions", "url", "gist"].contains(&key.as_str())
    }) || !value["thread"].is_string()
        || !value["acted"].is_boolean()
        || !value["reason"].is_string()
        || !value["redactions"].as_array()?.iter().all(Value::is_string)
    {
        return None;
    }
    if !value["acted"].as_bool()? {
        return (!fields.contains_key("gist") && !fields.contains_key("url")).then_some(value);
    }
    let url = value["url"].as_str()?;
    if !url.starts_with("https://gist.github.com/") {
        return None;
    }
    let parsed = reqwest::Url::parse(url).ok()?;
    if parsed.query().is_some() {
        return None;
    }
    if expected["kind"] == "gist_comment" {
        let comment = parsed.fragment()?.strip_prefix("gistcomment-")?;
        if comment.is_empty()
            || !comment.bytes().all(|b| b.is_ascii_digit())
            || comment.bytes().all(|b| b == b'0')
        {
            return None;
        }
    } else if parsed.fragment().is_some() {
        return None;
    }
    let id = gist_id(url)?;
    if expected["kind"] != "gist" && gist_id(expected["id"].as_str()?)? != id {
        return None;
    }
    if expected["kind"] == "gist_read" {
        let gist = value["gist"].as_object()?;
        if gist.len() != 7
            || gist.get("untrusted") != Some(&Value::Bool(true))
            || gist.get("id")?.as_str()? != id
            || gist.get("url")?.as_str()? != url
            || !gist.get("description")?.is_string()
            || gist.get("revision")?.as_str().is_none_or(|s| s.is_empty())
            || !gist.get("owner").is_some_and(|o| {
                o.is_null()
                    || o.as_str().is_some_and(|s| {
                        !s.is_empty()
                            && s.len() <= 39
                            && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    })
            })
            || !gist
                .get("files")?
                .as_object()
                .is_some_and(|f| !f.is_empty() && f.values().all(Value::is_string))
        {
            return None;
        }
    } else if fields.contains_key("gist") {
        return None;
    }
    Some(value)
}

/// Read the full authenticated result from durable custody; never modify it or submit work.
#[allow(clippy::too_many_arguments)]
pub(crate) fn lookup(
    store: &Store,
    identity: &VerifiedIdentity,
    bus: &str,
    mailbox: &str,
    selected: &str,
    config: &Config,
    request_id: &str,
    limits: &crate::outbound::Limits,
    verifier: &crate::auth::Verifier,
) -> Result<Option<Value>, crate::outbound::Error> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| crate::outbound::Error::Configuration)?
        .as_secs();
    if identity.expires_at() <= now {
        return Err(crate::outbound::Error::Authentication(
            crate::auth::Error::InvalidToken,
        ));
    }
    let _transaction = store.connection.unchecked_transaction()?;
    let authority = store.authorize(identity)?;
    let policy = store.outbound_policy(&authority.grant_id)?;
    let owner = crate::custody::fingerprint(&[
        identity.service(),
        identity.issuer(),
        identity.resource(),
        identity.subject(),
    ]);
    if store.outbound_recovery_expired(&owner, request_id, mailbox, &authority.grant_id, limits)? {
        return Ok(None);
    }
    let row:Option<(String,String,Option<String>,Option<i64>)>=store.connection.query_row("SELECT target,framed_text,receipt,recovery_until FROM outbound_reservations WHERE owner=?1 AND operation='send' AND request_id=?2 AND sender=?3 AND grant_id=?4",rusqlite::params![owner,request_id,mailbox,authority.grant_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let Some((target, framed, Some(receipt), recovery_until)) = row else {
        return Ok(None);
    };
    if recovery_until.ok_or(crate::outbound::Error::Busy)? <= i64::try_from(now).unwrap_or(i64::MAX)
    {
        return Ok(None);
    }
    if target != config.destination {
        return Ok(None);
    }
    if !config.permitted(&policy, &authority, selected, verifier) {
        return Err(crate::outbound::Error::Denied);
    }
    let Some((_, text)) = framed.split_once('\n') else {
        return Ok(None);
    };
    let expected: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    let Some(kind) = expected["kind"].as_str() else {
        return Ok(None);
    };
    if !proposal(kind, &expected) {
        return Ok(None);
    }
    let receipt: crate::outbound::Receipt = serde_json::from_str(&receipt)?;
    let crate::outbound::Receipt::Send(receipt) = receipt else {
        return Ok(None);
    };
    let (service, node) = config
        .origin()
        .ok_or(crate::outbound::Error::Configuration)?;
    let (texts, unavailable) = crate::reads::correlated(
        store,
        identity,
        &authority,
        bus,
        mailbox,
        &receipt.message_id,
        service,
        node,
        limits.max_framed_bytes.min(MAX_RESULT_BYTES),
    )?;
    let mut found: Option<(String, Value)> = None;
    for text in texts {
        if let Some(value) = action(&text, &expected) {
            if found.as_ref().is_some_and(|(old, _)| old != &text) {
                return Ok(Some(
                    json!({"state":"unknown","reason":"conflicting authenticated broker results","reconciliation_required":true}),
                ));
            }
            found = Some((text, value));
        }
    }
    Ok(found.map(|(_, value)| json!({"state":"confirmed","result":value})).or_else(||unavailable.then(||json!({"state":"unknown","reason":"authenticated broker result unavailable or exceeds bound","reconciliation_required":true}))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events_test_support::Setup;
    use std::collections::BTreeSet;
    fn limits(bound: usize) -> crate::outbound::Limits {
        crate::outbound::Limits {
            dedup_lifetime_secs: 86400,
            result_recovery_secs: 86400,
            max_framed_bytes: bound,
            timeout: std::time::Duration::from_secs(1),
            max_reservations: 100,
            max_retained_bytes: 1048576,
        }
    }
    fn result(content: &str) -> String {
        json!({"thread":"delegated-gateway","acted":true,"reason":"read","redactions":[],"url":"https://gist.github.com/abc","gist":{"untrusted":true,"id":"abc","url":"https://gist.github.com/abc","description":"example","owner":null,"revision":"revision","files":{"resource":content}}}).to_string()
    }
    async fn setup() -> (Setup, VerifiedIdentity, Config) {
        let setup = Setup::new();
        let identity = setup.verifier.verify("good-token").await.unwrap();
        let mut store = Store::open(&setup.provider.store_file).unwrap();
        store.migrate_retirement().unwrap();
        store
            .set_outbound_policy(
                "grant",
                2,
                &Policy {
                    send: Some(crate::outbound::Permission {
                        targets: BTreeSet::from(["genie@node".into()]),
                        required_scope: "identity:read".into(),
                    }),
                    reply: None,
                },
            )
            .unwrap();
        let owner = crate::custody::fingerprint(&[
            identity.service(),
            identity.issuer(),
            identity.resource(),
            identity.subject(),
        ]);
        let receipt =
            serde_json::to_string(&crate::outbound::Receipt::Send(xmsg::client::SendResult {
                message_id: "request-wire".into(),
                address: "genie@node".into(),
                outcome: "queued".into(),
            }))
            .unwrap();
        store.connection.execute("INSERT INTO outbound_reservations(owner,operation,request_id,payload_hash,sender,grant_id,grant_revision,idempotency_key,target,framed_text,created_at,retry_until,state,receipt) VALUES (?1,'send','read-1','hash','dot@bus','grant',3,'key','genie@node',?2,1,9999999999,'confirmed',?3)",rusqlite::params![owner,"[External message via dot@bus; gateway correlation key]\n{\"id\":\"abc\",\"kind\":\"gist_read\"}",receipt]).unwrap();
        store.connection.execute("UPDATE outbound_reservations SET created_at=?1,recovery_until=?1+86400,retry_until=MIN(retry_until,?1+86400)", [crate::webhook::signing_time().unwrap()]).unwrap();
        (
            setup,
            identity,
            Config {
                destination: "genie@node".into(),
            },
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn seed(
        setup: &Setup,
        id: &str,
        body: &str,
        origin: Value,
        correlation: &str,
        mailbox: &str,
        revision: i64,
        expiry: i64,
    ) {
        setup.seed(id, mailbox, revision, expiry);
        setup
            .db()
            .execute(
                "UPDATE custody_items SET text=?1,origin=?2,in_reply_to=?3 WHERE event_id=?4",
                rusqlite::params![body, origin.to_string(), correlation, id],
            )
            .unwrap();
    }
    fn read(
        setup: &Setup,
        identity: &VerifiedIdentity,
        config: &Config,
        bound: usize,
    ) -> Option<Value> {
        lookup(
            &Store::open(&setup.provider.store_file).unwrap(),
            identity,
            "bus",
            "dot@bus",
            "grant",
            config,
            "read-1",
            &limits(bound),
            &setup.verifier,
        )
        .unwrap()
    }
    #[tokio::test]
    async fn broker_full_custody_requires_origin_correlation_owner_revision_retention_and_size() {
        let (setup, identity, config) = setup().await;
        let body = result(&"é".repeat(6000));
        let good = json!({"id":null,"service":"genie","node":"node"});
        for (id, origin, correlation, mailbox, revision, expiry) in [
            (
                "wrong-node",
                json!({"id":null,"service":"genie","node":"foreign"}),
                "request-wire",
                "dot@bus",
                3,
                i64::MAX,
            ),
            (
                "session",
                json!({"id":"pretender","service":"genie","node":"node"}),
                "request-wire",
                "dot@bus",
                3,
                i64::MAX,
            ),
            (
                "wrong-service",
                json!({"id":null,"service":"other","node":"node"}),
                "request-wire",
                "dot@bus",
                3,
                i64::MAX,
            ),
            (
                "wrong-correlation",
                good.clone(),
                "other-wire",
                "dot@bus",
                3,
                i64::MAX,
            ),
            (
                "foreign-mailbox",
                good.clone(),
                "request-wire",
                "foreign@bus",
                3,
                i64::MAX,
            ),
            (
                "old-revision",
                good.clone(),
                "request-wire",
                "dot@bus",
                2,
                i64::MAX,
            ),
            ("expired", good.clone(), "request-wire", "dot@bus", 3, 1),
        ] {
            seed(
                &setup,
                id,
                &body,
                origin,
                correlation,
                mailbox,
                revision,
                expiry,
            );
            if id == "expired" {
                assert_eq!(
                    read(&setup, &identity, &config, 65536).unwrap()["state"],
                    "unknown"
                );
            } else {
                assert!(
                    read(&setup, &identity, &config, 65536).is_none(),
                    "accepted {id}"
                );
            }
        }
        seed(
            &setup,
            "good",
            &body,
            good.clone(),
            "request-wire",
            "dot@bus",
            3,
            i64::MAX,
        );
        let found = read(&setup, &identity, &config, 65536).unwrap();
        assert_eq!(
            found["result"]["gist"]["files"]["resource"],
            "é".repeat(6000)
        );
        assert_eq!(
            read(&setup, &identity, &config, 4096).unwrap()["state"],
            "unknown",
            "complete serialized result bypassed negotiated bound"
        );
        seed(
            &setup,
            "duplicate",
            &body,
            good.clone(),
            "request-wire",
            "dot@bus",
            3,
            i64::MAX,
        );
        assert_eq!(read(&setup, &identity, &config, 65536).unwrap(), found);
        seed(
            &setup,
            "conflict",
            &result("different"),
            good,
            "request-wire",
            "dot@bus",
            3,
            i64::MAX,
        );
        assert_eq!(
            read(&setup, &identity, &config, 65536).unwrap()["state"],
            "unknown"
        );
    }
    #[tokio::test]
    async fn broker_result_rechecks_current_ceiling_and_selected_grant() {
        let (setup, identity, config) = setup().await;
        seed(
            &setup,
            "good",
            &result("safe"),
            json!({"id":null,"service":"genie","node":"node"}),
            "request-wire",
            "dot@bus",
            3,
            i64::MAX,
        );
        let store = Store::open(&setup.provider.store_file).unwrap();
        assert!(lookup(
            &store,
            &identity,
            "bus",
            "dot@bus",
            "foreign",
            &config,
            "read-1",
            &limits(65536),
            &setup.verifier
        )
        .is_err());
        setup
            .db()
            .execute(
                "UPDATE outbound_policy SET document=?1 WHERE grant_id='grant'",
                [serde_json::to_string(&Policy::default()).unwrap()],
            )
            .unwrap();
        assert!(lookup(
            &store,
            &identity,
            "bus",
            "dot@bus",
            "grant",
            &config,
            "read-1",
            &limits(65536),
            &setup.verifier
        )
        .is_err());
    }
    #[tokio::test]
    async fn broker_result_does_not_expose_expired_or_uninitialized_live_reservations() {
        let (setup, identity, config) = setup().await;
        seed(
            &setup,
            "good",
            &result("private result"),
            json!({"id":null,"service":"genie","node":"node"}),
            "request-wire",
            "dot@bus",
            3,
            i64::MAX,
        );
        assert!(read(&setup, &identity, &config, 65536).is_some());
        let owner = crate::custody::fingerprint(&[
            identity.service(),
            identity.issuer(),
            identity.resource(),
            identity.subject(),
        ]);
        setup.db().execute("INSERT INTO outbound_retired(owner,request_id,sender,grant_id) VALUES (?1,'read-1','dot@bus','grant')", [&owner]).unwrap();
        assert!(
            read(&setup, &identity, &config, 65536).is_some(),
            "archive hid a live legacy send result"
        );
        setup.db().execute("INSERT INTO outbound_reservations(owner,operation,request_id,payload_hash,sender,grant_id,grant_revision,idempotency_key,target,framed_text,created_at,retry_until,recovery_until,state,receipt) SELECT owner,'reply',request_id,payload_hash,sender,grant_id,grant_revision,'other-op',target,framed_text,created_at,retry_until,recovery_until,state,receipt FROM outbound_reservations WHERE operation='send'", []).unwrap();
        setup
            .db()
            .execute(
                "UPDATE outbound_reservations SET recovery_until=1 WHERE operation='send'",
                [],
            )
            .unwrap();
        assert!(read(&setup, &identity, &config, 65536).is_none());
        setup
            .db()
            .execute("UPDATE outbound_reservations SET recovery_until=NULL", [])
            .unwrap();
        assert!(matches!(
            lookup(
                &Store::open(&setup.provider.store_file).unwrap(),
                &identity,
                "bus",
                "dot@bus",
                "grant",
                &config,
                "read-1",
                &limits(65536),
                &setup.verifier
            ),
            Err(crate::outbound::Error::Busy)
        ));
    }
    #[test]
    fn action_shape_and_requested_operation_are_validated() {
        let expected = json!({"kind":"gist_read","id":"abc"});
        assert!(action(&result("safe"), &expected).is_some());
        for body in [
            json!({"acted":true}),
            json!({"thread":"x","acted":true,"reason":"read","redactions":[],"url":"https://gist.github.com/def"}),
            json!({"thread":"x","acted":false,"reason":"refused","redactions":[],"gist":{}}),
        ] {
            assert!(action(&body.to_string(), &expected).is_none());
        }
    }
}
