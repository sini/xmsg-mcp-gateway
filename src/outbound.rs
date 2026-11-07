use crate::grants::{
    Error as GrantError, Store, CUSTODY_SCHEMA_VERSION, MAX_SUPPORTED_SCHEMA_VERSION,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("outbound schema must be explicitly migrated")]
    MigrationRequired,
    #[error("outbound operation denied")]
    Denied,
    #[error("request_id already reserved for a different payload")]
    Conflict,
    #[error("outbound text exceeds the complete framed byte bound")]
    Oversized,
    #[error("invalid outbound configuration")]
    Configuration,
    #[error("outbound reservation capacity exhausted")]
    Capacity,
    #[error(transparent)]
    Authority(#[from] GrantError),
    #[error("outbound store unavailable")]
    Database(#[from] rusqlite::Error),
    #[error("invalid outbound record")]
    Encoding(#[from] serde_json::Error),
    #[error("credential verification failed")]
    Authentication(#[from] crate::auth::Error),
    #[error("target discovery unavailable")]
    Transport(#[from] xmsg::client::ClientError),
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub send: Option<Permission>,
    pub reply: Option<Permission>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Permission {
    pub targets: BTreeSet<String>,
    pub required_scope: String,
}

impl Policy {
    fn validate(&self) -> Result<(), Error> {
        for permission in [&self.send, &self.reply].into_iter().flatten() {
            if permission.required_scope.trim().is_empty()
                || permission.targets.is_empty()
                || permission.targets.iter().any(|target| {
                    let Some((service, node)) = target.split_once('@') else {
                        return true;
                    };
                    service.is_empty()
                        || node.is_empty()
                        || node.contains('@')
                        || target.chars().any(|c| c.is_whitespace() || c.is_control())
                })
            {
                return Err(Error::Configuration);
            }
        }
        Ok(())
    }
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), GrantError> {
    connection.prepare("SELECT grant_id, document FROM outbound_policy LIMIT 0")?;
    connection.prepare("SELECT owner, operation, request_id, payload_hash, sender, grant_id, grant_revision, idempotency_key, target, correlation, framed_text, created_at, retry_until, state, receipt, submission_revision, revision_changed FROM outbound_reservations LIMIT 0")?;
    Ok(())
}

impl Store {
    pub fn migrate_outbound(&mut self) -> Result<(), Error> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version != CUSTODY_SCHEMA_VERSION {
            return Err(GrantError::NoChange.into());
        }
        tx.execute_batch("CREATE TABLE outbound_policy (
            grant_id TEXT PRIMARY KEY NOT NULL REFERENCES grants(id), document TEXT NOT NULL
        );
        CREATE TABLE outbound_reservations (
            owner TEXT NOT NULL, operation TEXT NOT NULL CHECK(operation IN ('send','reply')),
            request_id TEXT NOT NULL, payload_hash TEXT NOT NULL, sender TEXT NOT NULL,
            grant_id TEXT NOT NULL, grant_revision INTEGER NOT NULL,
            idempotency_key TEXT NOT NULL UNIQUE, target TEXT NOT NULL, correlation TEXT,
            framed_text TEXT NOT NULL, created_at INTEGER NOT NULL, retry_until INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('pending','unknown','confirmed')), receipt TEXT,
            submission_revision INTEGER, revision_changed INTEGER NOT NULL DEFAULT 0 CHECK(revision_changed IN (0,1)),
            PRIMARY KEY(owner, operation, request_id)
        );")?;
        tx.pragma_update(None, "user_version", MAX_SUPPORTED_SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(())
    }

    fn require_outbound_ready(&self) -> Result<(), Error> {
        let version: i64 = self
            .connection
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version != MAX_SUPPORTED_SCHEMA_VERSION {
            return Err(Error::MigrationRequired);
        }
        Ok(())
    }

    pub fn set_outbound_policy(
        &mut self,
        id: &str,
        revision: i64,
        policy: &Policy,
    ) -> Result<i64, Error> {
        self.require_outbound_ready()?;
        policy.validate()?;
        let service: String = self
            .connection
            .query_row("SELECT service FROM grants WHERE id=?1", [id], |r| r.get(0))
            .optional()?
            .ok_or(GrantError::NoChange)?;
        let _lease = self.wait_operation_lease(&service, std::time::Duration::from_secs(30))?;
        let document = serde_json::to_string(policy)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT document FROM outbound_policy WHERE grant_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        if previous.as_deref() == Some(&document) {
            return Err(GrantError::NoChange.into());
        }
        if tx.execute(
            "UPDATE grants SET revision=revision+1 WHERE id=?1 AND revision=?2",
            params![id, revision],
        )? != 1
        {
            return Err(GrantError::NoChange.into());
        }
        tx.execute("INSERT INTO outbound_policy VALUES (?1,?2) ON CONFLICT(grant_id) DO UPDATE SET document=excluded.document", params![id, document])?;
        tx.commit()?;
        Ok(revision + 1)
    }

    fn outbound_policy(&self, grant_id: &str) -> Result<Policy, Error> {
        let document: Option<String> = self
            .connection
            .query_row(
                "SELECT document FROM outbound_policy WHERE grant_id=?1",
                [grant_id],
                |r| r.get(0),
            )
            .optional()?;
        match document {
            Some(document) => Ok(serde_json::from_str(&document)?),
            None => Ok(Policy::default()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestId(String);

#[derive(Debug, thiserror::Error)]
#[error("request_id must contain 1..128 ASCII letters, digits or . _ : -")]
pub struct InvalidRequestId;

impl RequestId {
    pub fn parse(value: &str) -> Result<Self, InvalidRequestId> {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        {
            return Err(InvalidRequestId);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendArguments {
    pub request_id: RequestId,
    pub to: String,
    pub text: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyArguments {
    pub request_id: RequestId,
    pub message_id: String,
    pub text: String,
}

#[derive(Debug)]
pub enum Request {
    Send(SendArguments),
    Reply(ReplyArguments),
}

impl Request {
    fn parts(&self) -> (&'static str, &RequestId, &str) {
        match self {
            Self::Send(args) => ("send", &args.request_id, &args.text),
            Self::Reply(args) => ("reply", &args.request_id, &args.text),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "operation", content = "receipt")]
pub enum Receipt {
    Send(xmsg::client::SendResult),
    Reply(xmsg::client::ReplyRecord),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Pending,
    Unknown,
    Confirmed(Receipt),
}

pub struct Limits {
    pub dedup_lifetime_secs: i64,
    pub max_text_bytes: usize,
    pub timeout: std::time::Duration,
    pub max_reservations: i64,
    pub max_retained_bytes: i64,
}

pub struct Endpoint {
    sender: String,
    client: xmsg::client::AgentClient,
}

impl Endpoint {
    pub fn from_registered(service: &xmsg::client::RegisteredService) -> Result<Self, Error> {
        Ok(Self {
            sender: service
                .address()
                .ok_or(xmsg::client::ClientError::Disconnected)?
                .to_owned(),
            client: service.agent_client(),
        })
    }
}

impl Limits {
    fn validate(&self) -> Result<(), Error> {
        if self.dedup_lifetime_secs <= 0
            || self.max_text_bytes == 0
            || self.max_text_bytes > 65536
            || self.timeout.is_zero()
            || self.timeout > std::time::Duration::from_secs(25)
            || self.max_reservations <= 0
            || self.max_retained_bytes <= 0
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

struct Reservation {
    key: String,
    payload_hash: String,
    sender: String,
    grant_id: String,
    grant_revision: i64,
    framed_text: String,
    created_at: i64,
    retry_until: i64,
    receipt: Option<String>,
}

impl Reservation {
    fn retry_deadline(&self, limits: &Limits) -> i64 {
        self.retry_until
            .min(self.created_at.saturating_add(limits.dedup_lifetime_secs))
    }

    fn expired(&self, limits: &Limits) -> bool {
        now() >= self.retry_deadline(limits) || now() < self.created_at
    }
}

impl Store {
    fn expire_reservation(&self, reservation: &Reservation, limits: &Limits) -> Result<(), Error> {
        let deadline = if now() < reservation.created_at {
            0
        } else {
            reservation.retry_deadline(limits)
        };
        self.connection.execute("UPDATE outbound_reservations SET state='unknown', retry_until=MIN(retry_until,?2) WHERE idempotency_key=?1",params![reservation.key,deadline])?;
        Ok(())
    }

    fn reservation(
        &self,
        owner: &str,
        op: &str,
        id: &RequestId,
    ) -> Result<Option<Reservation>, Error> {
        Ok(self.connection.query_row("SELECT idempotency_key, payload_hash, sender, grant_id, grant_revision, framed_text, created_at, retry_until, receipt FROM outbound_reservations WHERE owner=?1 AND operation=?2 AND request_id=?3", params![owner,op,id.as_str()], |r| Ok(Reservation {
            key:r.get(0)?,payload_hash:r.get(1)?,sender:r.get(2)?,grant_id:r.get(3)?,grant_revision:r.get(4)?,framed_text:r.get(5)?,created_at:r.get(6)?,retry_until:r.get(7)?,receipt:r.get(8)?
        })).optional()?)
    }
}

pub async fn dispatch(
    store: &mut Store,
    service: &Endpoint,
    verifier: &crate::auth::Verifier,
    token: &str,
    bus_instance: &str,
    request: &Request,
    limits: &Limits,
) -> Result<Outcome, Error> {
    limits.validate()?;
    store.connection.busy_timeout(std::time::Duration::ZERO)?;
    store.require_outbound_ready()?;
    let started = std::time::Instant::now();
    let identity = tokio::time::timeout(limits.timeout, verifier.verify(token))
        .await
        .map_err(|_| Error::Transport(xmsg::client::ClientError::Timeout))??;
    let initial_grant = store.authorize(&identity)?;
    let initial_policy = store.outbound_policy(&initial_grant.grant_id)?;
    let initial_permission = match request {
        Request::Send(_) => initial_policy.send,
        Request::Reply(_) => initial_policy.reply,
    }
    .ok_or(Error::Denied)?;
    if !verifier.requires_scope(&initial_permission.required_scope) {
        return Err(Error::Denied);
    }
    let Some(_lease) = store.try_operation_lease(identity.service())? else {
        return Ok(Outcome::Pending);
    };
    let owner = crate::custody::fingerprint(&[
        identity.service(),
        identity.issuer(),
        identity.resource(),
        identity.subject(),
    ]);
    let remaining = limits.timeout.saturating_sub(started.elapsed());
    let result = tokio::time::timeout(
        remaining,
        submit(
            store,
            service,
            verifier,
            token,
            bus_instance,
            request,
            limits,
            &owner,
        ),
    )
    .await;
    match result {
        Ok(result) => result,
        Err(_) => {
            let (op, id, _) = request.parts();
            store.connection.execute("UPDATE outbound_reservations SET state='unknown' WHERE owner=?1 AND operation=?2 AND request_id=?3 AND receipt IS NULL", params![owner, op, id.as_str()])?;
            Ok(Outcome::Unknown)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn submit(
    store: &mut Store,
    service: &Endpoint,
    verifier: &crate::auth::Verifier,
    token: &str,
    bus_instance: &str,
    request: &Request,
    limits: &Limits,
    owner: &str,
) -> Result<Outcome, Error> {
    let identity = verifier.verify(token).await?;
    let fresh_owner = crate::custody::fingerprint(&[
        identity.service(),
        identity.issuer(),
        identity.resource(),
        identity.subject(),
    ]);
    if fresh_owner != owner || identity.expires_at() <= now() as u64 {
        return Err(Error::Denied);
    }
    let authority = store.authorize(&identity)?;
    let policy = store.outbound_policy(&authority.grant_id)?;
    let (op, id, text) = request.parts();
    let permission = match request {
        Request::Send(_) => policy.send,
        Request::Reply(_) => policy.reply,
    }
    .ok_or(Error::Denied)?;
    if !verifier.requires_scope(&permission.required_scope) {
        return Err(Error::Denied);
    }
    let sender = service.sender.as_str();
    let (target, correlation) = match request {
        Request::Send(args) => (args.to.clone(), None),
        Request::Reply(args) => {
            let origin: Option<String> = store.connection.query_row("SELECT c.origin FROM custody_items c JOIN grants g ON g.id=c.grant_id WHERE c.bus=?1 AND c.upstream_id=?2 AND c.mailbox=?3 AND c.owner=?4 AND g.service=?5 AND g.issuer=?6 AND g.resource=?7", params![bus_instance, args.message_id, sender, identity.subject(), identity.service(), identity.issuer(), identity.resource()], |r|r.get(0)).optional()?;
            let origin: xmsg::client::Origin = serde_json::from_str(&origin.ok_or(Error::Denied)?)?;
            let name = origin.service.ok_or(Error::Denied)?;
            if origin.id.is_some() {
                return Err(Error::Denied);
            }
            (
                format!("{name}@{}", origin.node),
                Some(args.message_id.as_str()),
            )
        }
    };
    let payload_hash = crate::custody::fingerprint(&[op, &target, correlation.unwrap_or(""), text]);
    let existing = store.reservation(owner, op, id)?;
    if existing
        .as_ref()
        .is_some_and(|reservation| reservation.payload_hash != payload_hash)
    {
        return Err(Error::Conflict);
    }
    if !permission.targets.contains(&target) {
        return Err(Error::Denied);
    }
    if let Some(reservation) = &existing {
        if let Some(receipt) = &reservation.receipt {
            return Ok(Outcome::Confirmed(serde_json::from_str(receipt)?));
        }
        if reservation.sender != sender
            || reservation.grant_id != authority.grant_id
            || reservation.grant_revision != authority.revision
        {
            return Err(Error::Denied);
        }
        if reservation.expired(limits) {
            store.expire_reservation(reservation, limits)?;
            return Ok(Outcome::Unknown);
        }
    }
    let Some((name, node)) = target.split_once('@') else {
        return Err(Error::Denied);
    };
    let recipients = service
        .client
        .list(xmsg::client::ListQuery {
            name: Some(name.into()),
            node: Some(node.into()),
            kind: Some("service".into()),
            status: Some("live".into()),
            ..Default::default()
        })
        .await?;
    if !recipients
        .nodes
        .iter()
        .any(|item| item.node == node && item.status == "ok")
        || !recipients.recipients.iter().any(|item| {
            item.address == target
                && item.node == node
                && item.kind == "service"
                && item.harness.as_deref() == Some("svc")
                && item.status == "live"
        })
    {
        return Err(Error::Denied);
    }
    let reservation = match existing {
        Some(reservation) => reservation,
        None => {
            let key = format!(
                "gw-{}",
                crate::custody::fingerprint(&[owner, op, id.as_str()])
            );
            let framed_text =
                format!("[External message via {sender}; gateway correlation {key}]\n{text}");
            if framed_text.len() > limits.max_text_bytes {
                return Err(Error::Oversized);
            }
            let timestamp = now();
            let tx = store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let (count, bytes): (i64,i64) = tx.query_row("SELECT COUNT(*), COALESCE(SUM(length(CAST(framed_text AS BLOB))),0) FROM outbound_reservations", [], |r|Ok((r.get(0)?,r.get(1)?)))?;
            if count >= limits.max_reservations
                || bytes.saturating_add(framed_text.len() as i64) > limits.max_retained_bytes
            {
                return Err(Error::Capacity);
            }
            tx.execute("INSERT INTO outbound_reservations (owner,operation,request_id,payload_hash,sender,grant_id,grant_revision,idempotency_key,target,correlation,framed_text,created_at,retry_until,state) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'pending')", params![owner,op,id.as_str(),payload_hash,sender,authority.grant_id,authority.revision,key,target,correlation,framed_text,timestamp,timestamp.saturating_add(limits.dedup_lifetime_secs)])?;
            tx.commit()?;
            store
                .reservation(owner, op, id)?
                .ok_or(Error::Configuration)?
        }
    };
    tracing::debug!(target:"gateway_outbound_reserved", "pending");
    let current = verifier.verify(token).await?;
    if current.expires_at() <= now() as u64 || store.authorize(&current)? != authority {
        return Err(Error::Denied);
    }
    if reservation.expired(limits) {
        store.expire_reservation(&reservation, limits)?;
        return Ok(Outcome::Unknown);
    }
    if reservation.framed_text.len() > limits.max_text_bytes {
        return Err(Error::Oversized);
    }
    let key = reservation.key.clone();
    let submitted = match correlation {
        Some(message_id) => service
            .client
            .reply(message_id, &reservation.framed_text, Some(&key))
            .await
            .map(Receipt::Reply),
        None => service
            .client
            .send(&target, &reservation.framed_text, Some(&key))
            .await
            .map(Receipt::Send),
    };
    tracing::debug!(target:"gateway_outbound_submitted", "outcome awaiting commit");
    let tx = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let revision: i64 = tx.query_row(
        "SELECT revision FROM grants WHERE id=?1",
        [&authority.grant_id],
        |r| r.get(0),
    )?;
    let outcome = match submitted {
        Ok(receipt) => {
            tx.execute("UPDATE outbound_reservations SET state='confirmed', receipt=?2, submission_revision=?3, revision_changed=?4 WHERE idempotency_key=?1 AND receipt IS NULL", params![reservation.key,serde_json::to_string(&receipt)?,authority.revision,revision!=authority.revision])?;
            Outcome::Confirmed(receipt)
        }
        Err(_) => {
            tx.execute("UPDATE outbound_reservations SET state='unknown', submission_revision=?2, revision_changed=?3 WHERE idempotency_key=?1 AND receipt IS NULL",params![reservation.key,authority.revision,revision!=authority.revision])?;
            Outcome::Unknown
        }
    };
    tx.commit()?;
    Ok(outcome)
}
