use crate::auth::VerifiedContext;
use crate::grants::{
    Error as GrantError, Store, CUSTODY_SCHEMA_VERSION, MAX_SUPPORTED_SCHEMA_VERSION,
    OUTBOUND_SCHEMA_VERSION,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;
use xmsg::client::{AttachRequest, AttachmentRef};

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
    #[error(
        "outbound request deadline elapsed before a new submission; retry the same request_id"
    )]
    Deadline,
    #[error("outbound reservation capacity exhausted")]
    Capacity,
    #[error("outbound store busy; operation not submitted, retry the same request_id")]
    Busy,
    #[error("read worker unavailable")]
    Worker,
    #[error(transparent)]
    Authority(GrantError),
    #[error("outbound store unavailable")]
    Database(#[source] rusqlite::Error),
    #[error("invalid outbound record")]
    Encoding(#[from] serde_json::Error),
    #[error("credential verification failed")]
    Authentication(#[from] crate::auth::Error),
    #[error("target discovery unavailable")]
    Transport(#[from] xmsg::client::ClientError),
}

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        if matches!(&error,rusqlite::Error::SqliteFailure(code,_) if matches!(code.code,rusqlite::ErrorCode::DatabaseBusy|rusqlite::ErrorCode::DatabaseLocked))
        {
            Self::Busy
        } else {
            Self::Database(error)
        }
    }
}

impl From<GrantError> for Error {
    fn from(error: GrantError) -> Self {
        match error {
            GrantError::Database(error) => error.into(),
            other => Self::Authority(other),
        }
    }
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

impl Permission {
    fn admits_node(&self, node: &str) -> bool {
        self.targets
            .iter()
            .any(|target| target.strip_prefix("*@") == Some(node))
    }

    fn admits_target(&self, target: &str) -> bool {
        let Some((name, node)) = target.split_once('@') else {
            return false;
        };
        if name.is_empty()
            || name == "*"
            || node.is_empty()
            || node.contains('@')
            || target.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return false;
        }
        self.targets.contains(target) || self.admits_node(node)
    }

    fn admits_listed_recipient(&self, item: &xmsg::client::Recipient) -> bool {
        if self.admits_node(&item.node) {
            matches!(item.kind.as_str(), "service" | "instance" | "subagent")
                && (item.kind != "service" || item.harness.as_deref() == Some("svc"))
        } else {
            self.targets.contains(&item.address)
                && item.kind == "service"
                && item.harness.as_deref() == Some("svc")
        }
    }
}

impl Policy {
    fn permission(&self, request: &Request) -> Result<Permission, Error> {
        match request {
            Request::Send(_) => self.send.clone(),
            Request::Reply(_) => self.reply.clone(),
        }
        .ok_or(Error::Denied)
    }

    fn validate(&self) -> Result<(), Error> {
        if self
            .reply
            .as_ref()
            .is_some_and(|permission| permission.targets.is_empty())
        {
            return Err(Error::Configuration);
        }
        for permission in [&self.send, &self.reply].into_iter().flatten() {
            if permission.required_scope.trim().is_empty()
                || permission.targets.iter().any(|target| {
                    let Some((service, node)) = target.split_once('@') else {
                        return true;
                    };
                    service.is_empty()
                        || (service != "*" && service.contains('*'))
                        || node.is_empty()
                        || node.contains('@')
                        || node.contains('*')
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
        tx.pragma_update(None, "user_version", OUTBOUND_SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn require_outbound_ready(&self) -> Result<(), Error> {
        let version: i64 = self
            .connection
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if !(OUTBOUND_SCHEMA_VERSION..=MAX_SUPPORTED_SCHEMA_VERSION).contains(&version) {
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
        let document = validated_policy_document(policy)?;
        let service: String = self
            .connection
            .query_row("SELECT service FROM grants WHERE id=?1", [id], |r| r.get(0))
            .optional()?
            .ok_or(GrantError::NoChange)?;
        let _lease = self.wait_operation_lease(&service, std::time::Duration::from_secs(30))?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let next = Self::set_outbound_policy_in(&tx, id, revision, &document)?;
        tx.commit()?;
        Ok(next)
    }

    pub fn apply_outbound_policy(
        &mut self,
        id: &str,
        policy: &Policy,
        enabled: Option<bool>,
    ) -> Result<ApplyResult, Error> {
        self.require_outbound_ready()?;
        let document = validated_policy_document(policy)?;
        let (service, revision): (String, i64) = self
            .connection
            .query_row(
                "SELECT service, revision FROM grants WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(GrantError::NoChange)?;
        let _lease = self.wait_operation_lease(&service, std::time::Duration::from_secs(30))?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (current_revision, current_enabled): (i64, bool) = tx
            .query_row(
                "SELECT revision, enabled FROM grants WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(GrantError::NoChange)?;
        if current_revision != revision {
            return Err(GrantError::NoChange.into());
        }
        let previous = outbound_policy_on(&tx, id)?;
        let mut next = revision;
        if previous != *policy {
            next = Self::set_outbound_policy_in(&tx, id, next, &document)?;
        }
        let mut events_change = None;
        if let Some(enabled) = enabled.filter(|enabled| *enabled != current_enabled) {
            (next, events_change) = Self::set_enabled_in(&tx, id, next, enabled)?;
        }
        tx.commit()?;
        if let Some(change) = events_change {
            change.committed();
        }
        Ok(ApplyResult {
            revision: next,
            changed: next != revision,
        })
    }

    fn set_outbound_policy_in(
        tx: &rusqlite::Transaction<'_>,
        id: &str,
        revision: i64,
        document: &str,
    ) -> Result<i64, Error> {
        let previous: Option<String> = tx
            .query_row(
                "SELECT document FROM outbound_policy WHERE grant_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        if previous.as_deref() == Some(document) {
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
        let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version >= crate::grants::EVENTS_SCHEMA_VERSION {
            crate::event_store::policy_changed(tx, id, revision, revision + 1)?;
        }
        Ok(revision + 1)
    }

    pub(crate) fn outbound_policy(&self, grant_id: &str) -> Result<Policy, Error> {
        outbound_policy_on(&self.connection, grant_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyResult {
    pub revision: i64,
    pub changed: bool,
}

fn validated_policy_document(policy: &Policy) -> Result<String, Error> {
    policy.validate()?;
    Ok(serde_json::to_string(policy)?)
}

fn outbound_policy_on(connection: &Connection, grant_id: &str) -> Result<Policy, Error> {
    let document: Option<String> = connection
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
    #[serde(default, deserialize_with = "crate::attachments::deserialize_inputs")]
    pub attachments: Vec<crate::attachments::Input>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyArguments {
    pub request_id: RequestId,
    pub message_id: String,
    pub text: String,
    #[serde(default, deserialize_with = "crate::attachments::deserialize_inputs")]
    pub attachments: Vec<crate::attachments::Input>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ListArguments {
    pub node: Option<String>,
    pub kind: Option<String>,
    pub status: Option<String>,
    pub within: Option<u64>,
}

impl ListArguments {
    pub fn validate(&self) -> Result<(), Error> {
        if self.node.as_deref().is_some_and(|node| {
            node.is_empty()
                || node.contains('@')
                || node.chars().any(|c| c.is_whitespace() || c.is_control())
        }) || self
            .kind
            .as_deref()
            .is_some_and(|kind| !matches!(kind, "service" | "instance" | "subagent"))
            || self
                .status
                .as_deref()
                .is_some_and(|status| !matches!(status, "live" | "inactive"))
            || self.within.is_some_and(|within| {
                within == 0 || within > 604_800 || self.status.as_deref() == Some("live")
            })
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ListedRecipient {
    pub address: String,
    pub node: String,
    pub kind: String,
    pub status: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FilteredList {
    pub recipients: Vec<ListedRecipient>,
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
    fn attachments(&self) -> &[crate::attachments::Input] {
        match self {
            Self::Send(args) => &args.attachments,
            Self::Reply(args) => &args.attachments,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "operation", content = "receipt")]
pub enum Receipt {
    Send(xmsg::client::SendResult),
    Reply(Box<xmsg::client::ReplyRecord>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Pending,
    Expired,
    Unknown,
    ExpiredUnknown,
    Confirmed(Receipt),
}

#[derive(Clone)]
pub struct Limits {
    pub dedup_lifetime_secs: i64,
    pub result_recovery_secs: i64,
    /// Complete framed message including the gateway preamble, in bytes.
    pub max_framed_bytes: usize,
    pub timeout: std::time::Duration,
    pub max_reservations: i64,
    pub max_retained_bytes: i64,
}

pub struct Endpoint {
    sender: String,
    client: xmsg::client::AgentClient,
    max_attachment_bytes: Option<usize>,
    max_body_bytes: Option<usize>,
    frame_budget: usize,
}

impl Endpoint {
    pub(crate) fn health(&self) -> Result<(), xmsg::client::ClientError> {
        self.client.health()
    }

    pub(crate) fn sender(&self) -> &str {
        &self.sender
    }

    pub(crate) fn frame_budget(&self) -> usize {
        self.frame_budget
    }

    pub(crate) fn with_frame_budget(mut self, max_frame_bytes: usize) -> Self {
        self.frame_budget = max_frame_bytes;
        self
    }

    pub(crate) async fn read_attachment(
        &self,
        message_id: &str,
        index: usize,
        offset: usize,
        length: Option<usize>,
    ) -> Result<xmsg::client::AttachmentRead, xmsg::client::ClientError> {
        if self.max_attachment_bytes.is_none() {
            return Err(xmsg::client::ClientError::Protocol);
        }
        self.client
            .read_attachment(message_id, index, offset, length)
            .await
    }

    pub fn from_registered(service: &xmsg::client::RegisteredService) -> Result<Self, Error> {
        Ok(Self {
            sender: service
                .address()
                .ok_or(xmsg::client::ClientError::Disconnected)?
                .to_owned(),
            client: service.agent_client(),
            max_attachment_bytes: service.max_attachment_bytes(),
            max_body_bytes: service.max_body_bytes(),
            frame_budget: service.max_body_bytes().unwrap_or(0),
        })
    }
}

impl Limits {
    fn text_fits(&self, framed: &str) -> bool {
        framed.len() <= self.max_framed_bytes
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.result_recovery_secs < self.dedup_lifetime_secs
            || self.dedup_lifetime_secs <= 0
            || self.max_framed_bytes == 0
            || self.max_framed_bytes > 65536
            || self.timeout.is_zero()
            || self.timeout > std::time::Duration::from_secs(25)
            || self.max_reservations <= 0
            || self.max_retained_bytes <= 0
        {
            return Err(Error::Configuration);
        }
        reservation_times(SystemTime::now(), self.dedup_lifetime_secs)?;
        reservation_times(SystemTime::now(), self.result_recovery_secs)?;
        Ok(())
    }
}

fn reservation_times(at: SystemTime, lifetime: i64) -> Result<(i64, i64), Error> {
    crate::deadline::window(at, lifetime).map_err(|_| Error::Configuration)
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
    attachments: Vec<AttachmentRef>,
    correlation: Option<String>,
    created_at: i64,
    retry_until: i64,
    receipt: Option<String>,
    target: String,
}

impl Reservation {
    fn retry_deadline(&self, limits: &Limits) -> i64 {
        // Stored deadlines also cap old rows; the ceiling allowance never extends them.
        self.retry_until.min(
            self.created_at
                .saturating_add(limits.dedup_lifetime_secs)
                .saturating_add(1),
        )
    }

    fn expired(&self, limits: &Limits) -> bool {
        now() >= self.retry_deadline(limits) || now() < self.created_at
    }
}

impl Store {
    #[allow(clippy::too_many_arguments)]
    fn reply_target(
        &self,
        bus: &str,
        message_id: &str,
        sender: &str,
        identity: &crate::auth::VerifiedIdentity,
        authority: &crate::grants::Authorization,
        existing: Option<&Reservation>,
        permission: &Permission,
    ) -> Result<String, Error> {
        if let Some(reservation) = existing {
            return Ok(reservation.target.clone());
        }
        let version: i64 = self
            .connection
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        let authority_predicate = if version >= crate::grants::EVENTS_SCHEMA_VERSION {
            "EXISTS(SELECT 1 FROM event_authorizations ea WHERE ea.event_id=c.event_id AND ea.dispatch_revision=?9)"
        } else {
            "c.grant_revision=?9"
        };
        let origin: Option<String> = self.connection.query_row(&format!("SELECT c.origin FROM custody_items c JOIN grants g ON g.id=c.grant_id WHERE c.bus=?1 AND c.upstream_id=?2 AND c.mailbox=?3 AND c.owner=?4 AND g.service=?5 AND g.issuer=?6 AND g.resource=?7 AND c.grant_id=?8 AND {authority_predicate} AND c.text IS NOT NULL AND c.expires_at>?10"), params![bus, message_id, sender, identity.subject(), identity.service(), identity.issuer(), identity.resource(), authority.grant_id, authority.revision, now()], |r|r.get(0)).optional()?;
        let origin: xmsg::client::Origin = serde_json::from_str(&origin.ok_or(Error::Denied)?)?;
        let name = match (origin.service.as_deref(), origin.id.as_deref()) {
            (Some(service), None) if !service.is_empty() && service != "*" => service,
            (None, Some(id))
                if !id.is_empty() && id != "*" && permission.admits_node(&origin.node) =>
            {
                id
            }
            _ => return Err(Error::Denied),
        };
        Ok(format!("{name}@{}", origin.node))
    }

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
        let refs_column = if crate::attachment_store::ready(&self.connection)? {
            "attachments"
        } else {
            "'[]'"
        };
        let sql = format!("SELECT idempotency_key,payload_hash,sender,grant_id,grant_revision,framed_text,created_at,retry_until,receipt,target,correlation,{refs_column} FROM outbound_reservations WHERE owner=?1 AND operation=?2 AND request_id=?3");
        let row = self
            .connection
            .query_row(&sql, params![owner, op, id.as_str()], |r| {
                let json: String = r.get(11)?;
                let attachments = serde_json::from_str(&json).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        11,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
                Ok(Reservation {
                    key: r.get(0)?,
                    payload_hash: r.get(1)?,
                    sender: r.get(2)?,
                    grant_id: r.get(3)?,
                    grant_revision: r.get(4)?,
                    framed_text: r.get(5)?,
                    created_at: r.get(6)?,
                    retry_until: r.get(7)?,
                    receipt: r.get(8)?,
                    target: r.get(9)?,
                    correlation: r.get(10)?,
                    attachments,
                })
            })
            .optional()?;
        Ok(row)
    }
}

pub fn filter_recipients(
    policy: &Policy,
    arguments: &ListArguments,
    listed: xmsg::client::ListResult,
) -> Result<FilteredList, Error> {
    arguments.validate()?;
    let permission = policy.send.as_ref();
    let healthy_nodes: BTreeSet<&str> = listed
        .nodes
        .iter()
        .filter(|node| node.status == "ok")
        .map(|node| node.node.as_str())
        .collect();
    let mut recipients: Vec<ListedRecipient> = listed
        .recipients
        .into_iter()
        .filter(|item| {
            permission.is_some_and(|allowed| allowed.admits_listed_recipient(item))
                && item.status == "live"
                && (listed.nodes.is_empty() || healthy_nodes.contains(item.node.as_str()))
                && arguments
                    .node
                    .as_deref()
                    .is_none_or(|node| item.node == node)
                && arguments
                    .kind
                    .as_deref()
                    .is_none_or(|kind| item.kind == kind)
                && arguments
                    .status
                    .as_deref()
                    .is_none_or(|status| item.status == status)
        })
        .map(|item| ListedRecipient {
            address: item.address,
            node: item.node,
            kind: item.kind,
            status: item.status,
        })
        .collect();
    recipients.sort_by(|left, right| left.address.cmp(&right.address));
    recipients.dedup_by(|left, right| left.address == right.address);
    Ok(FilteredList { recipients })
}

fn node_scoped_send_admitted(
    recipients: &xmsg::client::ListResult,
    target: &str,
    name: &str,
    node: &str,
) -> bool {
    if !recipients
        .nodes
        .iter()
        .any(|item| item.node == node && item.status == "ok")
    {
        return false;
    }
    let live_on_node = |item: &xmsg::client::Recipient| {
        item.node == node
            && item.status == "live"
            && matches!(item.kind.as_str(), "service" | "instance" | "subagent")
            && (item.kind != "service" || item.harness.as_deref() == Some("svc"))
    };
    if recipients
        .recipients
        .iter()
        .any(|item| live_on_node(item) && item.address == target)
    {
        return true;
    }
    if let Some((parent_ref, child_ref)) = name.split_once('/') {
        if parent_ref.is_empty() || child_ref.is_empty() || child_ref.contains('/') {
            return false;
        }
        let parent_address = format!("{parent_ref}@{node}");
        let parent_prefix = format!("{parent_ref}/");
        let resolved_parent = if recipients.recipients.iter().any(|item| {
            live_on_node(item)
                && ((item.kind == "instance" && item.address == parent_address)
                    || (item.kind == "subagent" && item.address.starts_with(&parent_prefix)))
        }) {
            Some(parent_ref)
        } else {
            let mut matches = recipients.recipients.iter().filter_map(|item| {
                (live_on_node(item)
                    && item.kind == "instance"
                    && item.label.as_deref() == Some(parent_ref))
                .then(|| item.address.split_once('@').map(|(id, _)| id))
                .flatten()
            });
            let first = matches.next();
            if matches.next().is_some() {
                None
            } else {
                first
            }
        };
        let Some(parent_id) = resolved_parent else {
            return false;
        };
        let subagent_address = format!("{parent_id}/{child_ref}@{node}");
        if recipients.recipients.iter().any(|item| {
            live_on_node(item) && item.kind == "subagent" && item.address == subagent_address
        }) {
            return true;
        }
        let subagent_prefix = format!("{parent_id}/");
        let mut label_matches = recipients.recipients.iter().filter(|item| {
            live_on_node(item)
                && item.kind == "subagent"
                && item.address.starts_with(&subagent_prefix)
                && item.label.as_deref() == Some(child_ref)
        });
        return label_matches.next().is_some() && label_matches.next().is_none();
    }
    let mut label_matches = recipients
        .recipients
        .iter()
        .filter(|item| live_on_node(item) && item.label.as_deref() == Some(name));
    label_matches.next().is_some() && label_matches.next().is_none()
}

pub async fn list(
    store: &mut Store,
    service: &Endpoint,
    verifier: &crate::auth::Verifier,
    token: &str,
    arguments: &ListArguments,
    limits: &Limits,
) -> Result<FilteredList, Error> {
    let started = std::time::Instant::now();
    let context = verify_context(store, verifier, token, limits).await?;
    list_verified(
        store, service, verifier, &context, arguments, limits, started,
    )
    .await
}

pub(crate) async fn list_verified(
    store: &mut Store,
    service: &Endpoint,
    verifier: &crate::auth::Verifier,
    context: &VerifiedContext,
    arguments: &ListArguments,
    limits: &Limits,
    started: std::time::Instant,
) -> Result<FilteredList, Error> {
    limits.validate()?;
    arguments.validate()?;
    let store_file = store.file.clone();
    {
        let list_store = Store::open_for_dispatch(&store_file)?;
        list_store.require_outbound_ready()?;
        list_store.require_retirement_ready()?;
    }
    let policy = {
        let list_store = Store::open_for_dispatch(&store_file)?;
        list_store.require_outbound_ready()?;
        list_store.require_retirement_ready()?;
        require_current(context, &list_store)?;
        let authority = context.authority();
        list_store.outbound_policy(&authority.grant_id)?
    };
    let permission = policy.send.as_ref().ok_or(Error::Denied)?;
    if !verifier.requires_scope_for(context.identity(), &permission.required_scope) {
        return Err(Error::Denied);
    }
    let remaining = limits.timeout.saturating_sub(started.elapsed());
    let listed = match tokio::time::timeout(
        remaining,
        service.client.list(xmsg::client::ListQuery {
            name: None,
            node: arguments.node.clone(),
            kind: arguments.kind.clone(),
            status: arguments.status.clone(),
            within: arguments.within,
        }),
    )
    .await
    .map_err(|_| Error::Deadline)?
    {
        Ok(listed) => listed,
        Err(xmsg::client::ClientError::Refused { code }) if code == "unknown_peer" => {
            crate::dispatch_outcome::emit("xmsg_list", "pre_effect_unavailable", "unknown_peer");
            xmsg::client::ListResult {
                recipients: Vec::new(),
                nodes: Vec::new(),
            }
        }
        Err(error) => return Err(error.into()),
    };
    filter_recipients(&policy, arguments, listed)
}

async fn verify_context(
    store: &mut Store,
    verifier: &crate::auth::Verifier,
    token: &str,
    limits: &Limits,
) -> Result<VerifiedContext, Error> {
    limits.validate()?;
    let identity = tokio::time::timeout(limits.timeout, verifier.verify(token))
        .await
        .map_err(|_| Error::Deadline)??;
    let authority = store.authorize(&identity)?;
    Ok(VerifiedContext::new(
        std::sync::Arc::new(identity),
        authority,
    ))
}

pub(crate) fn require_current(context: &VerifiedContext, store: &Store) -> Result<(), Error> {
    if context.identity().expires_at() <= now() as u64 {
        return Err(crate::auth::Error::InvalidToken.into());
    }
    if store.authorize(context.identity())? != *context.authority() {
        return Err(Error::Denied);
    }
    Ok(())
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
    let started = std::time::Instant::now();
    limits.validate()?;
    let mut dedicated = Store::open_for_dispatch(&store.file)?;
    let context = verify_context(&mut dedicated, verifier, token, limits).await?;
    dispatch_on_connection(
        &mut dedicated,
        service,
        verifier,
        &context,
        bus_instance,
        request,
        limits,
        None,
        started,
    )
    .await
}

pub(crate) async fn dispatch_verified(
    store: &mut Store,
    service: &Endpoint,
    verifier: &crate::auth::Verifier,
    context: &VerifiedContext,
    bus_instance: &str,
    request: &Request,
    limits: &Limits,
) -> Result<Outcome, Error> {
    limits.validate()?;
    let mut connection = Store::open_for_dispatch(&store.file)?;
    dispatch_on_connection(
        &mut connection,
        service,
        verifier,
        context,
        bus_instance,
        request,
        limits,
        None,
        std::time::Instant::now(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch_selected(
    store: &mut Store,
    service: &Endpoint,
    verifier: &crate::auth::Verifier,
    context: &VerifiedContext,
    bus_instance: &str,
    request: &Request,
    limits: &Limits,
    selected_grant: &str,
) -> Result<Outcome, Error> {
    limits.validate()?;
    let mut selected_connection = Store::open_for_dispatch(&store.file)?;
    dispatch_on_connection(
        &mut selected_connection,
        service,
        verifier,
        context,
        bus_instance,
        request,
        limits,
        Some(selected_grant),
        std::time::Instant::now(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_on_connection(
    store: &mut Store,
    service: &Endpoint,
    verifier: &crate::auth::Verifier,
    context: &VerifiedContext,
    bus_instance: &str,
    request: &Request,
    limits: &Limits,
    selected_grant: Option<&str>,
    started: std::time::Instant,
) -> Result<Outcome, Error> {
    store.require_outbound_ready()?;
    store.require_retirement_ready()?;
    limits.validate()?;
    let identity = context.identity();
    let initial_grant = context.authority();
    if selected_grant.is_some_and(|id| id != initial_grant.grant_id) {
        return Err(Error::Denied);
    }
    let initial_policy = store.outbound_policy(&initial_grant.grant_id)?;
    let initial_permission = initial_policy.permission(request)?;
    if !verifier.requires_scope_for(identity, &initial_permission.required_scope) {
        return Err(Error::Denied);
    }
    let inputs = request.attachments();
    if !inputs.is_empty() && !crate::attachment_store::ready(&store.connection)? {
        return Err(Error::MigrationRequired);
    }
    let cap = if inputs.is_empty() {
        0
    } else {
        service.max_attachment_bytes.ok_or(Error::Configuration)?
    };
    let prepared = crate::attachments::prepare(inputs, cap)?;
    let references: Vec<_> = prepared.iter().map(|file| file.reference.clone()).collect();
    let owner = crate::custody::fingerprint(&[
        identity.service(),
        identity.issuer(),
        identity.resource(),
        identity.subject(),
    ]);
    let (operation, raw_id, _) = request.parts();
    if store.outbound_id_retired(&owner, raw_id.as_str())?
        && store.reservation(&owner, operation, raw_id)?.is_none()
    {
        return Ok(Outcome::Expired);
    }
    let Some(_lease) = store.try_operation_lease(identity.service())? else {
        if store.outbound_id_conflicts(&owner, raw_id.as_str(), operation)? {
            return Err(Error::Conflict);
        }
        if store.outbound_recovery_expired(
            &owner,
            raw_id.as_str(),
            service.sender(),
            &initial_grant.grant_id,
            limits,
        )? {
            return Ok(Outcome::Expired);
        }
        let (op, id, text) = request.parts();
        if let Some(reservation) = store.reservation(&owner, op, id)? {
            let (target, correlation) = match request {
                Request::Send(args) => (args.to.as_str(), ""),
                Request::Reply(args) => (reservation.target.as_str(), args.message_id.as_str()),
            };
            if reservation.payload_hash
                != payload_fingerprint(op, target, correlation, text, &references)?
            {
                return Err(Error::Conflict);
            }
            if !initial_permission.admits_target(target) {
                return Err(Error::Denied);
            }
            if reservation.grant_id != initial_grant.grant_id
                || reservation.sender != service.sender()
            {
                return Err(Error::Denied);
            }
            if let Some(receipt) = reservation.receipt {
                require_current(context, store)?;
                return Ok(Outcome::Confirmed(serde_json::from_str(&receipt)?));
            }
        }
        return Ok(Outcome::Pending);
    };
    store.retire_outbound_locked(identity.service(), limits, now())?;
    if store.outbound_id_retired(&owner, raw_id.as_str())?
        && store.reservation(&owner, operation, raw_id)?.is_none()
    {
        return Ok(Outcome::Expired);
    }
    if store.outbound_id_conflicts(&owner, raw_id.as_str(), operation)? {
        return Err(Error::Conflict);
    }
    let (op, id, _) = request.parts();
    if store
        .reservation(&owner, op, id)?
        .is_some_and(|row| row.grant_id != initial_grant.grant_id || row.sender != service.sender())
    {
        return Err(Error::Denied);
    }
    let may_have_submitted = AtomicBool::new(
        store
            .reservation(&owner, op, id)?
            .is_some_and(|row| row.receipt.is_none()),
    );
    let remaining = limits.timeout.saturating_sub(started.elapsed());
    let result = tokio::time::timeout(
        remaining,
        submit(
            store,
            service,
            verifier,
            context,
            bus_instance,
            request,
            limits,
            &owner,
            &may_have_submitted,
            selected_grant,
            &prepared,
        ),
    )
    .await;
    let outcome = match result {
        Ok(result) => result,
        Err(_) => {
            if !may_have_submitted.load(Ordering::Relaxed) {
                return Err(Error::Deadline);
            }
            let (op, id, _) = request.parts();
            if store.connection.execute("UPDATE outbound_reservations SET state='unknown' WHERE owner=?1 AND operation=?2 AND request_id=?3 AND receipt IS NULL", params![owner, op, id.as_str()]).is_err() {
                tracing::debug!(target:"gateway_outbound_pending", "uncertain outcome could not be recorded");
            }
            Ok(Outcome::Unknown)
        }
    }?;
    if outcome == Outcome::Unknown {
        match store.reservation(&owner, op, id) {
            Ok(Some(reservation)) if !reservation.expired(limits) => Ok(Outcome::Unknown),
            _ => Ok(Outcome::ExpiredUnknown),
        }
    } else {
        Ok(outcome)
    }
}

fn payload_fingerprint(
    operation: &str,
    target: &str,
    correlation: &str,
    text: &str,
    refs: &[AttachmentRef],
) -> Result<String, Error> {
    if refs.is_empty() {
        Ok(crate::custody::fingerprint(&[
            operation,
            target,
            correlation,
            text,
        ]))
    } else {
        Ok(crate::custody::fingerprint(&[
            operation,
            target,
            correlation,
            text,
            &serde_json::to_string(refs)?,
        ]))
    }
}

fn attachment_frame_fits(request: &AttachRequest, bound: usize) -> Result<bool, Error> {
    let mut frame = serde_json::to_value(request)?;
    frame["action"] = serde_json::json!("attach");
    frame["schema_version"] = serde_json::json!(xmsg::client::SCHEMA_VERSION);
    Ok(serde_json::to_vec(&frame)?.len().saturating_add(1) <= bound)
}

async fn stage_attachment(
    service: &Endpoint,
    store: &mut Store,
    context: &VerifiedContext,
    file: &crate::attachments::Prepared,
) -> Result<(), Error> {
    let bound = service
        .frame_budget
        .min(service.max_body_bytes.ok_or(Error::Configuration)?);
    let inline = AttachRequest {
        name: Some(file.reference.name.clone()),
        media_type: Some(file.reference.media_type.clone()),
        data: Some(STANDARD.encode(&file.data)),
        ..Default::default()
    };
    let response = if attachment_frame_fits(&inline, bound)? {
        require_current(context, store)?;
        service.client.attach(inline).await?
    } else {
        let chunk_size = bound.saturating_sub(1024) / 4 * 3;
        if chunk_size == 0 {
            return Err(Error::Oversized);
        }
        let upload = format!("gateway-{}-{chunk_size}", file.reference.sha256);
        for (index, chunk) in file.data.chunks(chunk_size).enumerate() {
            let request = AttachRequest {
                upload: Some(upload.clone()),
                offset: Some(index * chunk_size),
                data: Some(STANDARD.encode(chunk)),
                ..Default::default()
            };
            if !attachment_frame_fits(&request, bound)? {
                return Err(Error::Oversized);
            }
            require_current(context, store)?;
            service.client.attach(request).await?;
        }
        let finish = AttachRequest {
            name: Some(file.reference.name.clone()),
            media_type: Some(file.reference.media_type.clone()),
            upload: Some(upload),
            sha256: Some(file.reference.sha256.clone()),
            ..Default::default()
        };
        if !attachment_frame_fits(&finish, bound)? {
            return Err(Error::Oversized);
        }
        require_current(context, store)?;
        service.client.attach(finish).await?
    };
    let reference: AttachmentRef = serde_json::from_value(
        response
            .get("attachment")
            .cloned()
            .ok_or(Error::Configuration)?,
    )?;
    if reference != file.reference {
        return Err(Error::Configuration);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn submit(
    store: &mut Store,
    service: &Endpoint,
    verifier: &crate::auth::Verifier,
    context: &VerifiedContext,
    bus_instance: &str,
    request: &Request,
    limits: &Limits,
    owner: &str,
    may_have_submitted: &AtomicBool,
    selected_grant: Option<&str>,
    prepared: &[crate::attachments::Prepared],
) -> Result<Outcome, Error> {
    let identity = context.identity();
    let authority = context.authority();
    if selected_grant.is_some_and(|id| id != authority.grant_id) {
        return Err(Error::Denied);
    }
    let policy = store.outbound_policy(&authority.grant_id)?;
    let (op, id, text) = request.parts();
    let permission = policy.permission(request)?;
    if !verifier.requires_scope_for(identity, &permission.required_scope) {
        return Err(Error::Denied);
    }
    let sender = service.sender.as_str();
    let existing = store.reservation(owner, op, id)?;
    let (target, correlation) = match request {
        Request::Send(args) => (args.to.clone(), None),
        Request::Reply(args) => (
            store.reply_target(
                bus_instance,
                &args.message_id,
                sender,
                identity,
                authority,
                existing.as_ref(),
                &permission,
            )?,
            Some(args.message_id.as_str()),
        ),
    };
    let references: Vec<_> = prepared.iter().map(|file| file.reference.clone()).collect();
    let refs_json = serde_json::to_string(&references)?;
    let payload_hash =
        payload_fingerprint(op, &target, correlation.unwrap_or(""), text, &references)?;
    if existing
        .as_ref()
        .is_some_and(|reservation| reservation.payload_hash != payload_hash)
    {
        return Err(Error::Conflict);
    }
    if !permission.admits_target(&target) {
        return Err(Error::Denied);
    }
    if let Some(reservation) = &existing {
        if reservation.grant_id != authority.grant_id || reservation.sender != sender {
            return Err(Error::Denied);
        }
        if let Some(receipt) = &reservation.receipt {
            require_current(context, store)?;
            return Ok(Outcome::Confirmed(serde_json::from_str(receipt)?));
        }
        if reservation.expired(limits) {
            store.expire_reservation(reservation, limits)?;
            return Ok(Outcome::Unknown);
        }
        if reservation.sender != sender
            || reservation.grant_id != authority.grant_id
            || reservation.grant_revision != authority.revision
        {
            return Err(Error::Denied);
        }
    }
    let Some((name, node)) = target.split_once('@') else {
        return Err(Error::Denied);
    };
    if permission.admits_node(node) {
        if matches!(request, Request::Send(_)) {
            let recipients = service
                .client
                .list(xmsg::client::ListQuery {
                    name: None,
                    node: Some(node.into()),
                    kind: None,
                    status: Some("live".into()),
                    ..Default::default()
                })
                .await?;
            if !node_scoped_send_admitted(&recipients, &target, name, node) {
                return Err(Error::Denied);
            }
        }
    } else {
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
    }
    if let Request::Reply(args) = request {
        if store.reply_target(
            bus_instance,
            &args.message_id,
            sender,
            identity,
            authority,
            None,
            &permission,
        )? != target
        {
            return Err(Error::Denied);
        }
    }
    for file in prepared {
        stage_attachment(service, store, context, file).await?;
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
            if !limits.text_fits(&framed_text) {
                return Err(Error::Oversized);
            }
            let timestamp_now = SystemTime::now();
            let (timestamp, retry_until) =
                reservation_times(timestamp_now, limits.dedup_lifetime_secs)?;
            let (_, recovery_until) =
                reservation_times(timestamp_now, limits.result_recovery_secs)?;
            let attachments_ready = crate::attachment_store::ready(&store.connection)?;
            let tx = store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let size_sql = if attachments_ready {
                "SELECT COUNT(*), COALESCE(SUM(length(CAST(framed_text AS BLOB))+length(CAST(attachments AS BLOB))),0) FROM outbound_reservations"
            } else {
                "SELECT COUNT(*), COALESCE(SUM(length(CAST(framed_text AS BLOB))),0) FROM outbound_reservations"
            };
            let (count, bytes): (i64, i64) =
                tx.query_row(size_sql, [], |r| Ok((r.get(0)?, r.get(1)?)))?;
            let retained_size = framed_text.len().saturating_add(if attachments_ready {
                refs_json.len()
            } else {
                0
            });
            if count >= limits.max_reservations
                || bytes.saturating_add(i64::try_from(retained_size).unwrap_or(i64::MAX))
                    > limits.max_retained_bytes
            {
                return Err(Error::Capacity);
            }
            tx.execute(
                "INSERT INTO outbound_request_fences(owner,request_id) VALUES(?1,?2)",
                params![owner, id.as_str()],
            )?;
            tx.execute("INSERT INTO outbound_reservations (owner,operation,request_id,payload_hash,sender,grant_id,grant_revision,idempotency_key,target,correlation,framed_text,created_at,retry_until,state,recovery_until) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'pending',?14)", params![owner,op,id.as_str(),payload_hash,sender,authority.grant_id,authority.revision,key,target,correlation,framed_text,timestamp,retry_until,recovery_until])?;
            if attachments_ready {
                tx.execute(
                    "UPDATE outbound_reservations SET attachments=?2 WHERE idempotency_key=?1",
                    params![key, refs_json],
                )?;
            }
            tx.commit()?;
            tracing::debug!(target: "gateway_outbound_reservation_committed", "pending reservation committed");
            store
                .reservation(owner, op, id)?
                .ok_or(Error::Configuration)?
        }
    };
    tracing::debug!(target:"gateway_outbound_reserved", "pending");
    require_current(context, store)?;
    if let Request::Reply(args) = request {
        if store.reply_target(
            bus_instance,
            &args.message_id,
            sender,
            identity,
            authority,
            None,
            &permission,
        )? != target
        {
            return Err(Error::Denied);
        }
    }
    if reservation.expired(limits) {
        store.expire_reservation(&reservation, limits)?;
        return Ok(Outcome::Unknown);
    }
    if !limits.text_fits(&reservation.framed_text) {
        return Err(Error::Oversized);
    }
    let key = reservation.key.clone();
    may_have_submitted.store(true, Ordering::Relaxed);
    let submitted = match reservation.correlation.as_deref() {
        Some(message_id) => service
            .client
            .reply_with_attachments(
                message_id,
                &reservation.framed_text,
                Some(&key),
                &reservation.attachments,
            )
            .await
            .map(|reply| Receipt::Reply(Box::new(reply))),
        None => service
            .client
            .send_with_attachments(
                &reservation.target,
                &reservation.framed_text,
                Some(&key),
                &reservation.attachments,
            )
            .await
            .map(Receipt::Send),
    };
    tracing::debug!(target:"gateway_outbound_submitted", "outcome awaiting commit");
    let accepted = submitted.is_ok();
    let persisted = (|| -> Result<Outcome, Error> {
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
    })();
    match persisted {
        Ok(outcome) => Ok(outcome),
        Err(_error) if accepted => Ok(Outcome::Pending),
        Err(_) => Ok(Outcome::Unknown),
    }
}

#[cfg(test)]
mod reservation_time_tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn fractional_reservation_times_preserve_the_complete_lifetime() {
        for seconds in [0, 1, 1_728_000_000] {
            for nanos in [0, 1, 999_999_999] {
                for lifetime in [1, 86_400] {
                    let elapsed = Duration::new(seconds, nanos);
                    let (created_at, retry_until) =
                        reservation_times(UNIX_EPOCH + elapsed, lifetime).unwrap();
                    assert_eq!(created_at, seconds as i64);
                    assert_eq!(
                        retry_until,
                        seconds as i64 + lifetime + i64::from(nanos != 0),
                        "reservation window was floored instead of ceiled"
                    );
                    let remaining = Duration::from_secs(retry_until as u64) - elapsed;
                    assert!(remaining >= Duration::from_secs(lifetime as u64));
                    assert!(remaining < Duration::from_secs(lifetime as u64 + 1));
                }
            }
        }
    }

    #[test]
    fn full_ttl_windows_end_by_the_pinned_nodes_first_purge_tick() {
        let revision = include_str!("../ci/xmsg-pin.toml")
            .lines()
            .find_map(|line| line.strip_prefix("revision = "))
            .expect("missing reviewed xmsg revision");
        assert_eq!(
            revision, "\"173f1527d4407a4f0abfd73bae9dc243c5708758\"",
            "review the node's idempotency retention boundary after a pin change"
        );
        // Reviewed xmsg 173f152 storage.rs:1215 and 1390–1400 retain keys through their final TTL tick.
        for nanos in [1, 999_999_999] {
            for ttl in [1, 86_400] {
                let (created_at, retry_until) =
                    reservation_times(UNIX_EPOCH + Duration::new(1_728_000_000, nanos), ttl)
                        .unwrap();
                for acceptance_delay in [0, 1] {
                    let node_accepted_floor = created_at + acceptance_delay;
                    let node_first_purge_tick = node_accepted_floor + ttl + 1;
                    assert!(retry_until <= node_first_purge_tick);
                    assert_eq!(retry_until + acceptance_delay, node_first_purge_tick);
                    assert!(node_accepted_floor >= (retry_until - 1) - ttl);
                }
            }
        }
    }

    #[test]
    fn unrepresentable_reservation_windows_are_configuration_refusals() {
        assert_eq!(
            reservation_times(UNIX_EPOCH, i64::MAX).unwrap(),
            (0, i64::MAX)
        );
        for (at, lifetime) in [
            (UNIX_EPOCH, 0),
            (UNIX_EPOCH, -1),
            (UNIX_EPOCH - Duration::from_nanos(1), 1),
            (UNIX_EPOCH + Duration::from_secs(1), i64::MAX),
            (UNIX_EPOCH + Duration::from_nanos(1), i64::MAX),
        ] {
            assert!(matches!(
                reservation_times(at, lifetime),
                Err(Error::Configuration)
            ));
        }
    }

    #[test]
    fn retry_deadlines_preserve_stored_windows_and_reduce_with_limits() {
        let mut limits = Limits {
            dedup_lifetime_secs: 1,
            result_recovery_secs: 86400,
            max_framed_bytes: 1,
            timeout: Duration::from_secs(1),
            max_reservations: 1,
            max_retained_bytes: 1,
        };
        let mut reservation = Reservation {
            key: String::new(),
            payload_hash: String::new(),
            sender: String::new(),
            grant_id: String::new(),
            grant_revision: 1,
            framed_text: String::new(),
            attachments: vec![],
            correlation: None,
            created_at: 100,
            retry_until: 101,
            receipt: None,
            target: String::new(),
        };
        assert_eq!(
            reservation.retry_deadline(&limits),
            101,
            "stored retry deadline was extended"
        );
        limits.dedup_lifetime_secs = 86_400;
        assert_eq!(
            reservation.retry_deadline(&limits),
            101,
            "stored retry deadline was extended"
        );
        reservation.retry_until = 86_501;
        assert_eq!(
            reservation.retry_deadline(&limits),
            86_501,
            "ceiled retry window was shortened"
        );
        limits.dedup_lifetime_secs = 1;
        assert_eq!(reservation.retry_deadline(&limits), 102);
        limits.dedup_lifetime_secs = 10;
        assert_eq!(reservation.retry_deadline(&limits), 111);
        reservation.created_at = i64::MAX - 1;
        reservation.retry_until = i64::MAX;
        assert_eq!(reservation.retry_deadline(&limits), i64::MAX);
    }
}

#[cfg(test)]
mod events_reply_tests {
    use super::*;
    use crate::event_store::EventKey;
    use crate::grants::Binding;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn first_release_reply_requires_owned_current_dispatch_authority() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("store");
        let key_file = dir.path().join("key");
        std::fs::write(&key_file, [11u8; 32]).unwrap();
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let key = EventKey::load(&key_file).unwrap();
        let mut store = Store::initialize(&file).unwrap();
        store.migrate_custody().unwrap();
        store.migrate_outbound().unwrap();
        store.migrate_events(&key).unwrap();
        let binding = Binding {
            service: "gateway".into(),
            issuer: "https://issuer.example/".into(),
            resource: "https://gateway.example/mcp".into(),
            subject: "owner".into(),
            hosted_client: "hosted-client".into(),
        };
        store.enroll("grant", &binding).unwrap();
        store.connection.execute(r#"INSERT INTO custody_items(bus,upstream_id,event_id,grant_id,grant_revision,mailbox,owner,origin,text,envelope,fingerprint,received_at,expires_at,held) VALUES ('bus','first','first','grant',1,'gateway@bus','owner','{"id":null,"service":"source","node":"source-node"}','body','envelope','first',1,9999999999,1)"#,[]).unwrap();
        let tx = store.connection.transaction().unwrap();
        tx.execute(
            "INSERT INTO custody_outbox(event_id,state) VALUES ('first','held')",
            [],
        )
        .unwrap();
        crate::event_store::record_acceptance(&tx, "first", "grant", 1).unwrap();
        tx.commit().unwrap();
        store.set_enabled("grant", 1, true).unwrap();
        let identity = crate::provider_fixture::verified(&binding);
        let authority = store.authorize(&identity).unwrap();
        let permission = Permission {
            targets: ["source@source-node".into()].into(),
            required_scope: "reply:write".into(),
        };
        assert_eq!(
            store
                .reply_target(
                    "bus",
                    "first",
                    "gateway@bus",
                    &identity,
                    &authority,
                    None,
                    &permission
                )
                .unwrap(),
            "source@source-node"
        );
        assert!(matches!(
            store.reply_target(
                "bus",
                "first",
                "foreign@bus",
                &identity,
                &authority,
                None,
                &permission
            ),
            Err(Error::Denied)
        ));
        let mut foreign = binding.clone();
        foreign.subject = "foreign".into();
        let foreign_identity = crate::provider_fixture::verified(&foreign);
        assert!(matches!(
            store.reply_target(
                "bus",
                "first",
                "gateway@bus",
                &foreign_identity,
                &authority,
                None,
                &permission
            ),
            Err(Error::Denied)
        ));
        store.set_enabled("grant", 2, false).unwrap();
        store.set_enabled("grant", 3, true).unwrap();
        let current = store.authorize(&identity).unwrap();
        assert!(matches!(
            store.reply_target(
                "bus",
                "first",
                "gateway@bus",
                &identity,
                &current,
                None,
                &permission
            ),
            Err(Error::Denied)
        ));
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT grant_revision FROM custody_items WHERE event_id='first'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1,
            "reply eligibility rewrote acceptance snapshot"
        );
    }
}
