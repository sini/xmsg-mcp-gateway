//! Static, content-free tool outcome diagnostics.
use crate::{auth, event_store, events, grants, outbound, reads, recovery, session};

pub(crate) fn emit(operation: &'static str, class: &'static str, kind: &'static str) {
    tracing::info!(target: "gateway_dispatch", operation, class, kind, "dispatch outcome");
}
pub(crate) fn operation(name: &str) -> &'static str {
    match name {
        "xmsg_send" => "xmsg_send",
        "xmsg_reply" => "xmsg_reply",
        "xmsg_list" => "xmsg_list",
        "xmsg_inbox" => "xmsg_inbox",
        "xmsg_read_message" => "xmsg_read_message",
        "xmsg_ack" => "xmsg_ack",
        "xmsg_message_status" => "xmsg_message_status",
        "xmsg_identity" => "xmsg_identity",
        "gist" => "gist",
        "gist_read" => "gist_read",
        "gist_update" => "gist_update",
        "gist_comment" => "gist_comment",
        _ => "unrecognized",
    }
}
fn verifier(error: &auth::Error) -> &'static str {
    match error {
        auth::Error::Configuration => "verifier_configuration",
        auth::Error::InvalidToken => "verifier_invalid_token",
        auth::Error::Denied => "store_denied",
        auth::Error::Unavailable => "verifier_unavailable",
    }
}
fn authority(error: &grants::Error) -> &'static str {
    match error {
        grants::Error::Denied => "store_denied",
        grants::Error::NoChange => "store_no_change",
        grants::Error::Conflict => "store_conflict",
        grants::Error::InvalidBinding => "store_invalid_binding",
        grants::Error::InvalidStore => "store_invalid",
        grants::Error::ProfileMismatch => "store_profile_mismatch",
        grants::Error::Io(_) => "store_io",
        grants::Error::Database(_) => "store_database",
        grants::Error::OperationBusy => "store_busy",
    }
}
fn client(error: &xmsg::client::ClientError) -> &'static str {
    use xmsg::client::ClientError;
    match error {
        ClientError::Configuration => "client_configuration",
        ClientError::Peer => "client_peer",
        ClientError::Io(_) => "client_io",
        ClientError::Timeout => "client_timeout",
        ClientError::Protocol => "client_protocol",
        ClientError::Disconnected => "client_disconnected",
        ClientError::Refused { code } => match code.as_str() {
            "not_found" => "not_found",
            "unavailable" => "unavailable",
            "denied" => "denied",
            "refused" => "refused",
            "unknown_peer" => "unknown_peer",
            "queue_full" => "queue_full",
            "bad_request" => "bad_request",
            "unattested" => "unattested",
            "conflict" => "conflict",
            _ => "unrecognized",
        },
    }
}
pub(crate) fn outbound(error: &outbound::Error) -> (&'static str, &'static str) {
    use outbound::Error;
    let class = match error {
        Error::Denied
        | Error::Authority(grants::Error::Denied)
        | Error::Authentication(auth::Error::InvalidToken) => "denied",
        Error::Conflict => "conflict",
        Error::Oversized | Error::Configuration => "invalid",
        _ => "pre_effect_unavailable",
    };
    let kind = match error {
        Error::MigrationRequired => "migration_required",
        Error::Denied => "denied",
        Error::Conflict => "conflict",
        Error::Oversized => "oversized",
        Error::Configuration => "configuration",
        Error::Deadline => "deadline",
        Error::Capacity => "capacity",
        Error::Busy => "store_busy",
        Error::Authority(e) => authority(e),
        Error::Database(_) => "store_database",
        Error::Encoding(_) => "encoding",
        Error::Authentication(e) => verifier(e),
        Error::Transport(e) => client(e),
    };
    (class, kind)
}
pub(crate) fn broker(error: &outbound::Error, confirmed: bool) -> (&'static str, &'static str) {
    let (class, kind) = outbound(error);
    let exception = matches!(
        error,
        outbound::Error::Denied
            | outbound::Error::Authority(grants::Error::Denied)
            | outbound::Error::Authentication(auth::Error::InvalidToken)
            | outbound::Error::Conflict
            | outbound::Error::Oversized
    );
    (
        if confirmed && !exception {
            "pending"
        } else {
            class
        },
        kind,
    )
}
pub(crate) fn session(error: &session::Error) -> &'static str {
    match error {
        session::Error::Registration(e) => client(e),
        session::Error::Manifest(_) => "manifest",
        session::Error::Identity => "identity",
        session::Error::Ledger => "store_database",
    }
}
fn event_store(error: &event_store::Error) -> &'static str {
    match error {
        event_store::Error::MigrationRequired => "migration_required",
        event_store::Error::Key => "key",
        event_store::Error::Database(_) => "store_database",
        event_store::Error::Authority(e) => authority(e),
    }
}
pub(crate) fn recovery(error: &recovery::Error) -> (&'static str, &'static str) {
    match error {
        recovery::Error::Arguments => ("invalid", "arguments"),
        recovery::Error::Authority(grants::Error::Denied) => ("denied", "store_denied"),
        recovery::Error::Authority(e) => ("pre_effect_unavailable", authority(e)),
        recovery::Error::Database(_) => ("pre_effect_unavailable", "store_database"),
        recovery::Error::Events(e) => ("pre_effect_unavailable", event_store(e)),
        recovery::Error::Encoding(_) => ("pre_effect_unavailable", "encoding"),
        recovery::Error::Broker(e) => outbound(e),
    }
}
pub(crate) fn reads(error: &reads::Error) -> (&'static str, &'static str) {
    match error {
        reads::Error::Arguments => ("invalid", "arguments"),
        reads::Error::Authority(grants::Error::Denied) => ("denied", "store_denied"),
        reads::Error::Authority(e) => ("pre_effect_unavailable", authority(e)),
        reads::Error::Database(_) => ("pre_effect_unavailable", "store_database"),
        reads::Error::Encoding(_) => ("pre_effect_unavailable", "encoding"),
    }
}
pub(crate) fn identity(error: &events::Error) -> (&'static str, &'static str) {
    let class = match error {
        events::Error::Authority(grants::Error::Denied)
        | events::Error::Credentials(auth::Error::InvalidToken) => "denied",
        _ => "pre_effect_unavailable",
    };
    let kind = match error {
        events::Error::Arguments => "arguments",
        events::Error::Conflict => "conflict",
        events::Error::Busy => "store_busy",
        events::Error::Authority(e) => authority(e),
        events::Error::Credentials(e) => verifier(e),
        events::Error::Store(e) => event_store(e),
        events::Error::Database(_) => "store_database",
        events::Error::Callback(_) => "callback",
    };
    (class, kind)
}

#[cfg(test)]
mod tests {
    #[test]
    fn confirmed_broker_errors_follow_pending_response_exceptions() {
        use crate::outbound::Error;
        assert_eq!(
            super::broker(&Error::Configuration, true),
            ("pending", "configuration")
        );
        assert_eq!(
            super::broker(&Error::Configuration, false),
            ("invalid", "configuration")
        );
        for (error, class) in [
            (Error::Denied, "denied"),
            (Error::Conflict, "conflict"),
            (Error::Oversized, "invalid"),
            (
                Error::Authentication(crate::auth::Error::InvalidToken),
                "denied",
            ),
            (Error::Authority(crate::grants::Error::Denied), "denied"),
        ] {
            assert_eq!(super::broker(&error, true).0, class);
        }
    }
}
