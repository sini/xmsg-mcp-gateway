//! Closed, content-free Events diagnostics emitted only after durable changes.
pub(crate) fn transition(reason: &str, changed: usize, held: usize, released: usize) {
    let reason = match reason {
        "enabled" => "enabled",
        "verifying" => "verifying",
        "disabled_by_revision" => "disabled_by_revision",
        "renewed" => "renewed",
        "expired" => "expired",
        "rebind" => "rebind",
        "unsubscribed" => "unsubscribed",
        "replay" => "replay",
        "release" => "release",
        _ => "unrecognized",
    };
    tracing::info!(target:"gateway_events",class="subscription",reason,changed,held,released,"Events transition");
}
pub(crate) fn delivery(class: &str, reason: Option<&str>, attempt: i64) {
    let class = match class {
        "accepted" => "accepted",
        "retry" => "retry",
        "backoff" => "backoff",
        "dead" => "dead",
        "token_parked" => "token_parked",
        _ => "unrecognized",
    };
    let reason = match reason {
        None => "none",
        Some("attempts_exhausted") => "attempts_exhausted",
        Some("payload_protocol_error") => "payload_protocol_error",
        Some("delivery_gone") => "delivery_gone",
        Some("callback_terminal") => "callback_terminal",
        Some("callback_retryable") => "callback_retryable",
        Some("callback_transport") => "callback_transport",
        Some("credential_required") => "credential_required",
        _ => "unrecognized",
    };
    tracing::info!(target:"gateway_events",class,reason,attempt,"Events delivery outcome");
}
#[derive(Default)]
pub(crate) struct Fence {
    pub(crate) held: usize,
    pub(crate) subscriptions: usize,
    pub(crate) released: usize,
}
impl Fence {
    pub(crate) fn committed(self) {
        if self.held > 0 || self.subscriptions > 0 {
            transition(
                "disabled_by_revision",
                self.subscriptions,
                self.held,
                self.released,
            );
        } else if self.released > 0 {
            transition("enabled", 0, 0, self.released);
        }
    }
}

pub(crate) fn expired() {
    tracing::info!(target:"gateway_events",class="subscription",reason="expired","Events expiry observed");
}
