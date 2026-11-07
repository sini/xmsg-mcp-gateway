use serde_json::json;
use xmsg_mcp_gateway::xmsg_config::{DeploymentManifest, ManifestError};

fn document() -> serde_json::Value {
    json!({"reply_ttl_secs":604800,"idempotency_ttl_secs":86400,
        "svc_queue_cap":100,"dedup_lifetime_secs":3600,"max_text_bytes":65536})
}

#[test]
fn messaging_manifest_requires_every_value_and_rejects_unknown_fields() {
    let valid = document();
    let manifest: DeploymentManifest = serde_json::from_value(valid.clone()).unwrap();
    manifest
        .check(Some(604800), Some(86400), Some(100))
        .unwrap();
    for field in valid.as_object().unwrap().keys() {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<DeploymentManifest>(missing).is_err(),
            "missing manifest field was defaulted: {field}"
        );
    }
    let mut unknown = valid;
    unknown["mailbox"] = json!("other@node");
    assert!(serde_json::from_value::<DeploymentManifest>(unknown).is_err());
}

#[test]
fn each_effective_node_limit_is_checked_independently() {
    let manifest: DeploymentManifest = serde_json::from_value(document()).unwrap();
    for (reply, dedup, cap, expected) in [
        (Some(1), Some(86400), Some(100), ManifestError::ReplyTtl),
        (
            Some(604800),
            Some(1),
            Some(100),
            ManifestError::IdempotencyTtl,
        ),
        (
            Some(604800),
            Some(86400),
            Some(1),
            ManifestError::QueueCapacity,
        ),
        (None, Some(86400), Some(100), ManifestError::ReplyTtl),
        (Some(604800), None, Some(100), ManifestError::IdempotencyTtl),
        (
            Some(604800),
            Some(86400),
            None,
            ManifestError::QueueCapacity,
        ),
    ] {
        assert_eq!(manifest.check(reply, dedup, cap), Err(expected));
    }
}

#[test]
fn dedup_lifetime_and_complete_text_bound_fail_closed() {
    for (field, value, error) in [
        ("dedup_lifetime_secs", 86401, ManifestError::DedupLifetime),
        ("dedup_lifetime_secs", 0, ManifestError::DedupLifetime),
        ("max_text_bytes", 65537, ManifestError::TextBound),
        ("max_text_bytes", 0, ManifestError::TextBound),
    ] {
        let mut invalid = document();
        invalid[field] = json!(value);
        let manifest: DeploymentManifest = serde_json::from_value(invalid).unwrap();
        assert_eq!(
            manifest.check(Some(604800), Some(86400), Some(100)),
            Err(error)
        );
    }
    let mut unrepresentable = document();
    unrepresentable["idempotency_ttl_secs"] = json!(u64::MAX);
    unrepresentable["dedup_lifetime_secs"] = json!(i64::MAX as u64 + 1);
    let manifest: DeploymentManifest = serde_json::from_value(unrepresentable).unwrap();
    assert_eq!(
        manifest.check(Some(604800), Some(u64::MAX), Some(100)),
        Err(ManifestError::DedupLifetime)
    );
}
