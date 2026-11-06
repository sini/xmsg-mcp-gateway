use xmsg_mcp_gateway::auth::{Error, Verifier, VerifierConfig};

#[test]
fn configuration_rejects_insecure_urls_and_unknown_fields() {
    let temp = tempfile::tempdir().unwrap();
    let secret = temp.path().join("secret");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options
        .open(&secret)
        .unwrap()
        .write_all(b"fixture-secret")
        .unwrap();
    let raw = serde_json::json!({
        "service": "gateway", "issuer": "https://issuer.example/",
        "resource": "https://gateway.example/mcp", "subject": "owner",
        "hosted_client": "hosted-client", "introspection_url": "https://provider.test/token",
        "introspection_client": "lookup-client", "client_secret_file": secret,
        "provider_addresses": ["127.0.0.1"], "required_scopes": ["identity:read"],
        "timeout_ms": 1000
    });
    assert!(Verifier::from_config(serde_json::from_value(raw.clone()).unwrap()).is_ok());
    for (field, value) in [
        (
            "introspection_url",
            serde_json::json!("http://provider.test/token"),
        ),
        ("issuer", serde_json::json!("http://issuer.example/")),
        ("resource", serde_json::json!("http://gateway.example/mcp")),
        ("provider_addresses", serde_json::json!([])),
        ("timeout_ms", serde_json::json!(0)),
        ("timeout_ms", serde_json::json!(30_001)),
        ("required_scopes", serde_json::json!([])),
        ("required_scopes", serde_json::json!(["invalid scope"])),
        ("hosted_client", serde_json::json!("")),
        ("introspection_client", serde_json::json!("bad:client")),
    ] {
        let mut invalid = raw.clone();
        invalid[field] = value;
        let config: VerifierConfig = serde_json::from_value(invalid).unwrap();
        assert!(
            matches!(Verifier::from_config(config), Err(Error::Configuration)),
            "accepted config {field}"
        );
    }
    let mut literal = raw.clone();
    literal["introspection_url"] = serde_json::json!("https://127.0.0.2/token");
    assert!(
        matches!(
            Verifier::from_config(serde_json::from_value(literal).unwrap()),
            Err(Error::Configuration)
        ),
        "accepted out-of-list IP literal"
    );
    let mut unknown = raw;
    unknown["verified"] = true.into();
    assert!(serde_json::from_value::<VerifierConfig>(unknown).is_err());
}

#[path = "common/provider.rs"]
mod provider;

fn binding() -> xmsg_mcp_gateway::grants::Binding {
    xmsg_mcp_gateway::grants::Binding {
        service: "gateway".into(),
        issuer: "https://issuer.example/".into(),
        resource: "https://gateway.example/mcp".into(),
        subject: "owner".into(),
        hosted_client: "hosted-client".into(),
    }
}

#[test]
fn only_the_configured_provider_can_verify_the_token() {
    let binding = binding();
    let identity = provider::verified(&binding);
    assert_eq!(identity.subject(), "owner");
    assert_eq!(identity.hosted_client(), "hosted-client");
    for (field, value) in [
        ("active", serde_json::json!(false)),
        ("iss", serde_json::json!("https://foreign.example/")),
        ("aud", serde_json::json!("kanidm-client")),
        ("aud", serde_json::json!([binding.resource, "extra"])),
        ("sub", serde_json::json!("other-owner")),
        ("client_id", serde_json::json!("lookup-client")),
        ("exp", serde_json::json!(0)),
        ("exp", serde_json::json!(true)),
        ("nbf", serde_json::json!(u64::MAX)),
        ("scope", serde_json::json!("other:read")),
    ] {
        let mut claims = provider::claims(&binding);
        claims[field] = value;
        assert!(
            matches!(
                provider::verify_response(&binding, claims, 200),
                Err(Error::InvalidToken)
            ),
            "accepted {field}"
        );
    }
    assert!(matches!(
        provider::verify_response(&binding, provider::claims(&binding), 302),
        Err(Error::Unavailable)
    ));
}

#[test]
fn oversized_provider_body_is_unavailable() {
    let binding = binding();
    let mut claims = provider::claims(&binding);
    claims["padding"] = "x".repeat(65_537).into();
    assert!(
        matches!(
            provider::verify_response(&binding, claims, 200),
            Err(Error::Unavailable)
        ),
        "oversized provider body accepted"
    );
}

#[test]
fn redirects_never_reach_an_active_token_provider() {
    let binding = binding();
    let (result, target_requests, _) = provider::network_case(
        &binding,
        provider::claims(&binding),
        302,
        true,
        std::time::Duration::ZERO,
        2000,
    );
    assert_eq!(target_requests, 0, "redirect target received a request");
    assert!(
        matches!(result, Err(Error::Unavailable)),
        "redirect was accepted"
    );
}

#[test]
fn stalled_provider_is_refused_before_its_response() {
    let binding = binding();
    let (result, _, elapsed) = provider::network_case(
        &binding,
        provider::claims(&binding),
        200,
        false,
        std::time::Duration::from_millis(900),
        250,
    );
    assert!(
        matches!(result, Err(Error::Unavailable)),
        "provider timeout refusal missing"
    );
    assert!(
        elapsed < std::time::Duration::from_millis(750),
        "provider timeout bound exceeded: {elapsed:?}"
    );
}
