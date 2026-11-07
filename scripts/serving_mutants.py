"""Witness runtime identity misuse without weakening the verifier module boundary."""

import shutil
import tempfile
import time
from pathlib import Path

from grant_mutants import ROOT, run

SOURCE = (ROOT / "src/serving.rs").read_text()
start = SOURCE.index("    let identity = match app.verifier.verify(&token).await {")
end = SOURCE.index("\n    };", start) + len("\n    };")
verification = SOURCE[start:end]
cached = (
    """    let identity = {
        static CACHE: std::sync::OnceLock<Arc<VerifiedIdentity>> = std::sync::OnceLock::new();
        if let Some(identity) = CACHE.get() { identity.clone() } else {
"""
    + verification
    + """
            let _ = CACHE.set(identity.clone());
            identity
        }
    };"""
)
eager = (
    """    let identity = {
        if let Err(error) = Store::open(&app.grant_store) { return policy_response(error.into()); }
"""
    + verification
    + """
        identity
    };"""
)
CASES = [
    (
        "fail-open",
        "Err(error) => return auth_response(error, &app.challenge),",
        'Err(_error) => return rpc_result(&Value::Null, json!({"subject":"unverified"})),',
        "unapproved_token_cannot_use_a_verified_flag_to_fail_open",
        "verification failure was accepted",
    ),
    (
        "different-token-reuse",
        verification,
        cached,
        "each_request_rechecks_the_current_token",
        "different token reused prior identity",
    ),
    (
        "revoked-token-reuse",
        verification,
        cached,
        "revocation_is_checked_on_a_later_request",
        "revoked token reused prior identity",
    ),
    (
        "precedence",
        """    if identity_spoof(&body) {
        return StatusCode::FORBIDDEN.into_response();
    }""",
        """    if identity_spoof(&body) {
        return rpc_result(&body["id"], json!({"subject": body["params"]["_meta"].get("subject").unwrap_or(&body["params"]["arguments"]["subject"])}));
    }""",
        "caller_identity_fields_cannot_override_verified_identity",
        "caller identity data was accepted",
    ),
    (
        "order",
        verification,
        eager,
        "invalid_token_is_refused_before_an_unavailable_store_is_opened",
        "policy lookup preceded authentication",
    ),
    (
        "grant-recheck",
        "store.authorize(&identity)",
        'Ok::<Authorization, GrantError>(Authorization { grant_id: "cached".into(), revision: 2 })',
        "grant_is_rechecked_after_discovery",
        "disabled grant was accepted",
    ),
]

start = SOURCE.index("async fn mcp(State(app)")
end = SOURCE.index("\nasync fn mcp_request", start)
deadline = SOURCE[start:end]
authority_start = SOURCE.index("async fn mcp_request(")
authority_end = SOURCE.index("    let token =", authority_start)
authority = SOURCE[authority_start:authority_end]
CASES += [
    (
        "post-policy-expiry",
        "if now >= identity.expires_at()",
        "if false",
        "token_expiry_during_policy_wait_prevents_dispatch",
        "expired token reached dispatch",
    ),
    (
        "state-profile",
        "store\n            .validate_profile(&profile)",
        "Ok::<(), GrantError>(())",
        "state_cannot_be_reused_for_another_service_resource_or_owner",
        "foreign authority profile was accepted",
    ),
    (
        "body-deadline",
        deadline,
        "async fn mcp(State(app): State<Arc<App>>, request: Request) -> Response { mcp_request(app, request, Arc::new(OnceLock::new())).await }\n",
        "body_read_is_bounded_before_any_credential_or_policy_io",
        "request body deadline was not enforced",
    ),
    (
        "body-bound",
        "const MAX_REQUEST: usize = 65_536;",
        "const MAX_REQUEST: usize = 1_048_576;",
        "http_host_origin_body_and_method_guards_hold",
        "oversized MCP request was accepted",
    ),
    (
        "http-authority",
        authority,
        authority.replace("if !permitted_request(&app, &request)", "if false"),
        "http_host_origin_body_and_method_guards_hold",
        "untrusted HTTP authority was accepted",
    ),
]

CASES.append(
    (
        "relative-profile-paths",
        "if file.is_relative()",
        "if false",
        "relative_paths_belong_to_the_owner_configuration_directory",
        "relative path resolved outside owner configuration directory",
    )
)

CASES += [
    (
        "owner-config-schema",
        "#[serde(deny_unknown_fields)]\nstruct Configuration {",
        "struct Configuration {",
        "owner_file_permissions_and_unknown_fields_are_checked",
        "unknown owner config fields accepted",
    ),
    (
        "owner-config-mode",
        "metadata.permissions().mode() & 0o077 != 0",
        "false",
        "owner_file_permissions_and_unknown_fields_are_checked",
        "public owner configuration accepted",
    ),
    (
        "loopback-bind",
        "!config.bind.ip().is_loopback()",
        "false",
        "incomplete_or_exposed_serving_profiles_are_refused",
        "unsafe serving profile accepted: bind",
    ),
]


def main():
    evidence = ROOT / ".artifacts/serving-mutants"
    evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gateway-serving-mutants-") as directory:
        root = Path(directory)
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copyfile(ROOT / name, root / name)
        for name in ("src", "tests"):
            shutil.copytree(ROOT / name, root / name, copy_function=shutil.copyfile)
        file = root / "src/serving.rs"
        original = file.read_text()
        for name, old, new, test, expected_red in CASES:
            assert original.count(old) == 1, (name, original.count(old))
            file.touch()
            started = time.monotonic()
            green = run(root, "serving", test, "src/serving.rs")
            assert (
                green.returncode == 0
                and "1 passed; 0 failed; 0 ignored" in green.stdout
            ), (name, "invalid baseline", green.stdout, green.stderr)
            print(
                f"{name}: baseline completed in {time.monotonic() - started:.1f}s",
                flush=True,
            )
            try:
                file.write_text(original.replace(old, new, 1))
                red = run(root, "serving", test, "src/serving.rs")
                assert (
                    red.returncode == 101
                    and f"test {test} ... FAILED" in red.stdout
                    and expected_red in red.stdout
                ), (name, "survivor or wrong red", red.stdout, red.stderr)
                (evidence / f"{name}.log").write_text(red.stdout + red.stderr)
                print(f"{name}: GREEN baseline, RED intended misuse test", flush=True)
            finally:
                file.write_text(original)
                file.touch()
    print(f"{len(CASES)}/{len(CASES)} serving mutants killed", flush=True)


if __name__ == "__main__":
    main()
