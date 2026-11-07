"""Prove the real MCP composition's request identity and cancellation boundaries."""

import argparse
import tempfile
from pathlib import Path

from grant_mutants import run
from transport_compat import ROOT, copy_fixture_tree

MCP = "real_mcp_send_keeps_request_identity_and_owner_policy"
ARGUMENTS = "serde_json::from_value::<outbound::SendArguments>(call.arguments)"
CASES = [
    (
        "detached-dispatch",
        "src/serving.rs",
        "tokio::spawn(work);",
        "work.await;",
        "messaging",
        "cancelling_a_handler_does_not_cancel_the_accepted_operation",
        "detached dispatch did not commit before retry",
    ),
    (
        "rpc-id-is-not-request-id",
        "src/serving.rs",
        "Ok(request) => request,",
        """Ok(mut request) => {
        let id = outbound::RequestId::parse(&id.to_string()).unwrap();
        match &mut request {
            outbound::Request::Send(args) => args.request_id = id,
            outbound::Request::Reply(args) => args.request_id = id,
        }
        request
    },""",
        "messaging",
        MCP,
        "RPC id changed logical send",
    ),
    (
        "metadata-is-not-request-id",
        "src/serving.rs",
        ARGUMENTS,
        """serde_json::from_value::<outbound::SendArguments>({
        let mut arguments = call.arguments;
        if arguments.get("request_id").is_none() {
            arguments["request_id"] = call._metadata.get("request_id").cloned().unwrap_or(Value::Null);
        }
        arguments
    })""",
        "messaging",
        MCP,
        "request_id came from outside strict tool arguments",
    ),
    (
        "missing-id-is-not-stringified-rpc-id",
        "src/serving.rs",
        ARGUMENTS,
        """serde_json::from_value::<outbound::SendArguments>({
        let mut arguments = call.arguments;
        if arguments.get("request_id").is_none() {
            arguments["request_id"] = json!(id.to_string());
        }
        arguments
    })""",
        "messaging",
        MCP,
        "request_id came from outside strict tool arguments",
    ),
    (
        "default-empty-policy",
        "src/serving.rs",
        "if !permission_enabled(&app, permission) {",
        "if false {",
        "messaging",
        MCP,
        "empty policy reached dispatcher",
    ),
]

for name, getter, field, test in [
    (
        "effective-reply-ttl",
        "reply_ttl_secs",
        "reply_ttl_secs",
        "reply_ttl_mismatch_refuses_before_router_availability",
    ),
    (
        "effective-idempotency-ttl",
        "idempotency_ttl_secs",
        "idempotency_ttl_secs",
        "idempotency_ttl_mismatch_refuses_before_router_availability",
    ),
    (
        "effective-queue-capacity",
        "svc_queue_cap",
        "svc_queue_cap",
        "queue_capacity_mismatch_refuses_before_router_availability",
    ),
]:
    CASES.append(
        (
            name,
            "src/serving.rs",
            f"registered.{getter}()",
            f"Some(messaging.manifest.{field})",
            "messaging",
            test,
            "inconsistent node manifest reached the router",
        )
    )

CASES.extend(
    [
        (
            "service-name-at-load",
            "src/xmsg_config.rs",
            "xmsg::client::validate_service_name(&self.service)",
            "Ok::<(), String>(())",
            "messaging",
            "invalid_service_names_refuse_at_configuration_load",
            "invalid name reached registration",
        ),
        (
            "dedup-lifetime",
            "src/xmsg_config.rs",
            "self.dedup_lifetime_secs > self.idempotency_ttl_secs",
            "false",
            "messaging",
            "dedup_lifetime_above_the_node_limit_refuses_startup",
            "inconsistent node manifest reached the router",
        ),
        (
            "no-degraded-profile",
            "src/serving.rs",
            "if let Some(messaging) = config.messaging {",
            "if let Some(messaging) = config.messaging.filter(|_| false) {",
            "messaging",
            "registration_failure_never_degrades_to_identity_only",
            "registration failure reached the router",
        ),
        (
            "explicit-messaging-migration",
            "src/serving.rs",
            "store\n                .require_outbound_ready()",
            "Ok::<(), outbound::Error>(())",
            "messaging",
            "messaging_requires_explicit_migration_and_a_complete_budget",
            "MigrationRequired",
        ),
        (
            "request-budget",
            "src/serving.rs",
            "if config.request_timeout_ms < minimum_budget",
            "if false",
            "messaging",
            "messaging_requires_explicit_migration_and_a_complete_budget",
            "insufficient messaging budget was accepted",
        ),
        (
            "manifest-no-defaults",
            "src/xmsg_config.rs",
            "pub reply_ttl_secs: u64,",
            "#[serde(default)]\n    pub reply_ttl_secs: u64,",
            "messaging",
            "absent_messaging_is_identity_only_and_partial_messaging_is_not",
            "missing messaging value was defaulted",
        ),
        (
            "manifest-unknown-fields",
            "src/xmsg_config.rs",
            "#[serde(deny_unknown_fields)]\npub struct DeploymentManifest",
            "pub struct DeploymentManifest",
            "deployment_manifest",
            "messaging_manifest_requires_every_value_and_rejects_unknown_fields",
            "unknown manifest field accepted",
        ),
        (
            "framed-field-no-alias",
            "src/xmsg_config.rs",
            "pub max_framed_bytes: usize,",
            '#[serde(alias = "max_text_bytes")]\n    pub max_framed_bytes: usize,',
            "deployment_manifest",
            "messaging_manifest_requires_every_value_and_rejects_unknown_fields",
            "legacy field alias accepted",
        ),
        (
            "reported-body-bound",
            "src/xmsg_config.rs",
            "effective_max_body.is_none_or(|bound| self.max_framed_bytes > bound)",
            "false",
            "deployment_manifest",
            "complete_frame_must_fit_the_reported_node_body_bound",
            "reported node body limit was ignored",
        ),
        (
            "null-is-not-absence",
            "src/serving.rs",
            '#[serde(default, deserialize_with = "present_messaging")]',
            "#[serde(default)]",
            "messaging",
            "absent_messaging_is_identity_only_and_partial_messaging_is_not",
            "null messaging silently became identity-only",
        ),
        (
            "discovery-policy",
            "src/serving.rs",
            "if !permission_enabled(app, permission)",
            "if false",
            "messaging",
            "fresh_policy_is_empty_and_cannot_be_changed_by_mcp",
            "empty policy advertised messaging authority",
        ),
        (
            "reply-route",
            "src/serving.rs",
            '"xmsg_send" => {',
            '"xmsg_reply" => {',
            "messaging",
            "mcp_replies_use_owned_custody_and_the_original_bus_receipt",
            "owned MCP reply was not confirmed",
        ),
        (
            "scope-ceiling",
            "src/serving.rs",
            "app.verifier.requires_scope(&permission.required_scope)",
            "true",
            "messaging",
            "unconfigured_scopes_do_not_advertise_or_dispatch_messaging",
            "unconfigured scope advertised messaging authority",
        ),
        (
            "configured-framed-bound",
            "src/serving.rs",
            "max_framed_bytes: messaging.manifest.max_framed_bytes,",
            "max_framed_bytes: 65536,",
            "messaging",
            "the_complete_framed_bound_is_used_instead_of_the_payload_length",
            "configured complete framed bound was ignored",
        ),
    ]
)

CASES.append(
    (
        "deadline-pending-response",
        "src/serving.rs",
        "Some(pending) => pending_response(pending),",
        "Some(_) => unavailable(),",
        "messaging",
        "handler_deadline_reports_pending_without_cancelling_accepted_work",
        "handler deadline hid its pending request",
    )
)


def main():
    if len(CASES) != 23:
        raise RuntimeError("wiring mutant inventory drift")
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=[case[0] for case in CASES])
    args = parser.parse_args()
    selected = [case for case in CASES if not args.case or case[0] == args.case]
    evidence = ROOT / ".artifacts/wiring-mutants"
    evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gateway-wiring-mutants-") as directory:
        root = Path(directory)
        copy_fixture_tree(root)
        completed = 0
        for name, filename, before, after, target, test, expected in selected:
            file = root / filename
            original = file.read_text()
            if original.count(before) != 1:
                raise RuntimeError(f"{name}: source site drift")
            file.touch()
            green = run(
                root,
                target,
                test,
                filename,
                test_timeout=60,
                test_args=("--include-ignored",),
            )
            if green.returncode or "1 passed; 0 failed; 0 ignored" not in green.stdout:
                raise RuntimeError(
                    (name, "invalid baseline", green.stdout, green.stderr)
                )
            try:
                file.write_text(original.replace(before, after, 1))
                red = run(
                    root,
                    target,
                    test,
                    filename,
                    test_timeout=60,
                    test_args=("--include-ignored",),
                )
                if (
                    red.returncode != 101
                    or f"test {test} ... FAILED" not in red.stdout
                    or expected not in red.stdout + red.stderr
                ):
                    raise RuntimeError(
                        (name, "survivor or wrong red", red.stdout, red.stderr)
                    )
                (evidence / f"{name}.log").write_text(red.stdout + red.stderr)
                print(f"{name}: GREEN baseline / RED intended", flush=True)
                completed += 1
            finally:
                file.write_text(original)
        if completed != len(selected):
            raise RuntimeError("wiring mutant inventory incomplete")
    print(f"wiring-mutants-complete:{completed}", flush=True)


if __name__ == "__main__":
    main()
