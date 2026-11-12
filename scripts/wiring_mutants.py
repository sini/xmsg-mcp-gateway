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
        "tasks.spawn(work);",
        "work.await;",
        "messaging",
        "cancelling_a_handler_does_not_cancel_the_accepted_operation",
        "detached dispatch did not commit before retry",
    ),
    (
        "rpc-id-is-not-request-id",
        "src/serving.rs",
        """let request = match request {
                    Ok(request) => request,
                    Err(_) => return invalid_dispatch(operation, &id, "Invalid params"),
                };
                return messaging_call(app, context, id, request, policy, store, progress).await;""",
        """let request = match request {
                    Ok(mut request) => {
                        let request_id = outbound::RequestId::parse(&id.to_string()).unwrap();
                        match &mut request {
                            outbound::Request::Send(args) => args.request_id = request_id,
                            outbound::Request::Reply(args) => args.request_id = request_id,
                        }
                        request
                    },
                    Err(_) => return invalid_dispatch(operation, &id, "Invalid params"),
                };
                return messaging_call(app, context, id, request, policy, store, progress).await;""",
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
        "if !permission_enabled(&app, context.identity(), permission) {",
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
            "src/session.rs",
            f"registered.{getter}()",
            f"Some(manifest.{field})",
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
            "store\n                .require_retirement_ready()",
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
            "if !permission_enabled(app, identity, permission)",
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
            "app.verifier\n            .requires_scope_for(identity, &permission.required_scope)",
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
        """Some(pending) => {
            diagnostic::emit(pending.operation, "pending", "request_deadline");
            pending_response(pending)
        }""",
        """Some(pending) => {
            diagnostic::emit(pending.operation, "pending", "request_deadline");
            unavailable()
        }""",
        "messaging",
        "handler_deadline_reports_pending_without_cancelling_accepted_work",
        "handler deadline hid its pending request",
    )
)

CASES.append(
    (
        "startup-reported-body-bound",
        "src/session.rs",
        "registered.max_body_bytes(),",
        "Some(65536),",
        "messaging",
        "reported_body_bound_refuses_an_oversized_deployment_manifest",
        "configured bound above the effective node body limit reached the router",
    )
)

CASES.extend(
    [
        (
            "runtime-reregistration",
            "src/session.rs",
            "let registered = register(&config, &manifest).await?;",
            "let registered = Err::<RegisteredService, Error>(Error::Identity)?;",
            "messaging",
            "serving_recovers_after_a_real_daemon_restart_without_consuming_mail",
            "serving failed to recover its registration",
        ),
        (
            "fresh-registration-limits",
            "src/session.rs",
            "let registered = register(&config, &manifest).await?;",
            "let registered = config.register().await.map_err(Error::Registration)?;",
            "messaging",
            "reconnect_rechecks_changed_limits_and_records_the_link_before_readiness",
            "changed node limits were published as ready",
        ),
        (
            "durable-reconnect-before-publication",
            "src/session.rs",
            "record_link(file.clone(), snapshot.bus.clone(), true, custody_limits.clone()).await?",
            "tokio::time::Instant::now()",
            "messaging",
            "reconnect_publication_waits_for_a_durable_ledger_commit",
            "replacement published before durable reconnect",
        ),
        (
            "in-flight-snapshot-publication",
            "src/session.rs",
            "publish.send_replace(State::Ready(snapshot));",
            "",
            "messaging",
            "an_accepted_operation_across_restart_recovers_its_original_receipt_and_key",
            "in-flight operation did not recover its receipt",
        ),
    ]
)


CASES.append(
    (
        "scoped-trace-observation",
        "tests/common/serving_fixture.rs",
        "tracing::subscriber::set_global_default(\n                tracing::subscriber::NoSubscriber::default(),\n            )",
        "Ok::<(), ()>(())",
        "messaging",
        "ordered_store_open_without_a_dispatcher_preserves_scoped_request_counts",
        "ordered no-dispatcher open hid scoped request store opens",
    )
)



CASES.extend([
    ("retryable-unknown", "src/serving.rs", '"reconciliation_required":false', '"reconciliation_required":true',
     "messaging", "an_accepted_operation_across_restart_recovers_its_original_receipt_and_key",
     "within-lifetime uncertainty must permit same-key retry"),
    ("expired-unknown", "src/serving.rs", 'tool_result(json!({"state":"unknown",\n            "request_id":request_id,"reconciliation_required":true}))', 'tool_result(json!({"state":"unknown",\n            "request_id":request_id,"reconciliation_required":false}))',
     "messaging", "expired_mcp_uncertainty_requires_reconciliation_without_resubmission",
     "expired uncertainty must require reconciliation"),
    ("same-tick-health", "src/session.rs", "match snapshot.endpoint.health() {", "match Ok::<(), ClientError>(()) {",
     "messaging", "a_request_after_daemon_death_within_the_same_tick_refuses_the_old_snapshot",
     "dead registration retained its ready snapshot"),
    ("healthy-write-coalescing", "src/session.rs", "if observed_at.elapsed() >= observation_interval {", "if true {",
     "messaging", "healthy_observations_do_not_disrupt_ninety_sends_in_three_rounds", "healthy "),
    ("observation-ceiling", "src/session.rs", ".min(Duration::from_secs(60))", "",
     "messaging", "healthy_observation_is_persisted_at_the_sixty_second_ceiling",
     "healthy observation exceeded the sixty-second ceiling"),
    ("graceful-observation", "src/session.rs", "if healthy {", "if false {",
     "messaging", "sigterm_drains_and_persists_the_final_healthy_observation",
     "graceful shutdown did not persist its final observation"),
])


CASES.append((
    "store-open-event", "src/grants.rs", 'tracing::debug!(target: "gateway_policy_store", "open");', ";",
    "messaging", "coalesced_background_observation_preserves_request_store_open_counts",
    "background observation hid request store opens",
))

CASES.append(
    (
        "read-response-id",
        "src/serving.rs",
        "Ok(Ok(data)) => rpc_result(&id, tool_result(data)),\n                    Ok(Err(reads::Error::Arguments)) => {",
        'Ok(Ok(data)) => rpc_result(&json!("wrong-read-response-id"), tool_result(data)),\n                    Ok(Err(reads::Error::Arguments)) => {',
        "reads",
        "reads_are_advertised_only_with_a_registered_mailbox",
        "read responses changed their JSON-RPC request IDs",
    )
)


CASES.append((
    "broker-expired-unknown", "src/serving.rs",
    'Outcome::ExpiredUnknown => return Ok(json!({"state":"unknown","request_id":request_id,"reconciliation_required":true}))',
    'Outcome::ExpiredUnknown => return Ok(json!({"state":"unknown","request_id":request_id,"reconciliation_required":false}))',
    "broker_bridge", "expired_broker_uncertainty_requires_reconciliation_without_retry_advice",
    "expired broker uncertainty must require reconciliation",
))

def main():
    if len(CASES) != 38:
        raise RuntimeError("wiring mutant inventory drift")
    for name, filename, before, *_ in CASES:
        if (ROOT / filename).read_text().count(before) != 1:
            raise RuntimeError(f"{name}: source site drift")
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
                application=name == "graceful-observation",
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
                application=name == "graceful-observation",
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
