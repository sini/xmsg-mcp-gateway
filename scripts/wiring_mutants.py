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
        "tokio::spawn(work);",
        "work.await;",
        "cancelling_a_handler_does_not_cancel_the_accepted_operation",
        "detached dispatch did not commit before retry",
    ),
    (
        "rpc-id-is-not-request-id",
        "Ok(request) => request,",
        """Ok(mut request) => {
            let id = outbound::RequestId::parse(&id.to_string()).unwrap();
            match &mut request {
                outbound::Request::Send(args) => args.request_id = id,
                outbound::Request::Reply(args) => args.request_id = id,
            }
            request
        },""",
        MCP,
        "RPC id changed logical send",
    ),
    (
        "metadata-is-not-request-id",
        ARGUMENTS,
        """serde_json::from_value::<outbound::SendArguments>({
            let mut arguments = call.arguments;
            if arguments.get("request_id").is_none() {
                arguments["request_id"] = call._metadata.get("request_id").cloned().unwrap_or(Value::Null);
            }
            arguments
        })""",
        MCP,
        "request_id came from outside strict tool arguments",
    ),
    (
        "missing-id-is-not-stringified-rpc-id",
        ARGUMENTS,
        """serde_json::from_value::<outbound::SendArguments>({
            let mut arguments = call.arguments;
            if arguments.get("request_id").is_none() {
                arguments["request_id"] = json!(id.to_string());
            }
            arguments
        })""",
        MCP,
        "request_id came from outside strict tool arguments",
    ),
    (
        "default-empty-policy",
        "if !permission_enabled(&app, permission) {",
        "if false {",
        MCP,
        "empty policy reached dispatcher",
    ),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=[case[0] for case in CASES])
    args = parser.parse_args()
    selected = [case for case in CASES if not args.case or case[0] == args.case]
    evidence = ROOT / ".artifacts/wiring-mutants"
    evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gateway-wiring-mutants-") as directory:
        root = Path(directory)
        copy_fixture_tree(root)
        file = root / "src/serving.rs"
        original = file.read_text()
        completed = 0
        for name, before, after, test, expected in selected:
            if original.count(before) != 1:
                raise RuntimeError(f"{name}: source site drift")
            file.touch()
            green = run(
                root,
                "messaging",
                test,
                "src/serving.rs",
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
                    "messaging",
                    test,
                    "src/serving.rs",
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
