"""Select complete mutation suites and verify actual execution receipts."""

import argparse
import fnmatch
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = "ci/mutation-suites.json"
SHARED = [
    ".github/workflows/**",
    "ci/mutation-*",
    "scripts/**",
    "Cargo.*",
    "rust-toolchain.toml",
    "pyproject.toml",
    "uv.lock",
    "ci/*pin.toml",
    "src/lib.rs",
    "src/main.rs",
    "src/client.rs",
    "src/grants.rs",
    "src/session.rs",
    "src/custody.rs",
    "src/outbound.rs",
    "src/deadline.rs",
    "src/retirement.rs",
    "tests/common/**",
    "tests/test_mutation_gates.py",
    "tests/test_header_timeout_mutant_runner.py",
    "src/auth.rs",
    "src/outbound_lease.rs",
    "src/xmsg_config.rs",
]
ORDINARY = [
    "docs/**",
    "LICENSE*",
    ".gitignore",
    ".gitattributes",
    "ci/ordinary-counts.json",
]


def load_registry(root=ROOT):
    value = json.loads((root / REGISTRY).read_text())
    if value.get("version") != 1:
        raise ValueError("unknown mutation registry version")
    suites = value["suites"]
    ids = [s["id"] for s in suites]
    if len(ids) != len(set(ids)) or len(suites) != 21:
        raise ValueError("mutation suite inventory drift")
    registered = {s["script"] for s in suites}
    discovered = {
        str(p.relative_to(root)) for p in (root / "scripts").glob("*_mutants.py")
    } | {"scripts/mutations.py"}
    if registered != discovered:
        raise ValueError("unregistered mutation script")
    modes = {(s["script"], tuple(s["args"])) for s in suites}
    required = {
        ("scripts/reservation_lifetime_mutants.py", ()),
        ("scripts/reservation_lifetime_mutants.py", ("--live",)),
    }
    if not required <= modes or len(modes) != len(suites):
        raise ValueError("mutation execution mode drift")
    if (
        sum(s["count"] for s in suites if not s["python"]) != 303
        or sum(s["count"] for s in suites if s["python"]) != 13
    ):
        raise ValueError("mutation case inventory drift")
    for suite in suites:
        if (
            not suite["dependencies"]
            or suite["count"] <= 0
            or len(suite["labels"]) != suite["count"]
            or len(set(suite["labels"])) != suite["count"]
        ):
            raise ValueError("incomplete mutation classification")
        if digest(root / suite["script"]) != suite["script_sha256"]:
            raise ValueError("mutation script inventory changed; review registry")
    return suites


def matches(filename, patterns):
    return any(fnmatch.fnmatchcase(filename, pattern) for pattern in patterns)


def select(suites, changed, *, full=False):
    if full or any(matches(p, SHARED) for p in changed):
        return [s["id"] for s in suites]
    selected = set()
    for filename in changed:
        affected = [s["id"] for s in suites if matches(filename, s["dependencies"])]
        if affected:
            selected.update(affected)
        elif not (
            matches(filename, ORDINARY)
            or ("/" not in filename and filename.endswith(".md"))
        ):
            return [s["id"] for s in suites]
    return [s["id"] for s in suites if s["id"] in selected]


def event_requires_full(event_name, event):
    if event_name != "pull_request":
        return True
    try:
        labels = event["pull_request"]["labels"]
        if not isinstance(labels, list) or any(
            not isinstance(label["name"], str) for label in labels
        ):
            return True
        return any(label["name"] == "full-gates" for label in labels)
    except (KeyError, TypeError):
        return True


def digest(filename):
    return hashlib.sha256(filename.read_bytes()).hexdigest()


def validate_output(suite, output):
    for pattern in suite["required_output"]:
        if len(re.findall(pattern, output, re.MULTILINE)) != 1:
            raise ValueError("missing or ambiguous named mutant execution")
    if suite["completion"]:
        if output.splitlines().count(suite["completion"]) != 1:
            raise ValueError("missing or ambiguous suite completion")
    else:
        arms = [
            json.loads(line)
            for line in output.splitlines()
            if line.startswith('{"arm":')
        ]
        expected = {"control", *suite["labels"]}
        if len(arms) != len(expected) or {a["arm"] for a in arms} != expected:
            raise ValueError("missing header mutation arm")
        for arm in arms:
            if (
                not arm["nonce"]
                or not arm["source_sha256"]
                or not arm["artifacts"]
                or not arm["results"]
            ):
                raise ValueError("incomplete header mutation evidence")
            if len(arm["results"]) != len(suite["arm_tests"][arm["arm"]]) or {
                r["test"] for r in arm["results"]
            } != set(suite["arm_tests"][arm["arm"]]):
                raise ValueError("missing header named test")
            for result in arm["results"]:
                if result["verdict"] not in (
                    {"green"}
                    if arm["arm"] == "control"
                    else {"red", "killed by timeout"}
                ):
                    raise ValueError("incorrect header mutation outcome")
                if result["verdict"] == "green" and result["status"] != 0:
                    raise ValueError("failed header control")
                if result["verdict"] == "red" and result["status"] in (None, 0):
                    raise ValueError("header mutant survived")
                if result["verdict"] == "killed by timeout" and (
                    arm["arm"] != "uninterruptible-backoff"
                    or result["baseline_duration_seconds"]
                    >= result["budget_seconds"] / 2
                ):
                    raise ValueError("invalid hang-class timeout kill")


def verify(plan, receipts, suites, root=ROOT):
    known = {s["id"]: s for s in suites}
    selected = plan["selected"]
    if len(selected) != len(set(selected)) or any(s not in known for s in selected):
        raise ValueError("unknown or duplicate selected suite")
    if plan["full"] and set(selected) != set(known):
        raise ValueError("full run omitted mutation suites")
    if selected != select(suites, plan["changed"], full=plan["full"]):
        raise ValueError("selection receipt omitted classified suites")
    if len(receipts) != len(selected) or {r["suite"] for r in receipts} != set(
        selected
    ):
        raise ValueError("missing, duplicate or unexpected suite receipt")
    for receipt in receipts:
        suite = known[receipt["suite"]]
        if (
            receipt["exit"] != 0
            or receipt["count"] != suite["count"]
            or receipt["registry_sha256"] != digest(root / REGISTRY)
            or receipt["revision"] != plan["revision"]
        ):
            raise ValueError("suite receipt provenance mismatch")
        log = root / receipt["log"]
        if digest(log) != receipt["log_sha256"]:
            raise ValueError("suite execution log changed")
        validate_output(suite, log.read_text())
    return sum(known[s]["count"] for s in selected)


def tee_command(command, log, console=None):
    """Keep live progress and the hashed execution log byte-identical."""
    console = sys.stdout.buffer if console is None else console
    child = subprocess.Popen(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    previous_term = signal.getsignal(signal.SIGTERM)

    def interrupted(_signum, _frame):
        raise InterruptedError("mutation suite interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    try:
        with log.open("wb") as output, child.stdout:
            while chunk := child.stdout.read1(65536):
                output.write(chunk)
                output.flush()
                console.write(chunk)
                console.flush()
        return child.wait()
    except BaseException:
        # This process group contains only the child launched above and its descendants.
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=3)
        raise
    finally:
        signal.signal(signal.SIGTERM, previous_term)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    selection = commands.add_parser("select")
    selection.add_argument("--event", required=True)
    selection.add_argument("--base")
    selection.add_argument("--head", required=True)
    selection.add_argument("--output", type=Path, required=True)
    run = commands.add_parser("run")
    run.add_argument("suite")
    run.add_argument("--output", type=Path, required=True)
    check = commands.add_parser("verify")
    check.add_argument("--plan", type=Path, required=True)
    check.add_argument("--receipts", type=Path, required=True)
    options = parser.parse_args()
    suites = load_registry()
    if options.command == "select":
        try:
            event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        except (OSError, ValueError, KeyError):
            event = {}
        full = event_requires_full(options.event, event)
        try:
            changed = (
                subprocess.check_output(
                    [
                        "git",
                        "diff",
                        "--name-only",
                        "-z",
                        "--no-renames",
                        options.base,
                        options.head,
                    ],
                    text=True,
                    cwd=ROOT,
                )
                .rstrip("\0")
                .split("\0")
                if not full
                else []
            )
        except (subprocess.CalledProcessError, TypeError):
            full, changed = True, []
        changed = [filename for filename in changed if filename]
        selected = select(suites, changed, full=full)
        full = full or set(selected) == {s["id"] for s in suites}
        plan = {
            "revision": options.head,
            "full": full,
            "selected": selected,
            "changed": changed,
        }
        options.output.parent.mkdir(parents=True, exist_ok=True)
        options.output.write_text(json.dumps(plan, indent=2) + "\n")
        matrix = {
            "include": [
                {"suite": s["id"], "fixture": s["fixture"], "python": s["python"]}
                for s in suites
                if s["id"] in selected
            ]
        }
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
            output.write(f"matrix={json.dumps(matrix)}\nselected={len(selected)}\n")
    elif options.command == "run":
        suite = next(s for s in suites if s["id"] == options.suite)
        options.output = (ROOT / options.output).resolve()
        options.output.relative_to(ROOT)
        options.output.mkdir(parents=True, exist_ok=True)
        log = options.output / f"{suite['id']}.log"
        status = tee_command([sys.executable, suite["script"], *suite["args"]], log)
        if status:
            raise SystemExit(status)
        validate_output(suite, log.read_text())
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, cwd=ROOT
        ).strip()
        receipt = {
            "suite": suite["id"],
            "count": suite["count"],
            "exit": 0,
            "revision": revision,
            "registry_sha256": digest(ROOT / REGISTRY),
            "log": str(log.relative_to(ROOT)),
            "log_sha256": digest(log),
        }
        (options.output / f"{suite['id']}.json").write_text(
            json.dumps(receipt, indent=2) + "\n"
        )
        print(f"mutation-suite-complete:{suite['id']}:{suite['count']}")
    else:
        plan = json.loads(options.plan.read_text())
        receipts = [json.loads(p.read_text()) for p in options.receipts.glob("*.json")]
        total = verify(plan, receipts, suites)
        print(f"mutation-gates-complete:{len(receipts)} suites:{total} mutants")


if __name__ == "__main__":
    main()
