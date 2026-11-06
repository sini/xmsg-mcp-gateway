"""Drive custody source mutations through isolated real-node acceptance cells."""

import argparse
import shutil
import tempfile
from pathlib import Path

from grant_mutants import ROOT, run

SOURCE = (ROOT / "src/custody.rs").read_text()
metadata_write = next(
    line
    for line in SOURCE.splitlines()
    if 'tx.execute("INSERT OR IGNORE INTO custody_metadata' in line
)
CASES = [
    (
        "permanent-refusal-ack",
        "    fn can_ack(&self) -> bool {",
        "    fn can_ack(&self) -> bool {\n        if matches!(self, Self::Refused) { return false; }",
        "permanent_refusals_do_not_starve_valid_traffic",
        "oversized refusals exhausted node queue",
    ),
    (
        "mailbox-binding",
        "        let mailbox = service\n            .address()\n            .ok_or(xmsg::client::ClientError::Disconnected)?;",
        "        let mailbox = scope.bus_instance.as_str();",
        "mailbox_is_derived_from_the_registered_handle_not_configuration",
        "mailbox came from configuration instead of the registered handle",
    ),
    (
        "stored-body",
        "mailbox, owner, origin, delivery.text(),",
        'mailbox, owner, origin, "mutated stored body",',
        "commit_before_ack_preserves_the_original_event_across_restart",
        "stored body differs from the accepted delivery",
    ),
    (
        "early-ack",
        "    let accepted = store.accept_delivery(scope, service, &delivery, limits, now)?;",
        "    service.ack(delivery.message_id()).await?;\n    let accepted = store.accept_delivery(scope, service, &delivery, limits, now)?;",
        "failed_transaction_never_acknowledges_or_retains_partial_custody",
        "failed custody transaction ACKed upstream",
    ),
    (
        "quarantine-write",
        metadata_write,
        "",
        "conflict_is_quarantined_before_the_upstream_ack",
        "durable quarantine missing",
    ),
    (
        "content-expiry",
        "UPDATE custody_items SET text=NULL, envelope=NULL WHERE",
        "UPDATE custody_items SET text=text, envelope=envelope WHERE",
        "retention_redacts_content_without_rebinding_the_tombstone",
        "expired body retained",
    ),
    (
        "refusal-size",
        "let bounded_size = i64::try_from(size).map_err(|_| Error::Configuration)?;",
        "let bounded_size = 0;",
        "oversized_refusal_is_durable_content_free_before_ack",
        "actual bounded byte size missing",
    ),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=[case[0] for case in CASES])
    args = parser.parse_args()
    assert len(CASES) == 7, "custody mutant inventory drift"
    evidence = ROOT / ".artifacts/custody-mutants"
    evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gateway-custody-mutants-") as directory:
        root = Path(directory)
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copyfile(ROOT / name, root / name)
        for name in ("src", "tests", "ci"):
            shutil.copytree(ROOT / name, root / name, copy_function=shutil.copyfile)
        file = root / "src/custody.rs"
        completed = 0
        for name, old, new, test, expected in CASES:
            if args.case and args.case != name:
                continue
            assert SOURCE.count(old) == 1, name
            file.touch()
            green = run(
                root,
                "custody_inbound",
                test,
                "src/custody.rs",
                test_args=("--include-ignored",),
            )
            assert (
                green.returncode == 0
                and "1 passed; 0 failed; 0 ignored" in green.stdout
            ), (name, "invalid baseline", green.stdout, green.stderr)
            try:
                file.write_text(SOURCE.replace(old, new, 1))
                red = run(
                    root,
                    "custody_inbound",
                    test,
                    "src/custody.rs",
                    test_args=("--include-ignored",),
                )
                assert (
                    red.returncode == 101
                    and f"test {test} ... FAILED" in red.stdout
                    and expected in red.stdout + red.stderr
                ), (name, "intended cell did not kill mutant", red.stdout, red.stderr)
                (evidence / f"{name}.log").write_text(red.stdout + red.stderr)
                completed += 1
                print(f"{name}: GREEN baseline / RED intended", flush=True)
            finally:
                file.write_text(SOURCE)
        assert completed == (1 if args.case else 7)
    print(f"custody-mutants-complete:{completed}", flush=True)


if __name__ == "__main__":
    main()
