"""Compile isolated recovery source mutants; compiler failures never count as kills.

Run from an immutable committed checkout. Supply --evidence in an ignored or external directory,
optionally --seed-target for a dependency-only build cache copied privately per case.
RUSTC, CARGO and CC may select the pinned toolchain. Local Cargo builds use a
12 GiB systemd scope; GitHub hosted CI uses its bounded runner without a user
systemd session. This script invokes no Nix commands or production runtime switches.
"""

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "grants::recovery_tests::"
HOT = "sigkill_hot_journal_recovers_once_with_exact_private_forensics"
MUTANTS = [
    ("readonly-to-writable", "src/grants.rs",
     "Connection::open_with_flags(file, OpenFlags::SQLITE_OPEN_READ_ONLY)?;",
     "Connection::open_with_flags(file, OpenFlags::SQLITE_OPEN_READ_WRITE)?;",
     "ordinary_readonly_open_preserves_bytes_mtime_and_directory"),
    ("disable-776-recovery", "src/grants.rs",
     "if error.extended_code == rusqlite::ffi::SQLITE_READONLY_ROLLBACK =>",
     "if error.extended_code == -1 =>", HOT),
    ("recover-before-readonly", "src/grants.rs",
     "        match Self::open_readonly_once(file) {",
     '''        let journal = std::path::PathBuf::from(format!("{}-journal", file.display()));
        if std::fs::metadata(journal).is_ok_and(|meta| meta.len() > 0) {
            recovery::recover(file)?;
        }
        match Self::open_readonly_once(file) {''',
     "live_writer_nonhot_journal_returns_committed_readonly_view"),
    ("skip-preservation", "src/grants_recovery.rs",
     "if !preserve(&file, &journal)? {", "if false {", HOT),
    ("ignore-magic-after-preservation", "src/grants_recovery.rs",
     "if !preserve(&file, &journal)? {",
     "if { let _ = preserve(&file, &journal)?; false } {",
     "garbage_journal_fails_closed_with_exact_forensics_and_no_source_changes"),
    ("ignore-preservation-failure", "src/grants_recovery.rs",
     "if !preserve(&file, &journal)? {",
     "if !preserve(&file, &journal).unwrap_or(true) {",
     "backup_directory_failure_fails_closed_without_recovering"),
    ("wrong-directory-mode", "src/grants_recovery.rs",
     "if metadata.mode() & 0o777 != 0o700 || metadata.uid() != source.uid() {",
     "if false && (metadata.mode() & 0o777 != 0o700 || metadata.uid() != source.uid()) {",
     "preexisting_permissive_recovery_directory_fails_closed"),
    ("ignore-quick-check-result", "src/grants_recovery.rs",
     'if results != ["ok"] {', 'if false && results != ["ok"] {',
     "quick_check_failure_returns_error_after_one_preserved_recovery"),
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(command, cwd, output, timeout=1800):
    result = subprocess.run(command, cwd=cwd, capture_output=True, timeout=timeout)
    output.write_bytes(result.stdout + result.stderr)
    return result


def snapshot(destination, revision):
    archive = subprocess.check_output(["git", "archive", revision], cwd=ROOT)
    subprocess.run(["tar", "-xf", "-"], input=archive, cwd=destination, check=True)


def build(root, target, evidence, label):
    nonce = uuid.uuid4().hex
    source = root / "src/grants_recovery.rs"
    original = source.read_bytes()
    if original.count(b"pub(super) fn recover(file: &Path) -> Result<(), Error> {") != 1:
        raise RuntimeError("nonce instrumentation site must be unique")
    instrumented = original.replace(
        b"pub(super) fn recover(file: &Path) -> Result<(), Error> {",
        b"pub(super) fn recover(file: &Path) -> Result<(), Error> {\n    std::hint::black_box(&RECOVERY_MUTANT_BUILD_NONCE);",
    )
    if instrumented == original:
        raise RuntimeError("missing nonce instrumentation site")
    source.write_bytes(instrumented + f'\nstatic RECOVERY_MUTANT_BUILD_NONCE: [u8; 32] = *b"{nonce}";\n'.encode())
    source_hashes = {str(p.relative_to(root)): sha(p.read_bytes()) for p in sorted((root / "src").rglob("*.rs"))}
    cap = [] if os.environ.get("GITHUB_ACTIONS") == "true" else [
        "systemd-run", "--user", "--scope", "-q", "-p", "MemoryMax=12G"
    ]
    command = [*cap, os.environ.get("CARGO", "cargo"), "test", "--locked", "--lib", "--no-run",
               "--message-format=json", "--jobs", "4", "--target-dir", str(target)]
    result = run(command, root, evidence / f"{label}-build.log")
    if result.returncode:
        raise RuntimeError(f"{label}: build exit {result.returncode}; not a mutant kill")
    artifacts = []
    for line in result.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (item.get("reason") == "compiler-artifact" and item.get("executable")
                and item.get("profile", {}).get("test") and "lib" in item.get("target", {}).get("kind", [])):
            artifacts.append(item)
    if len(artifacts) != 1 or artifacts[0].get("fresh") is not False:
        raise RuntimeError(f"{label}: expected one freshly compiled libtest artifact")
    artifact = Path(artifacts[0]["executable"]).resolve()
    artifact.relative_to(target.resolve())
    if nonce.encode() not in artifact.read_bytes():
        raise RuntimeError(f"{label}: compiled artifact does not contain source nonce")
    record = {"nonce": nonce, "sources_sha256": source_hashes,
              "executable": str(artifact), "executable_sha256": sha(artifact.read_bytes()),
              "fresh": False, "build_exit": result.returncode, "command": command}
    (evidence / f"{label}-artifact.json").write_text(json.dumps(record, indent=2) + "\n")
    source.write_bytes(original)
    return artifact


def tests(artifact, root, evidence, label, test=None):
    command = [str(artifact), PREFIX + test if test else PREFIX, "--nocapture", "--test-threads=1"]
    if test:
        command.append("--exact")
    result = run(command, root, evidence / f"{label}-test.log", timeout=180)
    output = result.stdout.decode(errors="replace")
    if test:
        expected = f"test {PREFIX}{test} ... FAILED"
        if result.returncode != 101 or expected not in output or "1 failed" not in output:
            raise RuntimeError(f"{label}: intended test must fail with exit 101")
    elif result.returncode != 0 or "10 passed; 0 failed" not in output:
        raise RuntimeError(f"{label}: restoration must pass all ten recovery tests")
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--seed-target", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT):
        raise RuntimeError("tracked checkout must be clean and committed")
    subprocess.run(["git", "ls-files", "--error-unmatch", "scripts/store_recovery_mutants.py"],
                   cwd=ROOT, stdout=subprocess.DEVNULL, check=True)
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    (evidence / "revision.txt").write_text(head + "\n")
    summary = []
    for name, filename, old, new, test in MUTANTS:
        case = evidence / name
        case.mkdir(mode=0o700)
        with tempfile.TemporaryDirectory(prefix="nqcx-mutant-") as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            snapshot(root, head)
            target = Path(temporary) / "target"
            if args.seed_target:
                subprocess.run(["cp", "-a", "--reflink=auto", str(args.seed_target.resolve()), str(target)], check=True)
            source = root / filename
            before = source.read_text()
            count = before.count(old)
            if count != 1:
                raise RuntimeError(f"{name}: site count {count}, expected exactly one")
            baseline = build(root, target, case, "baseline")
            tests(baseline, root, case, "baseline")
            after = before.replace(old, new)
            source.write_text(after)
            (case / "source.patch").write_text("".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile="a/" + filename, tofile="b/" + filename)))
            mutant = build(root, target, case, "mutant")
            red = tests(mutant, root, case, "mutant", test)
            source.write_text(before)
            restored = build(root, target, case, "restored")
            green = tests(restored, root, case, "restored")
            summary.append({"mutant": name, "site_count": count, "test": PREFIX + test,
                            "red_exit": red, "restored_exit": green, "restored_passed": 10})
            (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
            print(f"{name}: intended RED 101; restored 10 GREEN", flush=True)
    print(f"store-recovery-mutants-complete:{len(summary)}/{len(MUTANTS)}")


if __name__ == "__main__":
    main()
