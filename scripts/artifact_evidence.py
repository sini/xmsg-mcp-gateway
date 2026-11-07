"""Identify each rebuilt executable and reject reuse across source variants."""

import hashlib
import uuid

NONCE = uuid.uuid4().hex
SEEN = {}


def record(root, executable, label, *, directories=("src", "tests")):
    source = hashlib.sha256()
    for directory in directories:
        for file in sorted((root / directory).rglob("*.rs")):
            source.update(str(file.relative_to(root)).encode())
            source.update(file.read_bytes())
    variant = source.hexdigest()
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    previous = SEEN.setdefault(digest, variant)
    if previous != variant:
        raise RuntimeError("different source variants reused a test-executable hash")
    print(
        f"artifact nonce={NONCE} arm={label} path={executable} "
        f"mtime_ns={executable.stat().st_mtime_ns} sha256={digest} source={variant}",
        flush=True,
    )
