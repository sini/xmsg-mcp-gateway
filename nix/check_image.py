#!/usr/bin/env python3
"""Structural oracle check for the xmsg-mcp-gateway OCI image.

Asserts:
1. User is non-root (not empty, 0, root, 0:0, root:root, or 0:/root: prefixed).
2. Entrypoint is a 1-element list pointing to .../bin/xmsg-mcp-gateway.
3. The gateway binary is physically present in the image layers as an executable ELF binary (not a script or missing path).
4. No Python interpreter, libpython, .py/.pyc files, phase1 package, or shell (/bin/sh) exists in any layer.
"""

import io
import json
import os
import posixpath
import sys
import tarfile

FORBIDDEN_BINARIES = {
    "python",
    "python2",
    "python3",
    "pypy",
    "pypy3",
    "uv",
    "pip",
    "pip3",
    "sh",
    "bash",
    "dash",
    "zsh",
}

FORBIDDEN_FILES = {
    "pyproject.toml",
    "uv.lock",
}


def is_forbidden_member(member: tarfile.TarInfo, norm_path: str) -> str | None:
    parts = [p for p in norm_path.split("/") if p]
    if not parts:
        return None
    base = parts[-1]
    lower_base = base.lower()

    for seg in parts:
        low = seg.lower()
        if low == "phase1":
            return f"phase1 package path segment {seg!r}"
        if "-python3-" in low or "-python-" in low or low.endswith(("-python3", "-python")):
            return f"python store package {seg!r}"

    if not member.isdir():
        if lower_base in FORBIDDEN_BINARIES:
            return f"forbidden interpreter/shell {base!r}"
        if lower_base in FORBIDDEN_FILES:
            return f"forbidden python project file {base!r}"
        if (
            lower_base.startswith(("python2.", "python3.", "libpython"))
            or lower_base.endswith((".pyc", ".pyo", ".whl"))
        ):
            return f"python runtime artifact {base!r}"
        if norm_path in ("bin/sh", "usr/bin/sh") or norm_path.endswith("/bin/sh"):
            return "shell /bin/sh"
    return None


def check_image(image_tar_path: str) -> None:
    if not os.path.exists(image_tar_path):
        print(f"Error: image tarball not found at {image_tar_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[oracle] Loading image tarball from: {image_tar_path}")
    with tarfile.open(image_tar_path, "r:*") as outer_tar:
        try:
            manifest_member = outer_tar.getmember("manifest.json")
        except KeyError:
            print("Error: manifest.json not found in image tarball", file=sys.stderr)
            sys.exit(1)

        manifest_f = outer_tar.extractfile(manifest_member)
        assert manifest_f is not None
        manifest = json.load(manifest_f)
        if not manifest:
            print("Error: manifest.json is empty", file=sys.stderr)
            sys.exit(1)

        image_meta = manifest[0]
        config_filename = image_meta.get("Config")
        if not config_filename:
            print("Error: No Config found in manifest.json", file=sys.stderr)
            sys.exit(1)

        config_f = outer_tar.extractfile(outer_tar.getmember(config_filename))
        assert config_f is not None
        config_data = json.load(config_f)
        cfg = config_data.get("config", {})

        # Assertion 1: User is non-root
        user = cfg.get("User", "")
        print(f"[oracle] Checking User configuration: {user!r}")
        root_users = {"0", "root", "0:0", "root:root"}
        if (
            not isinstance(user, str)
            or not user.strip()
            or user in root_users
            or user.startswith(("0:", "root:"))
            or user.endswith((":0", ":root"))
        ):
            print(
                f"[FAIL] Oracle check: User must be non-root, got: {user!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"[oracle] -> User is non-root: {user}")

        # Assertion 2: Entrypoint is the xmsg-mcp-gateway binary
        entrypoint = cfg.get("Entrypoint", [])
        print(f"[oracle] Checking Entrypoint configuration: {entrypoint!r}")
        if (
            not isinstance(entrypoint, list)
            or len(entrypoint) != 1
            or not isinstance(entrypoint[0], str)
            or not entrypoint[0].startswith("/")
            or not entrypoint[0].endswith("/bin/xmsg-mcp-gateway")
        ):
            print(
                f"[FAIL] Oracle check: Entrypoint must be ['.../bin/xmsg-mcp-gateway'], got: {entrypoint!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        expected_rel = posixpath.normpath(entrypoint[0].lstrip("/"))
        print(f"[oracle] -> Entrypoint is gateway binary: {entrypoint[0]}")

        # Assertion 3 & 4: Gateway ELF binary present in layers; no Python/phase1/shell in any layer
        layers = image_meta.get("Layers", [])
        if not layers:
            print("[FAIL] Oracle check: Image contains zero layers", file=sys.stderr)
            sys.exit(1)
        print(
            f"[oracle] Scanning {len(layers)} image layer(s) for gateway binary and forbidden Python/shell content..."
        )

        found_gateway_elf = False
        forbidden_hits: list[tuple[str, str, str]] = []

        for layer_name in layers:
            layer_f = outer_tar.extractfile(outer_tar.getmember(layer_name))
            assert layer_f is not None
            layer_bytes = layer_f.read()
            with tarfile.open(fileobj=io.BytesIO(layer_bytes)) as layer_tar:
                for member in layer_tar.getmembers():
                    norm = posixpath.normpath(member.name.lstrip("./"))
                    if norm in ("", "."):
                        continue
                    reason = is_forbidden_member(member, norm)
                    if reason is not None:
                        forbidden_hits.append((layer_name, member.name, reason))
                    if norm == expected_rel:
                        if not member.isfile():
                            print(
                                f"[FAIL] Oracle check: Entrypoint {expected_rel!r} is not a regular file",
                                file=sys.stderr,
                            )
                            sys.exit(1)
                        if (member.mode & 0o111) == 0:
                            print(
                                f"[FAIL] Oracle check: Entrypoint {expected_rel!r} is not executable (mode={oct(member.mode)})",
                                file=sys.stderr,
                            )
                            sys.exit(1)
                        bin_f = layer_tar.extractfile(member)
                        assert bin_f is not None
                        magic = bin_f.read(4)
                        if magic != b"\x7fELF":
                            print(
                                f"[FAIL] Oracle check: Entrypoint {expected_rel!r} is not an ELF binary (magic={magic!r})",
                                file=sys.stderr,
                            )
                            sys.exit(1)
                        found_gateway_elf = True

        if not found_gateway_elf:
            print(
                f"[FAIL] Oracle check: Entrypoint binary {expected_rel!r} not found in any image layer",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"[oracle] -> Verified ELF executable present at /{expected_rel}")

        if forbidden_hits:
            print(
                f"[FAIL] Oracle check: Forbidden Python/phase1/shell artifacts detected in image: {forbidden_hits!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        print("[oracle] -> No Python interpreter, phase1 files, or /bin/sh found in any layer.")

    print(
        "[oracle] ALL ORACLES PASSED: Non-root user, xmsg-mcp-gateway ELF entrypoint present, no Python/shell."
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path_to_image_tar_gz>", file=sys.stderr)
        sys.exit(1)
    check_image(sys.argv[1])
