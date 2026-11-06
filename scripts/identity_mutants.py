"""Drive the public identity type boundary through named trybuild snapshots."""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from grant_mutants import ROOT, run

AUTH = ROOT / "src/auth.rs"
GRANTS = ROOT / "src/grants.rs"
source = AUTH.read_text()
start = source.index("pub struct VerifiedIdentity {")
end = source.index("\n}", start) + 2
identity = source[start:end]
grants = GRANTS.read_text()
start = grants.index("    pub fn authorize(")
authorize = grants[start : grants.rindex("\n}")]
unsafe_authorize = authorize.replace("&VerifiedIdentity", "&Binding")
for field in ("service", "issuer", "resource", "subject", "hosted_client"):
    unsafe_authorize = unsafe_authorize.replace(
        f"binding.{field}()", f"binding.{field}"
    )
unsafe_authorize = unsafe_authorize.replace("use crate::auth::VerifiedIdentity;", "")
CASES = [
    (
        "deserialize",
        "src/auth.rs",
        "#[derive(Debug)]\npub struct VerifiedIdentity",
        "#[derive(Debug, Deserialize)]\npub struct VerifiedIdentity",
        "identity_cannot_be_deserialized",
    ),
    (
        "default",
        "src/auth.rs",
        "#[derive(Debug)]\npub struct VerifiedIdentity",
        "#[derive(Debug, Default)]\npub struct VerifiedIdentity",
        "identity_has_no_default",
    ),
    (
        "public-fields",
        "src/auth.rs",
        identity,
        identity.replace("    ", "    pub "),
        "identity_fields_are_private",
    ),
    (
        "from-binding",
        "src/auth.rs",
        "impl VerifiedIdentity {",
        """impl From<crate::grants::Binding> for VerifiedIdentity {
    fn from(binding: crate::grants::Binding) -> Self {
        Self { service: binding.service, issuer: binding.issuer, resource: binding.resource,
            subject: binding.subject, hosted_client: binding.hosted_client, expires_at: u64::MAX }
    }
}
impl VerifiedIdentity {""",
        "identity_cannot_be_converted_from_binding",
    ),
    (
        "binding-authorizes",
        "src/grants.rs",
        authorize,
        unsafe_authorize,
        "enrollment_binding_cannot_authorize",
    ),
]


CASES.append(
    (
        "response-bound",
        "src/auth.rs",
        "const MAX_RESPONSE: u64 = 65_536;",
        "const MAX_RESPONSE: u64 = 1_048_576;",
        "oversized_provider_body_is_unavailable",
    )
)
CASES += [
    (
        "provider-https",
        "src/auth.rs",
        'url.scheme() != "https"',
        "false",
        "configuration_rejects_insecure_urls_and_unknown_fields",
    ),
    (
        "provider-allowlist",
        "src/auth.rs",
        "config.provider_addresses.is_empty()",
        "false",
        "configuration_rejects_insecure_urls_and_unknown_fields",
    ),
]
RUNTIME = [
    ("active", 'claims["active"] != true'),
    ("issuer", 'claims["iss"].as_str() != Some(&self.config.issuer)'),
    ("audience", '!exact_audience(&claims["aud"], &self.config.resource)'),
    ("subject", 'claims["sub"].as_str() != Some(&self.config.subject)'),
    (
        "hosted-client",
        'claims["client_id"].as_str() != Some(&self.config.hosted_client)',
    ),
    ("expired", "exp <= now"),
    ("not-before", "nbf > now"),
    ("scope", "actual == required"),
]
for name, guard in RUNTIME:
    CASES.append(
        (
            name,
            "src/auth.rs",
            guard,
            "true" if name == "scope" else "false",
            "only_the_configured_provider_can_verify_the_token",
        )
    )


def main():
    assert os.environ.get("TRYBUILD") != "overwrite", (
        "snapshot rewriting is not verification"
    )
    version = subprocess.check_output(["rustc", "--version"], text=True)
    assert version.startswith("rustc 1.95.0 "), version
    evidence = ROOT / ".artifacts/identity-mutants"
    evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gateway-identity-mutants-") as directory:
        root = Path(directory)
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copyfile(ROOT / name, root / name)
        for name in ("src", "tests"):
            shutil.copytree(ROOT / name, root / name)
        for name, filename, old, new, test in CASES:
            file = root / filename
            original = file.read_text()
            assert original.count(old) == 1, name
            file.touch()
            target = (
                "identity"
                if name
                in {row[0] for row in RUNTIME}
                | {"response-bound", "provider-https", "provider-allowlist"}
                else "identity_types"
            )
            green = run(root, target, test, filename)
            assert (
                green.returncode == 0
                and "1 passed; 0 failed; 0 ignored" in green.stdout
            ), (name, "invalid baseline", green.stdout, green.stderr)
            try:
                file.write_text(original.replace(old, new, 1))
                red = run(root, target, test, filename)
                assert (
                    red.returncode == 101 and f"test {test} ... FAILED" in red.stdout
                ), (name, "wrong red", red.stdout, red.stderr)
                if target == "identity_types":
                    assert (
                        "Expected test case to fail to compile, but it succeeded."
                        in red.stderr
                    ), (name, "unrelated snapshot failure", red.stderr)
                else:
                    assert (
                        "accepted " in red.stdout
                        or "oversized_provider_body_is_unavailable" in red.stdout
                    ), (
                        name,
                        "unrelated runtime failure",
                        red.stdout,
                    )
                (evidence / f"{name}.log").write_text(red.stdout + red.stderr)
                print(
                    f"{name}: GREEN baseline, RED intended identity test",
                    flush=True,
                )
            finally:
                file.write_text(original)
                file.touch()
    print(f"{len(CASES)}/{len(CASES)} identity mutants killed", flush=True)


if __name__ == "__main__":
    main()
