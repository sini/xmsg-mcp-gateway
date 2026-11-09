"""Drive the public identity type boundary through named trybuild snapshots."""

import os
import shutil
import subprocess
import tempfile
import time
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
unsafe_authorize = """    pub fn authorize<T>(&self, _binding: &T) -> Result<Authorization, Error> {
        Ok(Authorization { grant_id: "unverified".into(), revision: 1 })
    }"""
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
        "if !config.provider_addresses.is_empty()",
        "if false",
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

CASES += [
    (
        "provider-ip-literal",
        "src/auth.rs",
        "if !config.provider_addresses.contains(&ip)",
        "if false",
        "configuration_rejects_insecure_urls_and_unknown_fields",
    ),
    (
        "provider-redirect",
        "src/auth.rs",
        "reqwest::redirect::Policy::none()",
        "reqwest::redirect::Policy::limited(3)",
        "redirects_never_reach_an_active_token_provider",
    ),
    (
        "provider-timeout",
        "src/auth.rs",
        ".timeout(Duration::from_millis(config.timeout_ms))",
        "",
        "stalled_provider_is_refused_before_its_response",
    ),
    (
        "provider-pin-mismatch",
        "src/auth.rs",
        "builder = builder.no_proxy().resolve_to_addrs(host, &addresses);",
        "builder = builder.no_proxy();",
        "configuration_rejects_insecure_urls_and_unknown_fields",
    ),
    (
        "provider-unpinned-proxy",
        "src/auth.rs",
        "let mut builder = Client::builder()\n            .https_only(true)",
        "let mut builder = Client::builder()\n            .https_only(true)\n            .no_proxy()",
        "configuration_rejects_insecure_urls_and_unknown_fields",
    ),
]
TYPE_TESTS = {case[4] for case in CASES[:5]}
EXPECTED_RED = {
    "response-bound": "oversized provider body accepted",
    "provider-https": "accepted config introspection_url",
    "provider-allowlist": "accepted out-of-list IP literal",
    "provider-ip-literal": "accepted out-of-list IP literal",
    "provider-redirect": "redirect target received a request",
    "provider-timeout": "provider timeout refusal missing",
    "provider-pin-mismatch": "accepted mismatched provider pin",
    "provider-unpinned-proxy": "unpinned provider request should succeed through HTTPS_PROXY",
    **{
        name: f"accepted {field}"
        for name, field in [
            ("active", "active"),
            ("issuer", "iss"),
            ("audience", "aud"),
            ("subject", "sub"),
            ("hosted-client", "client_id"),
            ("expired", "exp"),
            ("not-before", "nbf"),
            ("scope", "scope"),
        ]
    },
}


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
            shutil.copytree(ROOT / name, root / name, copy_function=shutil.copyfile)
        for name, filename, old, new, test in CASES:
            file = root / filename
            original = file.read_text()
            assert original.count(old) == 1, name
            file.touch()
            target = "identity_types" if test in TYPE_TESTS else "identity"
            test_timeout = 120 if target == "identity_types" else 30
            started = time.monotonic()
            green = run(root, target, test, filename, test_timeout=test_timeout)
            print(
                f"{name}: baseline completed in {time.monotonic() - started:.1f}s",
                flush=True,
            )
            assert (
                green.returncode == 0
                and "1 passed; 0 failed; 0 ignored" in green.stdout
            ), (name, "invalid baseline", green.stdout, green.stderr)
            try:
                file.write_text(original.replace(old, new, 1))
                red = run(root, target, test, filename, test_timeout=test_timeout)
                assert (
                    red.returncode == 101 and f"test {test} ... FAILED" in red.stdout
                ), (name, "wrong red", red.stdout, red.stderr)
                if target == "identity_types":
                    assert (
                        "Expected test case to fail to compile, but it succeeded."
                        in red.stderr
                    ), (name, "unrelated snapshot failure", red.stderr)
                    if name == "public-fields":
                        assert (
                            "tests/ui/handler_mint.rs" in red.stderr
                            and "tests/ui/struct_literal.rs" in red.stderr
                        ), (name, "missing privacy arm", red.stderr)
                        assert (
                            red.stderr.count(
                                "Expected test case to fail to compile, but it succeeded."
                            )
                            == 2
                        ), (
                            name,
                            "both privacy arms must accept the mutant",
                            red.stderr,
                        )
                else:
                    assert EXPECTED_RED[name] in red.stdout, (
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
