import json
import secrets
import subprocess
import sys
import time

import pytest

from phase1.auth import SCOPES, OAuth
from phase1.config import Settings
from phase1.provider_probe import ProbeConfig, check_provider
from phase1.store import Store
from phase1.transport import public_address


def test_oauth_digest_revoke_is_explicitly_refused(tmp_path):
    store = Store(tmp_path / "state")
    with store.db() as db:
        db.execute("INSERT INTO credentials(id,mode) VALUES ('fixture-oauth','oauth')")
    with pytest.raises(ValueError, match="OAuth"):
        store.revoke_id("fixture-oauth")
    with store.db() as db:
        assert (
            db.execute(
                "SELECT revoked FROM credentials WHERE id='fixture-oauth'"
            ).fetchone()[0]
            == 0
        )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "phase1.cli",
            "--state",
            str(store.root),
            "revoke",
            "fixture-oauth",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode != 0
    assert "OAuth" in result.stderr and "Credential revoked." not in result.stdout


def test_provider_probe_and_server_agree_on_audiences(tmp_path):
    key = tmp_path / "lookup-secret"
    key.write_text(secrets.token_urlsafe(32))
    key.chmod(0o600)
    settings = Settings(
        issuer="https://issuer.example/",
        resource="https://resource.example/mcp",
        subject="fixture-owner",
        introspection_url="https://issuer.example/introspect",
        client_id="lookup-I",
        client_secret_file=key,
    )

    class Provider:
        audience = settings.resource

        def post(self, *args):
            return 200, json.dumps(
                {
                    "active": True,
                    "iss": settings.issuer,
                    "sub": settings.subject,
                    "aud": self.audience,
                    "client_id": "hosted-H",
                    "exp": time.time() + 300,
                    "scope": " ".join(SCOPES),
                }
            ).encode()

    provider = Provider()
    oauth = OAuth(settings, provider)
    probe = ProbeConfig(
        issuer=settings.issuer,
        resource=settings.resource,
        expected_subject=settings.subject,
        approved_hosted_oauth_client_id="hosted-H",
        introspection_client_id=settings.client_id,
        introspection_client_secret_file=key,
        introspection_url=settings.introspection_url,
        required_scopes=SCOPES,
    )
    for audience, valid in [
        (settings.resource, True),
        ([settings.resource], True),
        ([settings.resource, "https://other.example/mcp"], False),
        ([], False),
        (None, False),
    ]:
        provider.audience = audience
        assert bool(oauth.validate("fixture-access-token")) == valid
        assert (
            check_provider(probe, "fixture-access-token", provider)["status"] == "pass"
        ) == valid
        if valid:
            assert oauth.validate("fixture-access-token")["aud"] == settings.resource


@pytest.mark.parametrize("address", ["::8.8.8.8", "::ffff:8.8.8.8", "fec0::1"])
def test_unsafe_ipv6_callback_address_is_refused(address):
    assert public_address("2606:4700:4700::1111")
    assert not public_address(address)


def test_unknown_revoke_id_exits_nonzero(tmp_path):
    store = Store(tmp_path / "state")
    token = store.issue()
    from phase1.store import digest

    def run(ident):
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "phase1.cli",
                "--state",
                str(store.root),
                "revoke",
                ident,
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    assert run(digest(token)).returncode == 0
    result = run("unknown")
    assert result.returncode != 0 and "Credential revoked." not in result.stdout


def test_unknown_or_non_dead_retry_id_exits_nonzero(tmp_path):
    store = Store(tmp_path / "state")
    ident = store.emit("fixture-occurrence")
    with store.db() as db:
        db.execute("UPDATE outbox SET state='dead' WHERE event_id=?", (ident,))

    def run(ident):
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "phase1.cli",
                "--state",
                str(store.root),
                "retry-dead",
                ident,
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    assert run(ident).returncode == 0
    for target in (ident, "unknown"):
        result = run(target)
        assert result.returncode != 0 and "rearmed" not in result.stdout
