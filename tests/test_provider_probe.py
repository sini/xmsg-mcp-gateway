import base64
import json
import secrets
import time
from urllib.parse import parse_qs

import pytest

from phase1.provider_probe import ProbeConfig, check_provider, main


@pytest.fixture
def probe(tmp_path):
    key = tmp_path / "introspection-secret"
    key.write_text(secrets.token_urlsafe(32))
    key.chmod(0o600)
    token = secrets.token_urlsafe(48)
    config = ProbeConfig(
        issuer="https://issuer.example/",
        resource="https://mcp.example/mcp",
        expected_subject="fixture-owner",
        approved_hosted_oauth_client_id="hosted-client-H",
        introspection_client_id="lookup-client-I",
        introspection_client_secret_file=key,
        introspection_url="https://issuer.example/introspect",
        required_scopes=["identity:read", "events:subscribe"],
    )

    class IdP:
        def __init__(self):
            self.claims = {
                "active": True,
                "iss": config.issuer,
                "aud": config.resource,
                "sub": config.expected_subject,
                "client_id": "hosted-client-H",
                "exp": int(time.time()) + 300,
                "scope": "identity:read events:subscribe",
            }
            self.status = 200
            self.calls = 0

        def post(self, url, body, headers):
            self.calls += 1
            assert url == config.introspection_url
            assert parse_qs(body.decode())["token"] == [token]
            auth = base64.b64decode(headers["Authorization"].split()[1]).decode()
            assert auth.split(":")[0] == "lookup-client-I"
            return self.status, json.dumps(self.claims).encode()

    return config, token, key, IdP()


def test_probe_distinguishes_hosted_and_introspection_clients(probe):
    config, token, _, provider = probe
    result = check_provider(config, token, provider)
    assert result["status"] == "pass"
    assert all(result["checks"].values())
    provider.claims["client_id"] = config.introspection_client_id
    rejected = check_provider(config, token, provider)
    assert rejected["status"] == "fail"
    assert rejected["checks"]["approved_hosted_client"] is False


@pytest.mark.parametrize(
    "field,bad",
    [
        ("active", False),
        ("iss", "https://wrong.example/"),
        ("aud", "https://other.example/mcp"),
        ("sub", "other-owner"),
        ("client_id", "other-client"),
        ("exp", 0),
        ("exp", True),
        ("nbf", time.time() + 3600),
        ("scope", "openid"),
    ],
)
def test_probe_rejects_invalid_authority(probe, field, bad):
    config, token, _, provider = probe
    assert check_provider(config, token, provider)["status"] == "pass"
    provider.claims[field] = bad
    assert check_provider(config, token, provider)["status"] == "fail"


@pytest.mark.parametrize("field", ["client_id", "sub", "aud", "iss", "exp", "scope"])
def test_probe_missing_required_claim_does_not_fall_back(probe, field):
    config, token, _, provider = probe
    del provider.claims[field]
    assert check_provider(config, token, provider)["status"] == "fail"


def test_probe_does_not_return_token_secret_or_claims(probe):
    config, token, key, provider = probe
    provider.claims["unexpected_secret"] = key.read_text()
    provider.claims["user_message"] = token
    encoded = json.dumps(check_provider(config, token, provider))
    for sensitive in (
        token,
        key.read_text(),
        config.expected_subject,
        config.issuer,
        config.approved_hosted_oauth_client_id,
    ):
        assert sensitive not in encoded
    provider.status = 401
    assert check_provider(config, token, provider)["status"] == "unavailable"


def test_probe_does_not_read_insecure_secret_file(probe):
    config, token, key, provider = probe
    key.chmod(0o644)
    with pytest.raises(ValueError):
        check_provider(config, token, provider)
    assert provider.calls == 0


def test_probe_cli_errors_are_redacted(tmp_path, capsys):
    config = tmp_path / "invalid.toml"
    marker = secrets.token_urlsafe(48)
    config.write_text('private_key = "' + marker + '"\n')
    result = main(["--config", str(config), "--token-file", str(tmp_path / "missing")])
    assert result == 2
    output = capsys.readouterr().out
    assert marker not in output
    assert json.loads(output)["reason"] == "configuration_or_private_file_error"
