"""Local-only probe for fresh test credentials; never print tokens or claims."""

import argparse
import base64
import json
import math
import os
import stat
import time
import tomllib
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .auth import exact_audience
from .transport import HTTPS


class ProbeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    issuer: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    expected_subject: str = Field(min_length=1)
    approved_hosted_oauth_client_id: str = Field(min_length=1)
    introspection_client_id: str = Field(min_length=1)
    introspection_client_secret_file: Path
    introspection_url: str = Field(min_length=1)
    required_scopes: list[str] = Field(min_length=1)

    @field_validator("issuer", "resource", "introspection_url")
    @classmethod
    def https_identifier(cls, value):
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("HTTPS identifiers required")
        return value

    @field_validator("introspection_client_id")
    @classmethod
    def basic_client_identifier(cls, value):
        if ":" in value:
            raise ValueError("invalid introspection client ID")
        return value


def read_private(filename, limit=16384):
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        details = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) & 0o077
            or details.st_size > limit
        ):
            raise ValueError("owner-only regular file required")
        value = stream.read(limit + 1)
        if len(value) > limit:
            raise ValueError("private file exceeds limit")
        return value.decode()


def finite_number(value):
    return type(value) in (int, float) and math.isfinite(value)


def check_provider(config, token, http=None):
    secret = read_private(config.introspection_client_secret_file, 4096).strip()
    if not secret or not token or len(token) > 8192 or any(c.isspace() for c in token):
        raise ValueError("invalid test credential")
    credentials = base64.b64encode(
        (config.introspection_client_id + ":" + secret).encode()
    ).decode()
    try:
        status, body = (http or HTTPS()).post(
            config.introspection_url,
            urlencode({"token": token, "token_type_hint": "access_token"}).encode(),
            {
                "Authorization": "Basic " + credentials,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
    except (OSError, ValueError):
        return {"status": "unavailable", "reason": "introspection_transport_failed"}
    if status != 200:
        return {
            "status": "unavailable",
            "reason": "introspection_http_error",
            "http_status": status,
        }
    try:
        claims = json.loads(body)
        if not isinstance(claims, dict):
            raise ValueError()
    except (ValueError, UnicodeDecodeError):
        return {"status": "fail", "reason": "invalid_introspection_json"}
    now = time.time()
    exp, nbf = claims.get("exp"), claims.get("nbf", 0)
    audience = claims.get("aud")
    checks = {
        "token_active": claims.get("active") is True,
        "issuer": claims.get("iss") == config.issuer,
        "expected_owner_subject": claims.get("sub") == config.expected_subject,
        "approved_hosted_client": claims.get("client_id")
        == config.approved_hosted_oauth_client_id,
        "exact_resource_audience": exact_audience(audience, config.resource),
        "unexpired": finite_number(exp) and exp > now,
        "not_before": finite_number(nbf) and nbf <= now,
        "required_scopes": isinstance(claims.get("scope"), str)
        and set(config.required_scopes).issubset(claims["scope"].split()),
    }
    return {
        "status": "pass" if all(checks.values()) else "fail",
        "checks": checks,
        "hosted_login": "not_measured",
        "refresh_stability": "not_measured",
        "tunnel_and_events": "not_measured",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        config = ProbeConfig(**tomllib.loads(read_private(args.config)))
        if not config.introspection_client_secret_file.is_absolute():
            config = config.model_copy(
                update={
                    "introspection_client_secret_file": args.config.parent
                    / config.introspection_client_secret_file
                }
            )
        token = read_private(args.token_file, 8193).strip()
        result = check_provider(config, token)
    except (ValueError, OSError):
        print(
            json.dumps(
                {
                    "status": "unavailable",
                    "reason": "configuration_or_private_file_error",
                }
            )
        )
        return 2
    print(json.dumps(result, sort_keys=True))
    return (
        0
        if result["status"] == "pass"
        else 2
        if result["status"] == "unavailable"
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
