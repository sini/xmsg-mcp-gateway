import base64
import json
import math
import time
from urllib.parse import urlencode

from .grants import AuthorizationUnavailable
from .transport import HTTPS

SCOPES = ["identity:read", "events:subscribe"]
PRINCIPAL = "dot@phase1-synthetic"


class OAuth:
    def __init__(self, settings, http=None):
        self.settings = settings
        self.http = http or HTTPS()
        for field in (
            "issuer",
            "resource",
            "subject",
            "introspection_url",
            "approved_hosted_oauth_client_id",
        ):
            if not getattr(settings, field):
                raise ValueError("OAuth configuration incomplete: " + field)
        if not all(
            getattr(settings, field).startswith("https://")
            for field in ("issuer", "resource", "introspection_url")
        ):
            raise ValueError("OAuth endpoints and resource must be HTTPS")
        self.secret = None
        if settings.introspection_auth_method == "client_secret_basic":
            if not settings.client_id or not settings.client_secret_file:
                raise ValueError("introspection credentials required")
            self.secret = settings.client_secret_file.read_text().strip()
            if not self.secret or ":" in settings.client_id:
                raise ValueError("invalid introspection credentials")

    def validate(self, token):
        try:
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            if self.secret is not None:
                credentials = base64.b64encode(
                    (self.settings.client_id + ":" + self.secret).encode()
                ).decode()
                headers["Authorization"] = "Basic " + credentials
            status, raw = self.http.post(
                self.settings.introspection_url,
                urlencode({"token": token, "token_type_hint": "access_token"}).encode(),
                headers,
            )
            if status != 200:
                raise AuthorizationUnavailable("introspection unavailable")
            claims = json.loads(raw)
            now = time.time()
            exp = claims.get("exp")
            valid = (
                status == 200
                and claims.get("active") is True
                and claims.get("iss") == self.settings.issuer
                and claims.get("aud") == self.settings.resource
                and claims.get("sub") == self.settings.subject
                and claims.get("client_id")
                == self.settings.approved_hosted_oauth_client_id
                and isinstance(exp, (int, float))
                and not isinstance(exp, bool)
                and math.isfinite(exp)
                and exp > now
                and isinstance(claims.get("nbf", 0), (int, float))
                and not isinstance(claims.get("nbf", 0), bool)
                and math.isfinite(claims.get("nbf", 0))
                and claims.get("nbf", 0) <= now
                and isinstance(claims.get("scope"), str)
                and set(SCOPES).issubset(claims["scope"].split())
            )
            return claims if valid else None
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            raise AuthorizationUnavailable("introspection unavailable") from exc
