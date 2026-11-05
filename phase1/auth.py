import base64
import json
import math
import time
from urllib.parse import urlencode

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
            "client_id",
            "client_secret_file",
        ):
            if not getattr(settings, field):
                raise ValueError("OAuth configuration incomplete: " + field)
        if not all(
            getattr(settings, field).startswith("https://")
            for field in ("issuer", "resource", "introspection_url")
        ):
            raise ValueError("OAuth endpoints and resource must be HTTPS")
        self.secret = settings.client_secret_file.read_text().strip()
        if not self.secret or ":" in settings.client_id:
            raise ValueError("invalid OAuth client credentials")

    def validate(self, token):
        try:
            credentials = base64.b64encode(
                (self.settings.client_id + ":" + self.secret).encode()
            ).decode()
            status, raw = self.http.post(
                self.settings.introspection_url,
                urlencode({"token": token, "token_type_hint": "access_token"}).encode(),
                {
                    "Authorization": "Basic " + credentials,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            claims = json.loads(raw)
            now = time.time()
            exp = claims.get("exp")
            valid = (
                status == 200
                and claims.get("active") is True
                and claims.get("iss") == self.settings.issuer
                and claims.get("aud") == self.settings.resource
                and claims.get("sub") == self.settings.subject
                and isinstance(exp, (int, float))
                and not isinstance(exp, bool)
                and math.isfinite(exp)
                and exp > now
                and isinstance(claims.get("nbf", 0), (int, float))
                and claims.get("nbf", 0) <= now
                and isinstance(claims.get("scope"), str)
                and set(SCOPES).issubset(claims["scope"].split())
            )
            return claims if valid else None
        except (OSError, ValueError, TypeError, AttributeError):
            return None
