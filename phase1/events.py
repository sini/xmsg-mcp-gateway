import base64
import hmac
import json
import secrets
import time
from datetime import UTC, datetime

from .auth import PRINCIPAL
from .store import digest, encode
from .transport import signed_post


class CallbackError(ValueError):
    pass


def validate_secret(secret):
    try:
        if not secret.startswith("whsec_"):
            raise ValueError()
        key = base64.b64decode(secret[6:], validate=True)
        if not 24 <= len(key) <= 64:
            raise ValueError()
    except ValueError as exc:
        raise ValueError("invalid webhook signing secret") from exc


def subscription_id(url):
    return "sub_" + digest(PRINCIPAL + "\0" + url + "\0xmsg.message.received.v1\0{}")


def subscribe(store, credential, request, http, oauth):
    validate_secret(request.delivery.secret)
    url = request.delivery.url
    identifier = subscription_id(url)
    with store.guard(), store.db() as db:
        if not store.credential_active(db, credential, oauth):
            raise PermissionError("revoked")
        previous = db.execute("SELECT * FROM subscription").fetchone()
        if previous and previous["url"] != url:
            raise ValueError("callback binding conflicts; owner reset required")
        now = time.time()
        cached = (
            previous
            and previous["verified_until"] > now
            and store.cipher.decrypt(previous["secret"]).decode()
            == request.delivery.secret
        )
        if not cached:
            challenge = secrets.token_urlsafe(32)
            body = encode({"type": "verification", "challenge": challenge})
            try:
                status, raw = signed_post(
                    http,
                    url,
                    body,
                    "verification_" + secrets.token_hex(16),
                    identifier,
                    [request.delivery.secret],
                )
                if not 200 <= status < 300:
                    raise CallbackError("challenge_failed")
                reply = json.loads(raw)
                if (
                    not isinstance(reply.get("challenge"), str)
                    or not hmac.compare_digest(reply["challenge"], challenge)
                    or time.time() - now > 30
                ):
                    raise CallbackError("challenge_failed")
            except (OSError, ValueError, TypeError, AttributeError) as exc:
                raise CallbackError("challenge_failed") from exc
        expires = time.time() + min((request.ttlMs or 3600000) / 1000, 86400)
        if oauth:
            row = db.execute(
                "SELECT token FROM credentials WHERE id=?", (credential,)
            ).fetchone()
            claims = oauth.validate(store.cipher.decrypt(row["token"]).decode())
            if not claims:
                raise PermissionError("revoked during verification")
            expires = min(expires, int(claims["exp"]))
        encrypted = store.cipher.encrypt(request.delivery.secret.encode())
        old, rotation_until = None, 0
        if previous:
            current = store.cipher.decrypt(previous["secret"]).decode()
            if current != request.delivery.secret:
                old, rotation_until = previous["secret"], time.time() + 300
            elif previous["rotation_until"] > time.time():
                old, rotation_until = previous["old_secret"], previous["rotation_until"]
        verified_until = previous["verified_until"] if cached else time.time() + 300
        db.execute(
            "INSERT OR REPLACE INTO subscription VALUES (1,?,?,?,?,?,?,?,1,?)",
            (
                identifier,
                url,
                encrypted,
                old,
                rotation_until,
                expires,
                credential,
                verified_until,
            ),
        )
        return {
            "id": identifier,
            "refreshBefore": datetime.fromtimestamp(expires, UTC).isoformat(),
            "cursor": None,
            "truncated": False,
        }


def unsubscribe(store, credential, request, oauth):
    with store.guard(), store.db() as db:
        if not store.credential_active(db, credential, oauth):
            raise PermissionError("revoked")
        db.execute(
            "UPDATE subscription SET active=0 WHERE id=?",
            (subscription_id(request.delivery.url),),
        )
    return {}
