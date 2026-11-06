"""Durable service bindings; tokens cannot create or change local authority."""

import json
import secrets
import time


class GrantDenied(PermissionError):
    pass


class AuthorizationUnavailable(RuntimeError):
    pass


def resolve(db, settings, claims, required):
    row = db.execute(
        "SELECT * FROM service_grants WHERE service_id=? AND issuer=? AND subject=? "
        "AND resource=? AND hosted_client_id=? AND enabled=1",
        (
            settings.service_id,
            claims["iss"],
            claims["sub"],
            claims["aud"],
            claims["client_id"],
        ),
    ).fetchone()
    if not row:
        raise GrantDenied("service grant unavailable")
    try:
        ceiling = json.loads(row["scope_ceiling"])
        if not isinstance(ceiling, list) or not all(
            isinstance(s, str) for s in ceiling
        ):
            raise ValueError("invalid policy")
    except (ValueError, TypeError) as exc:
        raise AuthorizationUnavailable("grant policy unavailable") from exc
    if not set(required).issubset(ceiling):
        raise GrantDenied("service grant unavailable")
    return row


def snapshot_active(db, grant_id, revision):
    return bool(
        db.execute(
            "SELECT 1 FROM service_grants WHERE id=? AND revision=? AND enabled=1",
            (grant_id, revision),
        ).fetchone()
    )


def enroll(store, settings, scopes):
    store.configure(settings)
    if (
        not all(
            (
                settings.issuer,
                settings.subject,
                settings.resource,
                settings.approved_hosted_oauth_client_id,
            )
        )
        or not scopes
    ):
        raise ValueError("complete service binding and scope ceiling required")
    identifier = "grant_" + secrets.token_hex(16)
    with store.guard(), store.db() as db:
        db.execute(
            "INSERT INTO service_grants VALUES (?,?,?,?,?,?,?,1,0)",
            (
                identifier,
                settings.service_id,
                settings.issuer,
                settings.subject,
                settings.resource,
                settings.approved_hosted_oauth_client_id,
                json.dumps(sorted(set(scopes))),
            ),
        )
    return identifier


def set_enabled(store, identifier, enabled):
    with store.guard(), store.db() as db:
        row = db.execute(
            "SELECT * FROM service_grants WHERE id=?", (identifier,)
        ).fetchone()
        if not row:
            raise ValueError("unknown grant")
        if bool(row["enabled"]) == bool(enabled):
            return
        if (
            enabled
            and db.execute(
                "SELECT 1 FROM service_grants WHERE service_id=? AND enabled=1",
                (row["service_id"],),
            ).fetchone()
        ):
            raise ValueError("service already has an enabled binding")
        db.execute(
            "UPDATE service_grants SET enabled=?,revision=revision+1 WHERE id=?",
            (int(enabled), identifier),
        )
        if not enabled:
            db.execute(
                "UPDATE outbox SET state='held_grant_disabled',last_error='grant_disabled' "
                "WHERE state='pending' AND dispatch_grant_id=?",
                (identifier,),
            )
            db.execute(
                "UPDATE subscription SET active=0 WHERE grant_id=?", (identifier,)
            )


def replay(store, event_id, operator, reason):
    if not operator or not reason or len(operator) > 256 or len(reason) > 1024:
        raise ValueError("bounded operator and reason required")
    with store.guard(), store.db() as db:
        event = db.execute(
            "SELECT * FROM outbox WHERE event_id=?", (event_id,)
        ).fetchone()
        subscription = db.execute(
            "SELECT * FROM subscription WHERE active=1"
        ).fetchone()
        if not event or not event["state"].startswith("held") or not subscription:
            raise ValueError("held event and current subscription required")
        grant_id, revision = subscription["grant_id"], subscription["grant_revision"]
        if not grant_id or not snapshot_active(db, grant_id, revision):
            raise GrantDenied("no current replay authority")
        db.execute(
            "INSERT INTO grant_replays VALUES (?,?,?,?,?,?,?,?)",
            (
                event_id,
                event["dispatch_grant_id"],
                event["dispatch_grant_revision"],
                grant_id,
                revision,
                operator,
                reason,
                time.time(),
            ),
        )
        db.execute(
            "UPDATE outbox SET dispatch_grant_id=?,dispatch_grant_revision=?,state='pending',"
            "attempts=0,next_attempt=0,last_error=NULL WHERE event_id=?",
            (grant_id, revision, event_id),
        )
