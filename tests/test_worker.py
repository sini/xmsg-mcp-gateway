import json
import secrets
import time

import pytest

from phase1.auth import SCOPES, OAuth
from phase1.config import Settings
from phase1.events import subscribe
from phase1.schemas import Subscribe
from phase1.store import Store
from phase1.worker import Worker


@pytest.fixture
def worker_env(tmp_path):
    store = Store(tmp_path / "state")
    key_file = store.root / "fixture-client-secret"
    key_file.write_text(secrets.token_urlsafe(32))
    settings = Settings(
        state_dir=store.root,
        issuer="https://issuer.example/",
        resource="https://resource.example/mcp",
        subject="fixture-owner",
        introspection_url="https://issuer.example/introspect",
        client_id="fixture",
        client_secret_file=key_file,
    )

    class Issuer:
        def __init__(self):
            self.calls = 0
            self.status = 200
            self.claims = {
                "active": True,
                "iss": settings.issuer,
                "aud": settings.resource,
                "sub": settings.subject,
                "scope": " ".join(SCOPES),
                "exp": time.time() + 3600,
            }

        def post(self, *args):
            self.calls += 1
            return self.status, json.dumps(self.claims).encode()

    class Callback:
        def __init__(self):
            self.events = []

        def post(self, url, body, headers):
            event = json.loads(body)
            if event.get("type") == "verification":
                return 200, json.dumps({"challenge": event["challenge"]}).encode()
            self.events.append(event)
            return 200, b"{}"

    import base64

    issuer, callback = Issuer(), Callback()
    oauth = OAuth(settings, issuer)
    credential = store.authenticate(secrets.token_urlsafe(48), oauth)
    request = Subscribe.model_validate(
        {
            "name": "xmsg.message.received.v1",
            "arguments": {},
            "delivery": {
                "mode": "webhook",
                "url": "https://callback.example/events",
                "secret": "whsec_" + base64.b64encode(secrets.token_bytes(32)).decode(),
            },
        }
    )
    subscribe(store, credential, request, callback, oauth)
    assert issuer.calls > 0
    issuer.calls = 0
    return store, issuer, callback, Worker(store, callback, oauth)


@pytest.mark.parametrize(
    "queue_state",
    ["empty", "accepted", "dead", "backoff", "exhausted", "inactive", "expired"],
)
def test_idle_worker_skips_introspection(worker_env, queue_state):
    store, issuer, callback, worker = worker_env
    if queue_state != "empty":
        store.emit("fixture-occurrence")
        with store.db() as db:
            if queue_state in ("accepted", "dead"):
                db.execute("UPDATE outbox SET state=?", (queue_state,))
            elif queue_state == "backoff":
                db.execute("UPDATE outbox SET next_attempt=?", (time.time() + 300,))
            elif queue_state == "exhausted":
                db.execute("UPDATE outbox SET attempts=5")
            elif queue_state == "inactive":
                db.execute("UPDATE subscription SET active=0")
            elif queue_state == "expired":
                db.execute("UPDATE subscription SET expires=0")
    if queue_state == "backoff":
        store.emit("later-ready-occurrence")
    worker.once()
    assert issuer.calls == 0
    assert callback.events == []
    if queue_state == "exhausted":
        assert store.health()["dead"] == 1


@pytest.mark.parametrize(
    "authorization", ["active", "revoked", "expired", "unavailable"]
)
def test_due_worker_rechecks_authorization(worker_env, authorization):
    store, issuer, callback, worker = worker_env
    event_id = store.emit("due-occurrence")
    if authorization == "revoked":
        issuer.claims["active"] = False
    elif authorization == "expired":
        issuer.claims["exp"] = 0
    elif authorization == "unavailable":
        issuer.status = 503
    worker.once()
    assert issuer.calls == 1
    if authorization == "active":
        assert [event["eventId"] for event in callback.events] == [event_id]
        assert store.health()["accepted"] == 1
    else:
        assert callback.events == []
        assert store.health()["pending"] == 1
        assert store.entries()[0]["attempts"] == 0
