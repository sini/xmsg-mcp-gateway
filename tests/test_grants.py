import base64
import json
import secrets
import time

import pytest
from starlette.testclient import TestClient

from phase1.app import create_app
from phase1.auth import SCOPES, OAuth
from phase1.config import Settings
from phase1.store import Store
from phase1.worker import Worker


@pytest.fixture
def granted(tmp_path):
    store = Store(tmp_path / "state")
    secret = tmp_path / "lookup-secret"
    secret.write_text(secrets.token_urlsafe(32))
    settings = Settings(
        state_dir=store.root,
        service_id="fixture-service",
        issuer="https://issuer.example/",
        resource="https://resource.example/mcp",
        subject="fixture-owner",
        approved_hosted_oauth_client_id="hosted-H",
        introspection_url="https://issuer.example/introspect",
        client_id="lookup-I",
        client_secret_file=secret,
    )

    class Provider:
        status = 200
        claims = {
            "active": True,
            "iss": settings.issuer,
            "aud": settings.resource,
            "sub": settings.subject,
            "client_id": "hosted-H",
            "scope": " ".join(SCOPES),
            "exp": time.time() + 3600,
        }

        def post(self, url, body, headers):
            caller = (
                base64.b64decode(headers["Authorization"].split()[1])
                .decode()
                .split(":")[0]
            )
            assert caller == "lookup-I"
            return self.status, json.dumps(self.claims).encode()

    class Callback:
        def __init__(self):
            self.events = []

        def post(self, url, body, headers):
            payload = json.loads(body)
            if payload.get("type") == "verification":
                return 200, json.dumps({"challenge": payload["challenge"]}).encode()
            self.events.append(payload)
            return 200, b"{}"

    provider, callback = Provider(), Callback()
    oauth = OAuth(settings, provider)
    app = create_app(settings, store, callback, oauth)
    return (
        store,
        settings,
        provider,
        callback,
        oauth,
        TestClient(app, base_url="http://localhost"),
    )


def request(client, token, method="tools/call", params=None):
    return client.post(
        "/mcp",
        headers={"Authorization": "Bearer " + token},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
            if params is not None
            else {"name": "xmsg_identity", "arguments": {}},
        },
    )


def subscribe(client, token):
    return request(
        client,
        token,
        "events/subscribe",
        {
            "name": "xmsg.message.received.v1",
            "arguments": {},
            "delivery": {
                "mode": "webhook",
                "url": "https://callback.example/events",
                "secret": "whsec_" + base64.b64encode(secrets.token_bytes(32)).decode(),
            },
        },
    )


def enable(store, settings):
    ident = store.enroll_grant(settings, SCOPES)
    store.set_grant_enabled(ident, True)
    return ident


def test_enrollment_is_disabled_and_tokens_cannot_enroll(granted):
    store, settings, _, _, _, client = granted
    token = secrets.token_urlsafe(48)
    assert request(client, token).status_code == 403
    with store.db() as db:
        assert db.execute("SELECT count(*) FROM service_grants").fetchone()[0] == 0
    grant = store.enroll_grant(settings, SCOPES)
    with store.db() as db:
        row = db.execute("SELECT * FROM service_grants WHERE id=?", (grant,)).fetchone()
        assert row["revision"] == 1 and row["enabled"] == 0
    assert request(client, token).status_code == 403
    store.set_grant_enabled(grant, True)
    assert request(client, token).json()["result"]["isError"] is False


def test_token_client_is_independent_of_lookup_caller(granted):
    store, settings, provider, _, _, client = granted
    enable(store, settings)
    assert request(client, secrets.token_urlsafe(48)).status_code == 200
    for wrong in ("lookup-I", "foreign-client", None):
        provider.claims["client_id"] = wrong
        assert request(client, secrets.token_urlsafe(48)).status_code == 401


def test_disable_refresh_reenable_and_selected_replay(granted):
    store, settings, _, callback, oauth, client = granted
    grant = enable(store, settings)
    token = secrets.token_urlsafe(48)
    assert subscribe(client, token).status_code == 200
    first, second = store.emit("one"), store.emit("two")
    old_body = store.entries()[0]["body"]
    store.set_grant_enabled(grant, False)
    refreshed = secrets.token_urlsafe(48)
    assert request(client, refreshed).status_code == 403
    store.set_grant_enabled(grant, True)
    assert subscribe(client, refreshed).status_code == 200
    assert Worker(Store(store.root), callback, oauth).once() is False
    assert callback.events == []
    store.replay_event(first, "fixture-operator", "explicit selected replay")
    assert Worker(Store(store.root), callback, oauth).once() is True
    assert [e["eventId"] for e in callback.events] == [first]
    rows = {r["event_id"]: r for r in Store(store.root).entries()}
    assert rows[first]["body"] == old_body
    assert rows[first]["accepted_grant_revision"] == 2
    assert rows[first]["dispatch_grant_revision"] == 4
    assert rows[second]["state"].startswith("held")
    with store.db() as db:
        audit = db.execute(
            "SELECT * FROM grant_replays WHERE event_id=?", (first,)
        ).fetchall()
        assert (
            len(audit) == 1
            and audit[0]["old_revision"] == 2
            and audit[0]["new_revision"] == 4
        )


def test_unbound_work_never_adopts_a_new_subscription(granted):
    store, settings, _, callback, oauth, client = granted
    event = store.emit("before-enrollment")
    enable(store, settings)
    assert subscribe(client, secrets.token_urlsafe(48)).status_code == 200
    assert Worker(store, callback, oauth).once() is False
    assert callback.events == []
    assert store.entries()[0]["state"] == "held_unbound"
    store.replay_event(event, "fixture-operator", "reviewed unbound fixture")
    assert Worker(store, callback, oauth).once() is True
    assert callback.events[0]["eventId"] == event


def test_provider_outage_is_unavailable_not_invalid_token(granted):
    store, settings, provider, callback, oauth, client = granted
    enable(store, settings)
    token = secrets.token_urlsafe(48)
    assert subscribe(client, token).status_code == 200
    store.emit("outage-control")
    provider.status = 503
    assert request(client, token).status_code == 503
    assert Worker(store, callback, oauth).once() is False
    assert callback.events == []
    assert store.entries()[0]["attempts"] == 0


def test_scope_ceiling_cannot_be_broadened_by_a_token(granted):
    store, settings, _, _, _, client = granted
    ident = store.enroll_grant(settings, ["identity:read"])
    store.set_grant_enabled(ident, True)
    assert request(client, secrets.token_urlsafe(48)).status_code == 403


def test_disabled_acceptance_is_held_and_restart_keeps_the_snapshot(granted):
    store, settings, _, _, _, _ = granted
    grant = enable(store, settings)
    store.set_grant_enabled(grant, False)
    event = store.emit("disabled-acceptance")
    row = Store(store.root).entries()[0]
    assert row["event_id"] == event
    assert row["state"] == "held_grant_disabled"
    assert row["accepted_grant_id"] == grant and row["accepted_grant_revision"] == 3


def test_corrupt_policy_is_unavailable_and_missing_database_is_not_recreated(granted):
    store, settings, _, callback, oauth, client = granted
    grant = enable(store, settings)
    token = secrets.token_urlsafe(48)
    assert subscribe(client, token).status_code == 200
    store.emit("policy-outage")
    with store.db() as db:
        db.execute(
            "UPDATE service_grants SET scope_ceiling='broken' WHERE id=?", (grant,)
        )
    assert request(client, token).status_code == 503
    assert Worker(store, callback, oauth).once() is False
    assert callback.events == []
    (store.root / "state.sqlite3").rename(store.root / "offline.sqlite3")
    assert request(client, token).status_code == 503
    assert not (store.root / "state.sqlite3").exists()


def test_legacy_oauth_custody_migrates_held_without_changing_identity(granted):
    store, settings, _, callback, oauth, client = granted
    enable(store, settings)
    assert subscribe(client, secrets.token_urlsafe(48)).status_code == 200
    event = store.emit("legacy-event")
    original = store.entries()[0]["body"]
    with store.db() as db:
        for table, columns in {
            "credentials": ["grant_id", "grant_revision"],
            "subscription": ["grant_id", "grant_revision"],
            "outbox": [
                "accepted_grant_id",
                "accepted_grant_revision",
                "dispatch_grant_id",
                "dispatch_grant_revision",
            ],
        }.items():
            for column in columns:
                db.execute("ALTER TABLE " + table + " DROP COLUMN " + column)
        db.execute("DROP TABLE grant_replays")
        db.execute("DROP TABLE service_grants")
    migrated = Store(store.root)
    row = migrated.entries()[0]
    assert row["event_id"] == event and row["body"] == original
    assert row["state"] == "held_replay_required"
    assert row["accepted_grant_id"] is None
    assert Worker(migrated, callback, oauth).once() is False
    assert callback.events == []


def test_disable_waits_for_real_network_submission_and_blocks_later_work(granted):
    import http.client
    import select
    import subprocess
    import sys
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    store, settings, _, _, oauth, client = granted
    grant = enable(store, settings)
    entered, release = threading.Event(), threading.Event()
    received = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            received.append(
                json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            )
            entered.set()
            assert release.wait(5)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

    server = HTTPServer(("127.0.0.1", 0), Handler)
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()

    class Network:
        def post(self, url, body, headers):
            assert url == "https://callback.example/events"
            connection = http.client.HTTPConnection(
                "127.0.0.1", server.server_port, timeout=5
            )
            try:
                connection.request("POST", "/events", body=body, headers=headers)
                response = connection.getresponse()
                return response.status, response.read()
            finally:
                connection.close()

    assert subscribe(client, secrets.token_urlsafe(48)).status_code == 200
    first = store.emit("submitted-before-disable")
    second = store.emit("must-be-held")
    results = []
    worker = threading.Thread(
        target=lambda: results.append(
            Worker(Store(store.root), Network(), oauth).once()
        )
    )
    child = None
    try:
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import sys; from phase1.store import Store; "
                's=Store(sys.argv[1]); print("ready",flush=True); '
                'sys.stdin.readline(); print("started",flush=True); '
                "s.set_grant_enabled(sys.argv[2],False); "
                'print("disabled",flush=True)',
                str(store.root),
                grant,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert select.select([child.stdout], [], [], 5)[0]
        assert child.stdout.readline().strip() == "ready"
        worker.start()
        assert entered.wait(5)
        child.stdin.write("disable\n")
        child.stdin.flush()
        assert select.select([child.stdout], [], [], 5)[0]
        assert child.stdout.readline().strip() == "started"
        assert not select.select([child.stdout], [], [], 1)[0]
        assert child.poll() is None
        release.set()
        output, errors = child.communicate(timeout=10)
        assert child.returncode == 0, errors
        assert output.strip() == "disabled"
        worker.join(timeout=5)
        assert not worker.is_alive() and results == [True]
        assert [e["eventId"] for e in received] == [first]
        assert Worker(Store(store.root), Network(), oauth).once() is False
        assert [e["eventId"] for e in received] == [first]
        rows = {r["event_id"]: r for r in Store(store.root).entries()}
        assert rows[first]["state"] == "accepted"
        assert rows[second]["state"] == "held_grant_disabled"
    finally:
        release.set()
        if child and child.poll() is None:
            child.terminate()
            child.wait(timeout=5)
        if worker.ident is not None:
            worker.join(timeout=5)
        server.shutdown()
        server.server_close()
        serving.join(timeout=5)
        assert not worker.is_alive() and not serving.is_alive()


def test_worker_checks_the_items_snapshot_not_only_the_subscription(granted):
    store, settings, _, callback, oauth, client = granted
    enable(store, settings)
    assert subscribe(client, secrets.token_urlsafe(48)).status_code == 200
    good = store.emit("current-snapshot")
    assert Worker(store, callback, oauth).once() is True
    stale = store.emit("older-snapshot")
    with store.db() as db:
        db.execute(
            "UPDATE outbox SET dispatch_grant_revision=1 WHERE event_id=?", (stale,)
        )
    assert Worker(store, callback, oauth).once() is False
    assert [e["eventId"] for e in callback.events] == [good]
    assert store.entries()[1]["state"] == "held_replay_required"


def test_no_auth_introspection_and_canonical_config_fields(granted):
    store, settings, _, _, _, _ = granted
    configured = Settings(
        **{
            **settings.model_dump(exclude={"client_id", "client_secret_file"}),
            "introspection_auth_method": "none",
            "introspection_client_id": None,
            "introspection_client_secret_file": None,
        }
    )

    class PublicIntrospection:
        def post(self, url, body, headers):
            assert "Authorization" not in headers
            return 200, json.dumps(
                {
                    "active": True,
                    "iss": configured.issuer,
                    "aud": configured.resource,
                    "sub": configured.subject,
                    "client_id": configured.approved_hosted_oauth_client_id,
                    "scope": " ".join(SCOPES),
                    "exp": time.time() + 300,
                }
            ).encode()

    oauth = OAuth(configured, PublicIntrospection())
    assert oauth.validate(secrets.token_urlsafe(48))
    profile = Settings(introspection_client_id="separate-lookup-I")
    assert profile.client_id == "separate-lookup-I"
    assert profile.approved_hosted_oauth_client_id is None


def test_existing_state_without_its_key_refuses_startup(tmp_path):
    store = Store(tmp_path / "fixture-state")
    (store.root / "key").unlink()
    with pytest.raises(ValueError, match="missing its encryption key"):
        Store(store.root)


def test_a_state_directory_cannot_be_shared_by_different_services(granted):
    store, settings, _, _, _, _ = granted
    other = settings.model_copy(update={"service_id": "other-service"})
    with pytest.raises(ValueError, match="another service"):
        Store(store.root).configure(other)


def test_generic_profile_and_owner_cli_lifecycle(tmp_path):
    import subprocess
    import sys

    config = tmp_path / "profile.toml"
    state = tmp_path / "user-selected-state"
    config.write_text(
        "\n".join(
            [
                'service_id="custom-service"',
                f"state_dir={json.dumps(str(state))}",
                'issuer="https://provider.example/"',
                'resource="https://resource.example/mcp"',
                'subject="owner-chosen-subject"',
                'approved_hosted_oauth_client_id="approved-client"',
                'introspection_url="https://provider.example/introspect"',
                'introspection_auth_method="none"',
            ]
        )
    )

    def cli(*args):
        result = subprocess.run(
            [sys.executable, "-m", "phase1.cli", "--config", str(config), *args],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    grant = cli("grant-enroll")
    assert grant.startswith("grant_")
    store = Store(state)
    with store.db() as db:
        assert (
            db.execute(
                "SELECT enabled FROM service_grants WHERE id=?", (grant,)
            ).fetchone()[0]
            == 0
        )
    cli("grant-enable", grant)
    cli("emit", "user-selected-occurrence")
    cli("grant-disable", grant)
    status = json.loads(cli("status"))
    assert status["health"]["held_grant_disabled"] == 1
    assert len(status["outbox"]) == 1
