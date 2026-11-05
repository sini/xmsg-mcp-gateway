import base64
import json
import os
import secrets
import subprocess
import sys
import time

import pytest
from standardwebhooks import Webhook
from standardwebhooks.webhooks import WebhookVerificationError
from starlette.testclient import TestClient

from phase1 import transport
from phase1.app import create_app
from phase1.config import Settings
from phase1.store import Store
from phase1.worker import Worker


def secret():
    return "whsec_" + base64.b64encode(secrets.token_bytes(32)).decode()


class Callback:
    def __init__(self):
        self.calls = []
        self.status = 200
        self.wrong_challenge = False

    def post(self, url, body, headers):
        self.calls.append((url, body, headers))
        data = json.loads(body)
        reply = {
            "challenge": "wrong" if self.wrong_challenge else data.get("challenge")
        }
        return self.status, json.dumps(reply).encode()


@pytest.fixture
def env(tmp_path):
    store = Store(tmp_path / "state")
    token = store.issue()
    callback = Callback()
    settings = Settings(state_dir=store.root, auth_mode="local-test")
    client = TestClient(
        create_app(settings, store, callback), base_url="http://localhost"
    )
    return store, token, callback, client


def rpc(client, token, method, params=None):
    headers = {"Authorization": "Bearer " + token} if token else {}
    return client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        headers=headers,
    )


def sub(client, token, key=None, **extra):
    return rpc(
        client,
        token,
        "events/subscribe",
        {
            "name": "xmsg.message.received.v1",
            "arguments": {},
            "delivery": {
                "mode": "webhook",
                "url": "https://callback.example/events",
                "secret": key or secret(),
            },
            **extra,
        },
    )


@pytest.mark.parametrize(
    "method",
    [
        "tools/list",
        "tools/call",
        "events/list",
        "events/subscribe",
        "events/unsubscribe",
    ],
)
def test_auth(env, method):
    store, token, _, client = env
    params = (
        {"name": "xmsg_identity", "arguments": {}} if method == "tools/call" else {}
    )
    if method.startswith("events/") and method != "events/list":
        params = {
            "name": "xmsg.message.received.v1",
            "arguments": {},
            "delivery": {"mode": "webhook", "url": "https://callback.example/events"},
        }
        if method == "events/subscribe":
            params["delivery"]["secret"] = secret()
    missing = rpc(client, None, method, params)
    wrong = rpc(client, "wrong-token", method, params)
    assert missing.status_code == 401
    assert wrong.status_code == 401
    good = rpc(client, token, method, params)
    assert good.status_code == 200
    assert "result" in good.json()
    store.revoke(token)
    assert rpc(client, token, method, params).status_code == 401


@pytest.mark.parametrize(
    "field", ["from", "origin", "as_agent", "mailbox", "mailbox_id"]
)
def test_unknown_sender(env, field):
    _, token, _, client = env
    response = rpc(
        client,
        token,
        "tools/call",
        {"name": "xmsg_identity", "arguments": {field: "attacker"}},
    )
    assert response.json()["error"]["code"] == -32602
    response = rpc(
        client,
        token,
        "events/subscribe",
        {
            "name": "xmsg.message.received.v1",
            "arguments": {field: "attacker"},
            "delivery": {
                "mode": "webhook",
                "url": "https://callback.example/",
                "secret": secret(),
            },
        },
    )
    assert response.json()["error"]["code"] == -32602
    assert (
        "result"
        in rpc(
            client, token, "tools/call", {"name": "xmsg_identity", "arguments": {}}
        ).json()
    )


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "100.127.255.254",
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "2002:7f00:1::",
        "64:ff9b::7f00:1",
        "0.0.0.0",
        "224.0.0.1",
    ],
)
def test_ssrf(address, monkeypatch):
    monkeypatch.setattr(
        transport.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", (address, 443))]
    )
    with pytest.raises(transport.DestinationError):
        transport.resolve_public("https://dns.example/callback")
    with pytest.raises(transport.DestinationError):
        transport.resolve_public(
            "https://" + ("[" + address + "]" if ":" in address else address) + "/"
        )
    monkeypatch.setattr(
        transport.socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    assert transport.resolve_public("https://public.example/callback")[1] == [
        "93.184.216.34"
    ]


def test_rebinding_and_pin(monkeypatch):
    addresses = ["93.184.216.34"]
    monkeypatch.setattr(
        transport.socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", (a_, 443)) for a_ in addresses],
    )
    requests = []

    class Conn:
        def __init__(self, host, **kwargs):
            assert host == "callback.example"

        def request(self, method, target, body, headers):
            requests.append(self._create_connection(("callback.example", 443), 10))

        def getresponse(self):
            return type("Reply", (), {"status": 200, "read": lambda self, n: b"{}"})()

        def close(self):
            pass

    monkeypatch.setattr(transport.http.client, "HTTPSConnection", Conn)
    dialed = []

    def dial(address, timeout):
        dialed.append(address)
        return object()

    monkeypatch.setattr(transport, "dial_ip", dial)
    transport.HTTPS().post("https://callback.example/", b"{}", {})
    assert dialed == [("93.184.216.34", 443)]
    addresses[:] = ["10.0.0.2"]
    with pytest.raises(transport.DestinationError):
        transport.HTTPS().post("https://callback.example/", b"{}", {})
    assert len(dialed) == 1
    addresses[:] = ["93.184.216.34", "10.0.0.2"]
    with pytest.raises(transport.DestinationError):
        transport.resolve_public("https://callback.example/")


def test_redirect(env):
    _, token, callback, client = env
    assert "result" in sub(client, token).json()
    callback.status = 302
    response = sub(client, token)
    assert response.json()["error"]["code"] == -32015
    assert len(callback.calls) == 2


def test_signatures(env):
    store, token, callback, client = env
    key = secret()
    assert "result" in sub(client, token, key).json()
    _, challenge, challenge_headers = callback.calls[-1]
    Webhook(key).verify(challenge, challenge_headers)
    store.emit("occurrence-one")
    Worker(store, callback).once()
    _, body, headers = callback.calls[-1]
    event = Webhook(key).verify(body, headers)
    assert event["eventId"] == headers["webhook-id"]
    assert event["data"]["mailbox"] == "dot@phase1-synthetic"
    assert event["data"]["body_available"] is False
    with pytest.raises(WebhookVerificationError):
        Webhook(secret()).verify(body, headers)
    with pytest.raises(WebhookVerificationError):
        Webhook(key).verify(body + b" ", headers)
    assert store.health()["accepted"] == 1


def test_custody(env):
    store, token, callback, client = env
    sub(client, token)
    # A separate process exits without closing Python/SQLite after durable emit.
    process = subprocess.run(
        [
            sys.executable,
            "-c",
            "import os,sys; from phase1.store import Store; "
            'Store(sys.argv[1]).emit("crash-occurrence"); os._exit(73)',
            str(store.root),
        ],
        capture_output=True,
    )
    assert process.returncode == 73
    pending = store.entries()
    assert len(pending) == 1 and pending[0]["state"] == "pending"
    expected = pending[0]["event_id"]
    restarted = Store(store.root)
    assert restarted.emit("crash-occurrence") == expected
    assert len(restarted.entries()) == 1
    callback.status = 503
    Worker(restarted, callback).once()
    first_body = callback.calls[-1][1]
    assert restarted.entries()[0]["attempts"] == 1
    with restarted.db() as db:
        db.execute("UPDATE outbox SET next_attempt=0")
    callback.status = 200
    Worker(Store(store.root), callback).once()
    assert callback.calls[-1][1] == first_body
    assert json.loads(first_body)["eventId"] == expected
    assert restarted.health()["accepted"] == 1


def test_default_bind(tmp_path):
    assert Settings(state_dir=tmp_path).bind == "127.0.0.1"
    with pytest.raises(ValueError):
        Settings(state_dir=tmp_path, bind="0.0.0.0")
    with pytest.raises(ValueError):
        Settings(
            state_dir=tmp_path,
            bind="0.0.0.0",
            exposure="public-https",
            auth_mode="local-test",
        )


def test_challenge_lifecycle(env):
    store, token, callback, client = env
    callback.wrong_challenge = True
    assert sub(client, token).json()["error"]["code"] == -32015
    assert store.health()["subscription"] == "none"
    callback.wrong_challenge = False
    key = secret()
    a = sub(client, token, key).json()["result"]
    b = sub(client, token, key).json()["result"]
    assert a["id"] == b["id"]
    assert a["cursor"] is None
    assert store.health()["subscription"] == "active"
    unknown = sub(client, token, key, extra="no")
    assert unknown.json()["error"]["code"] == -32602
    data = {
        "name": "xmsg.message.received.v1",
        "arguments": {},
        "delivery": {"mode": "webhook", "url": "https://different.example/"},
    }
    assert rpc(client, token, "events/unsubscribe", data).json() == {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {},
    }
    assert store.health()["subscription"] == "active"
    data["delivery"]["url"] = "https://callback.example/events"
    rpc(client, token, "events/unsubscribe", data)
    assert store.health()["subscription"] == "inactive"


def test_revocation_stops_delivery(env):
    store, token, callback, client = env
    sub(client, token)
    store.emit("revoke")
    store.revoke(token)
    before = len(callback.calls)
    Worker(store, callback).once()
    assert len(callback.calls) == before
    assert store.health()["pending"] == 1


@pytest.mark.parametrize("status", [410, 413, 302, 400, 503])
def test_dead_letter(env, status):
    store, token, callback, client = env
    sub(client, token)
    callback.status = status
    store.emit("failure")
    for _ in range(6):
        Worker(store, callback).once()
        with store.db() as db:
            db.execute("UPDATE outbox SET next_attempt=0")
    assert store.health()["dead"] == 1
    assert store.entries()[0]["attempts"] == (5 if status == 503 else 1)


def test_secret_encryption_and_rotation(env):
    store, token, callback, client = env
    key1, key2 = secret(), secret()
    sub(client, token, key1)
    sub(client, token, key2)
    store.emit("rotate")
    Worker(Store(store.root), callback).once()
    _, body, headers = callback.calls[-1]
    Webhook(key1).verify(body, headers)
    Webhook(key2).verify(body, headers)
    raw = (store.root / "state.sqlite3").read_bytes()
    assert (
        key1.encode() not in raw
        and key2.encode() not in raw
        and token.encode() not in raw
    )
    assert os.stat(store.root / "state.sqlite3").st_mode & 0o777 == 0o600
    assert os.stat(store.root / "key").st_mode & 0o777 == 0o600


def test_oauth_claims_and_revocation(tmp_path):
    from phase1.auth import OAuth

    settings = Settings(
        state_dir=tmp_path,
        issuer="https://issuer.example/",
        resource="https://resource.example/mcp",
        subject="owner-subject",
        introspection_url="https://issuer.example/introspect",
        client_id="fixture",
        client_secret_file=tmp_path / "secret",
    )
    settings.client_secret_file.write_text(secrets.token_urlsafe(32))

    class Issuer:
        claims = {
            "active": True,
            "iss": settings.issuer,
            "aud": settings.resource,
            "sub": settings.subject,
            "scope": "identity:read events:subscribe",
            "exp": time.time() + 300,
        }

        def post(self, *args):
            return 200, json.dumps(self.claims).encode()

    issuer = Issuer()
    auth = OAuth(settings, issuer)
    assert auth.validate("generated-token")
    for field, bad in [
        ("active", False),
        ("iss", "wrong"),
        ("aud", "wrong"),
        ("sub", "other"),
        ("scope", "openid"),
        ("exp", 0),
    ]:
        old = issuer.claims[field]
        issuer.claims[field] = bad
        assert not auth.validate("generated-token"), field
        issuer.claims[field] = old
    issuer.claims["active"] = False
    assert not auth.validate("generated-token")


def test_mcp_protocol(env):
    _, token, _, client = env
    init = rpc(
        client,
        token,
        "initialize",
        {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
    )
    assert init.json()["result"]["capabilities"] == {"tools": {}, "events": {}}
    tools = rpc(client, token, "tools/list").json()["result"]["tools"]
    assert [t["name"] for t in tools] == ["xmsg_identity"]
    assert tools[0]["inputSchema"]["additionalProperties"] is False
    events = rpc(client, token, "events/list").json()["result"]["events"]
    assert [e["name"] for e in events] == ["xmsg.message.received.v1"]
    assert events[0]["payloadSchema"]["additionalProperties"] is False
    assert (
        client.get("/mcp", headers={"Authorization": "Bearer " + token}).status_code
        == 405
    )
    assert rpc(client, token, "xmsg_send").json()["error"]["code"] == -32601


def test_verification_cache_and_expiry(env):
    store, token, callback, client = env
    key = secret()
    sub(client, token, key)
    first = len(callback.calls)
    sub(client, token, key)
    assert len(callback.calls) == first
    # Expired verification cannot authorize a later subscription without a challenge.
    with store.db() as db:
        db.execute("UPDATE subscription SET verified_until=0")
    sub(client, token, key)
    assert len(callback.calls) == first + 1
    with store.db() as db:
        db.execute("UPDATE subscription SET expires=0")
    store.emit("expired")
    before = len(callback.calls)
    Worker(store, callback).once()
    assert len(callback.calls) == before
    assert store.health()["subscription"] == "expired"


def test_binding_conflict(env):
    store, token, callback, client = env
    sub(client, token)
    response = rpc(
        client,
        token,
        "events/subscribe",
        {
            "name": "xmsg.message.received.v1",
            "arguments": {},
            "delivery": {
                "mode": "webhook",
                "url": "https://other.example/",
                "secret": secret(),
            },
        },
    )
    assert response.json()["error"]["code"] == -32602
    assert len(callback.calls) == 1
    assert store.health()["subscription"] == "active"


def test_oauth_http_and_delivery_revocation(tmp_path):
    from phase1.auth import OAuth

    store = Store(tmp_path / "state")
    key_file = tmp_path / "introspection-secret"
    key_file.write_text(secrets.token_urlsafe(32))
    settings = Settings(
        state_dir=store.root,
        issuer="https://issuer.example/",
        resource="https://resource.example/mcp",
        subject="owner-subject",
        introspection_url="https://issuer.example/introspect",
        client_id="fixture",
        client_secret_file=key_file,
    )
    token = secrets.token_urlsafe(48)

    class Issuer:
        active = True

        def post(self, url, body, headers):
            from urllib.parse import parse_qs

            active = self.active and parse_qs(body.decode())["token"] == [token]
            return 200, json.dumps(
                {
                    "active": active,
                    "iss": settings.issuer,
                    "aud": settings.resource,
                    "sub": settings.subject,
                    "scope": "identity:read events:subscribe",
                    "exp": time.time() + 60,
                }
            ).encode()

    issuer = Issuer()
    oauth = OAuth(settings, issuer)
    callback = Callback()
    client = TestClient(
        create_app(settings, store, callback, oauth), base_url="http://localhost"
    )
    for method in ("tools/list", "events/list"):
        assert rpc(client, None, method).status_code == 401
        assert rpc(client, "wrong-token", method).status_code == 401
        assert "result" in rpc(client, token, method).json()
    assert "result" in sub(client, token).json()
    store.emit("oauth-revocation")
    issuer.active = False
    for method in (
        "tools/list",
        "events/list",
        "events/subscribe",
        "events/unsubscribe",
    ):
        assert rpc(client, token, method).status_code == 401
    before = len(callback.calls)
    Worker(store, callback, oauth).once()
    assert len(callback.calls) == before
    assert store.health()["pending"] == 1


def test_limits_and_no_replay(env):
    _, token, _, client = env
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    assert client.post("/mcp", headers=headers, content=b" " * 65537).status_code == 413
    assert (
        sub(client, token, cursor="invented-position").json()["error"]["code"] == -32602
    )
    assert sub(client, token, ttlMs=0).json()["error"]["code"] == -32602
    assert sub(client, token, key="whsec_broken").json()["error"]["code"] == -32602
    assert (
        client.post(
            "/mcp",
            headers={**headers, "Origin": "https://attacker.example/"},
            content=b"{}",
        ).status_code
        == 403
    )


def test_attempt_reserved_before_callback(env):
    store, token, callback, client = env
    sub(client, token)
    store.emit("reserved-attempt")

    class Crash(BaseException):
        pass

    class FailAfterAttempt:
        def post(self, url, body, headers):
            assert store.entries()[0]["attempts"] == 1
            raise Crash()

    with pytest.raises(Crash):
        Worker(store, FailAfterAttempt()).once()
    assert store.entries()[0]["attempts"] == 1
    with store.db() as db:
        db.execute("UPDATE outbox SET next_attempt=0")
    Worker(store, callback).once()
    assert store.health()["accepted"] == 1


def test_public_exposure_requires_oauth(tmp_path):
    settings = Settings(
        state_dir=tmp_path,
        bind="0.0.0.0",
        exposure="public-https",
        public_url="https://resource.example/mcp",
    )
    assert settings.auth_mode == "oauth"
    with pytest.raises(ValueError):
        create_app(settings)


def test_local_server_cli_and_socket(tmp_path):
    import socket
    from pathlib import Path

    config = tmp_path / "local.toml"
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    config.write_text(f'auth_mode = "local-test"\nport = {port}\n')
    state = tmp_path / "state"
    output = tmp_path / "test-token"
    issue = subprocess.run(
        [
            sys.executable,
            "-m",
            "phase1.cli",
            "--config",
            str(config),
            "--state",
            str(state),
            "issue-local-test",
            "--output",
            str(output),
        ],
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert issue.returncode == 0
    assert output.read_bytes().strip() not in issue.stdout + issue.stderr
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "phase1.cli",
            "--config",
            str(config),
            "--state",
            str(state),
            "serve",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                assert process.poll() is None
                time.sleep(0.05)
        else:
            pytest.fail("server did not start")
        inodes = set()
        for fd in Path(f"/proc/{process.pid}/fd").iterdir():
            try:
                target = os.readlink(fd)
                if target.startswith("socket:["):
                    inodes.add(target[8:-1])
            except FileNotFoundError:
                pass
        listeners = [
            line.split()[1]
            for line in Path(f"/proc/{process.pid}/net/tcp")
            .read_text()
            .splitlines()[1:]
            if line.split()[9] in inodes and line.split()[3] == "0A"
        ]
        assert listeners == [f"0100007F:{port:04X}"]
        import httpx

        response = httpx.post(
            f"http://127.0.0.1:{port}/mcp",
            headers={"Authorization": "Bearer " + output.read_text().strip()},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            timeout=3,
        )
        assert response.status_code == 200 and "result" in response.json()
    finally:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
        assert output.read_bytes().strip() not in stdout + stderr


def test_oauth_subscription_not_beyond_token(env):
    from phase1.auth import OAuth

    store, _, callback, _ = env
    key_file = store.root / "fixture-client-secret"
    key_file.write_text(secrets.token_urlsafe(32))
    settings = Settings(
        state_dir=store.root,
        issuer="https://issuer.example/",
        resource="https://resource.example/mcp",
        subject="owner-subject",
        introspection_url="https://issuer.example/introspect",
        client_id="fixture",
        client_secret_file=key_file,
    )
    expiry = time.time() + 30

    class Issuer:
        def post(self, *args):
            return 200, json.dumps(
                {
                    "active": True,
                    "iss": settings.issuer,
                    "aud": settings.resource,
                    "sub": settings.subject,
                    "scope": "identity:read events:subscribe",
                    "exp": expiry,
                }
            ).encode()

    client = TestClient(
        create_app(settings, store, callback, OAuth(settings, Issuer())),
        base_url="http://localhost",
    )
    result = sub(client, secrets.token_urlsafe(48)).json()["result"]
    from datetime import datetime

    assert datetime.fromisoformat(result["refreshBefore"]).timestamp() <= expiry


@pytest.mark.parametrize(
    "headers", [{"Origin": "null"}, {"Host": ""}, {"Host": "attacker.example"}]
)
def test_invalid_origin_host(env, headers):
    _, token, _, client = env
    response = client.post(
        "/mcp",
        headers={"Authorization": "Bearer " + token, **headers},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    "method",
    [
        "initialize",
        "ping",
        "tools/list",
        "tools/call",
        "events/list",
        "events/subscribe",
        "events/unsubscribe",
    ],
)
@pytest.mark.parametrize("progress_token", ["progress-one", 42])
def test_protocol_metadata_accepted(env, method, progress_token):
    _, token, _, client = env
    params = {
        "_meta": {
            "progressToken": progress_token,
            "com.example/trace": {"value": "fixture"},
        }
    }
    if method == "initialize":
        params.update(
            protocolVersion="2025-03-26",
            capabilities={},
            clientInfo={"name": "fixture", "version": "1"},
        )
    elif method == "tools/call":
        params.update(name="xmsg_identity", arguments={})
    elif method in ("events/subscribe", "events/unsubscribe"):
        params.update(
            name="xmsg.message.received.v1",
            arguments={},
            delivery={"mode": "webhook", "url": "https://callback.example/events"},
        )
        if method == "events/subscribe":
            params["delivery"]["secret"] = secret()
    response = rpc(client, token, method, params)
    assert response.status_code == 200
    assert "result" in response.json()


def test_metadata_does_not_select_sender_or_loosen_arguments(env):
    _, token, _, client = env
    metadata = {"progressToken": "test", "from": "attacker", "mailbox": "other"}
    response = rpc(
        client,
        token,
        "tools/call",
        {"name": "xmsg_identity", "arguments": {}, "_meta": metadata},
    )
    assert (
        response.json()["result"]["structuredContent"]["identity"]
        == "dot@phase1-synthetic"
    )
    for arguments in ({"_meta": metadata}, {"from": "attacker"}):
        rejected = rpc(
            client,
            token,
            "tools/call",
            {"name": "xmsg_identity", "arguments": arguments, "_meta": metadata},
        )
        assert rejected.json()["error"]["code"] == -32602
    rejected = sub(client, token, _meta=metadata, from_sender="attacker")
    assert rejected.json()["error"]["code"] == -32602
    rejected = rpc(
        client,
        token,
        "events/subscribe",
        {
            "name": "xmsg.message.received.v1",
            "arguments": {"_meta": metadata},
            "_meta": metadata,
            "delivery": {
                "mode": "webhook",
                "url": "https://callback.example/events",
                "secret": secret(),
            },
        },
    )
    assert rejected.json()["error"]["code"] == -32602


@pytest.mark.parametrize(
    "metadata",
    [
        "string",
        [],
        None,
        {"progressToken": None},
        {"progressToken": True},
        {"progressToken": 1.5},
    ],
)
def test_invalid_protocol_metadata(env, metadata):
    _, token, _, client = env
    response = rpc(client, token, "ping", {"_meta": metadata})
    assert response.json()["error"]["code"] == -32602


def test_metadata_not_part_of_subscription_identity(env):
    _, token, callback, client = env
    key = secret()
    first = sub(client, token, key, _meta={"progressToken": "one"}).json()["result"]
    second = sub(client, token, key, _meta={"progressToken": "two"}).json()["result"]
    assert first["id"] == second["id"]
    assert len(callback.calls) == 1
