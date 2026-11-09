"""Throwaway Step 0 probe; no xmsg connection or hosted credentials."""

import base64
import importlib.util
import json
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
import uvicorn
from pydantic import ValidationError
from standardwebhooks import Webhook
from standardwebhooks.webhooks import WebhookVerificationError
from starlette.testclient import TestClient

import phase1.events
from phase1.auth import OAuth
from phase1.config import Settings
from phase1.store import Store
from phase1.transport import signed_post
from phase1.worker import Worker

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "step0_spike.py"
CALLBACK = "https://callback.example/events"


def example():
    spec = importlib.util.spec_from_file_location("step0_spike", EXAMPLE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_example_requires_explicit_bearer_opt_in(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text(
        f'auth_mode = "bearer"\nstate_dir = "{tmp_path / "state"}"\n'
        'exposure = "public-https"\npublic_url = "https://mcp.example/mcp"\n'
    )
    output = tmp_path / "credential"
    command = [
        sys.executable,
        str(EXAMPLE),
        "--config",
        str(config),
        "issue-bearer",
        "--output",
        str(output),
    ]
    refused = subprocess.run(command, capture_output=True, timeout=10)
    assert refused.returncode != 0
    assert not output.exists()
    allowed = subprocess.run(
        command[:4] + ["--allow-bearer"] + command[4:],
        capture_output=True,
        timeout=10,
    )
    assert allowed.returncode == 0, allowed.stderr.decode()
    assert output.stat().st_mode & 0o077 == 0
    assert output.read_text().strip()
    assert not allowed.stdout and not allowed.stderr


def test_local_test_profile_stays_loopback_only():
    with pytest.raises(ValidationError):
        Settings(
            auth_mode="local-test",
            exposure="public-https",
            public_url="https://mcp.example/mcp",
        )


def ingress_probe(tmp_path, monkeypatch, http=None):
    # Isolate the inherited example's global tracing while measuring its replacement.
    monkeypatch.setattr(phase1.events, "signed_post", signed_post)
    spike = example()
    store = Store(tmp_path / "state")
    token = store.issue()
    settings = spike.SpikeSettings(state_dir=store.root, auth_mode="bearer")
    app = spike.create_spike(
        settings, allow_bearer=True, ingress_token=token, store=store, http=http
    )
    return TestClient(app, base_url="http://127.0.0.1"), store, token


def post_rpc(client, method, params=None, **kwargs):
    return client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        **kwargs,
    )


def test_no_auth_ingress_uses_issued_credential_and_preserves_wrong_bearer_401(
    tmp_path, monkeypatch
):
    client, store, token = ingress_probe(tmp_path, monkeypatch)
    original = store.authenticate
    checked = []

    def authenticate(value, oauth):
        checked.append(value)
        return original(value, oauth)

    monkeypatch.setattr(store, "authenticate", authenticate)
    with client:
        response = post_rpc(
            client, "tools/call", {"name": "xmsg_identity", "arguments": {}}
        )
        assert response.status_code == 200
        assert (
            response.json()["result"]["structuredContent"]["identity"]
            == "dot@phase1-synthetic"
        )
        assert checked == [token], (
            "phase1 must authenticate the injected issued credential"
        )
        assert (
            post_rpc(
                client, "ping", headers={"Authorization": "Bearer wrong"}
            ).status_code
            == 401
        )
        assert checked[-1] == "wrong", "an explicit credential must never be replaced"
        store.revoke(token)
        assert post_rpc(client, "ping").status_code == 401


@pytest.mark.parametrize("mode,bind", [("oauth", "127.0.0.1"), ("bearer", "::1")])
def test_no_auth_ingress_requires_bearer_and_ipv4_loopback(tmp_path, mode, bind):
    spike = example()
    settings = spike.SpikeSettings(state_dir=tmp_path, auth_mode=mode, bind=bind)
    with pytest.raises(ValueError, match="requires bearer mode on 127.0.0.1"):
        spike.create_spike(
            settings, allow_bearer=True, ingress_token="fixture-issued-token"
        )


def test_no_auth_ingress_tracing_does_not_replace_reference_signer(
    tmp_path, monkeypatch
):
    original = phase1.events.signed_post
    client, _store, _token = ingress_probe(tmp_path, monkeypatch)
    with client:
        assert phase1.events.signed_post is original


def test_no_auth_ingress_lists_noauth_tools_only_for_credentialless_arm(
    tmp_path, monkeypatch
):
    client, _store, token = ingress_probe(tmp_path, monkeypatch)
    with client:
        tools = post_rpc(client, "tools/list").json()["result"]["tools"]
        assert tools and all(
            t["securitySchemes"] == [{"type": "noauth"}] for t in tools
        )
        secured = post_rpc(
            client, "tools/list", headers={"Authorization": "Bearer " + token}
        )
        assert (
            secured.json()["result"]["tools"][0]["securitySchemes"][0]["type"]
            == "oauth2"
        )


def test_no_auth_ingress_malformed_subscription_records_shapes_not_values(
    tmp_path, monkeypatch
):
    client, store, _token = ingress_probe(tmp_path, monkeypatch)
    key = "whsec_" + base64.b64encode(secrets.token_bytes(32)).decode()
    url = "https://callback-canary.example/private-path?private=value"
    cursor = "private-cursor-value"
    with client:
        response = post_rpc(
            client,
            "events/subscribe",
            {
                "name": "xmsg.message.received.v1",
                "arguments": {},
                "delivery": {"mode": "webhook", "url": url, "secret": key},
                "cursor": cursor,
            },
        )
        assert response.json()["error"]["code"] == -32602
    file = store.root / "step0-diagnostics.jsonl"
    raw = file.read_text()
    record = json.loads(raw.splitlines()[-1])
    assert record["params"]["delivery"] == {
        "mode": "str",
        "url": "str",
        "secret": "str",
    }
    assert record["params"]["cursor"] == "str"
    assert record["error"]["code"] == -32602
    assert not record.get("callback"), "malformed subscriptions must record shape only"
    for private in (url, "callback-canary", "private-path", key, cursor):
        assert private not in raw
    assert file.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize(
    "failure,step",
    [
        ("refused", "http_status"),
        ("tls", "tls"),
        ("json", "response_json"),
        ("challenge", "challenge_echo"),
    ],
)
def test_no_auth_ingress_callback_diagnostics_name_failing_step_without_content(
    tmp_path, monkeypatch, failure, step
):
    canary = "private-callback-content"

    class CallbackFailure:
        def post(self, url, body, headers):
            if failure == "tls":
                raise ssl.SSLCertVerificationError(f"{url} {canary}")
            if failure == "refused":
                return 403, canary.encode()
            if failure == "json":
                return 200, canary.encode()
            return 200, json.dumps({"challenge": canary}).encode()

    client, store, _token = ingress_probe(tmp_path, monkeypatch, CallbackFailure())
    key = "whsec_" + base64.b64encode(secrets.token_bytes(32)).decode()
    with client:
        result = post_rpc(
            client,
            "events/subscribe",
            {
                "name": "xmsg.message.received.v1",
                "arguments": {},
                "delivery": {"mode": "webhook", "url": CALLBACK, "secret": key},
                "cursor": None,
            },
        ).json()
        assert result["error"]["data"]["reason"] == "challenge_failed"
    raw = (store.root / "step0-diagnostics.jsonl").read_text()
    records = [json.loads(line) for line in raw.splitlines()]
    assert any(
        r.get("step") == "callback_post" and r.get("failed_step") == step
        for r in records
    )
    assert canary not in raw and key not in raw and CALLBACK not in raw


@contextmanager
def mcp_server(app):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                log_level="critical",
                access_log=False,
            )
        )
        thread = threading.Thread(
            target=server.run, kwargs={"sockets": [listener]}, daemon=True
        )
        thread.start()
        deadline = time.monotonic() + 5
        try:
            while not server.started:
                assert thread.is_alive() and time.monotonic() < deadline, (
                    "MCP startup timed out"
                )
                time.sleep(0.01)
            yield f"http://127.0.0.1:{listener.getsockname()[1]}"
        finally:
            server.should_exit = True
            thread.join(5)
            assert not thread.is_alive(), "MCP server did not stop"


@contextmanager
def callback_server(key):
    received = []
    refused = []

    class Callback(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            headers = dict(self.headers)
            try:
                data = Webhook(key).verify(body, headers)
            except WebhookVerificationError:
                refused.append(body)
                self.send_response(401)
                self.end_headers()
                return
            received.append((data, body, headers))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"challenge": data.get("challenge")}).encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Callback)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/events", received, refused
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
        assert not thread.is_alive(), "callback server did not stop"


class FixtureTransport:
    """Route only the fixture's callback; never installed by the example."""

    def __init__(self, local_callback, token):
        self.local_callback = local_callback
        self.token = token

    def post(self, url, body, headers):
        if url == "https://auth.example/introspect":
            token = parse_qs(body.decode())["token"][0]
            claims = {
                "active": token == self.token,
                "iss": "https://auth.example/",
                "aud": "https://mcp.example/mcp",
                "sub": "step0-owner",
                "exp": int(time.time()) + 3600,
                "scope": "identity:read events:subscribe",
            }
            return 200, json.dumps(claims).encode()
        assert url == CALLBACK
        response = httpx.post(
            self.local_callback, content=body, headers=headers, timeout=5
        )
        return response.status_code, response.content


@pytest.mark.parametrize("auth_mode", ["bearer", "oauth"])
def test_step0_mcp_to_signed_callback(tmp_path, auth_mode):
    spike = example()
    key = "whsec_" + base64.b64encode(secrets.token_bytes(32)).decode()
    store = Store(tmp_path / "state")
    token = store.issue() if auth_mode == "bearer" else secrets.token_urlsafe(32)
    client_secret = tmp_path / "provider-secret"
    client_secret.write_text(secrets.token_urlsafe(32))
    settings = spike.SpikeSettings(
        state_dir=store.root,
        auth_mode=auth_mode,
        issuer="https://auth.example/",
        resource="https://mcp.example/mcp",
        subject="step0-owner",
        introspection_url="https://auth.example/introspect",
        client_id="step0-probe",
        client_secret_file=client_secret,
    )
    with callback_server(key) as (callback, received, refused):
        transport = FixtureTransport(callback, token)
        oauth = OAuth(settings, transport) if auth_mode == "oauth" else None
        app = spike.create_spike(
            settings,
            allow_bearer=auth_mode == "bearer",
            store=store,
            http=transport,
            oauth=oauth,
        )
        with mcp_server(app) as base, httpx.Client(base_url=base, timeout=5) as client:
            assert client.post("/mcp", json={}).status_code == 401
            assert (
                client.post(
                    "/mcp", json={}, headers={"Authorization": "Bearer invalid"}
                ).status_code
                == 401
            )

            def rpc(method, params=None):
                response = client.post(
                    "/mcp",
                    headers={
                        "Authorization": "Bearer " + token,
                        "mcp-protocol-version": "2025-11-25",
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": method,
                        "params": params or {},
                    },
                )
                assert response.status_code == 200
                data = response.json()
                assert "error" not in data, data
                return data["result"]

            initialized = rpc(
                "initialize",
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "step0-fixture", "version": "0"},
                },
            )
            assert initialized["capabilities"]["events"] == {}
            assert [tool["name"] for tool in rpc("tools/list")["tools"]] == [
                "xmsg_identity"
            ]
            identity = rpc("tools/call", {"name": "xmsg_identity", "arguments": {}})
            assert identity["structuredContent"]["identity"] == "dot@phase1-synthetic"
            assert [event["name"] for event in rpc("events/list")["events"]] == [
                "xmsg.message.received.v1"
            ]
            subscription = rpc(
                "events/subscribe",
                {
                    "name": "xmsg.message.received.v1",
                    "arguments": {},
                    "delivery": {"mode": "webhook", "url": CALLBACK, "secret": key},
                },
            )
            with store.db() as db:
                recorded = db.execute("SELECT * FROM subscription").fetchone()
                assert recorded["url"] == CALLBACK
                assert recorded["id"] == subscription["id"]
            assert received[0][0]["type"] == "verification"
            event_id = store.emit("step0-one")
            assert Worker(store, transport, oauth).once()
            accepted_count = len(received)
            assert accepted_count == 2, (
                "callback must accept the signed synthetic event"
            )
            event, body, headers = received[-1]
            assert event["eventId"] == headers["webhook-id"] == event_id
            assert event["name"] == "xmsg.message.received.v1"
            assert event["data"]["origin"] == {
                "id": "synthetic",
                "node": "phase1-synthetic",
            }
            assert event["data"]["body_available"] is False
            assert store.health()["accepted"] == 1
            tampered_body = body.replace(b"phase 1", b"phase 2")
            assert tampered_body != body
            tampered = httpx.post(
                callback, content=tampered_body, headers=headers, timeout=5
            )
            assert tampered.status_code == 401
            assert len(received) == 2 and len(refused) == 1
