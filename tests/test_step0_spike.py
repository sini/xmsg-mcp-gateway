"""Throwaway Step 0 probe; no xmsg connection or hosted credentials."""

import base64
import importlib.util
import json
import secrets
import socket
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

from phase1.auth import OAuth
from phase1.config import Settings
from phase1.store import Store
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
