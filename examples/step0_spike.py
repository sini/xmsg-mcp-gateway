"""Throwaway hosted-integration probe. Synthetic events only; never connects to xmsg."""

import argparse
import json
import os
import sys
import tomllib
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import uvicorn

import phase1.events
from phase1.app import create_app
from phase1.config import Settings
from phase1.store import Store


class SpikeSettings(Settings):
    # The shipped local-test profile keeps its original loopback-only constraint.
    auth_mode: Literal["oauth", "bearer"] = "oauth"


def require_bearer_opt_in(settings, allow_bearer):
    if settings.auth_mode == "bearer" and not allow_bearer:
        raise ValueError("example bearer mode requires --allow-bearer")


def create_spike(settings, *, allow_bearer=False, ingress_token=None, **kwargs):
    require_bearer_opt_in(settings, allow_bearer)
    app = create_app(settings, **kwargs)
    if ingress_token is None:
        return app
    if settings.auth_mode != "bearer" or settings.bind != "127.0.0.1":
        raise ValueError("--no-auth-ingress requires bearer mode on 127.0.0.1")
    header = b"Bearer " + ingress_token.encode()

    diagnostics = Path(settings.state_dir) / "step0-diagnostics.jsonl"

    def note(record):
        fd = os.open(diagnostics, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "a") as stream:
            stream.write(json.dumps(record) + "\n")

    # phase1 reports every verification failure as challenge_failed; record which step failed.
    original_post = phase1.events.signed_post

    def traced_post(http, url, body, event_id, subscription_id, keys):
        record = {"step": "callback_post", "kind": event_id.split("_")[0]}
        try:
            status, raw = original_post(
                http, url, body, event_id, subscription_id, keys
            )
        except Exception as exc:
            record["raised"] = f"{type(exc).__name__}: {exc}"[:200]
            note(record)
            raise
        record["status"] = status
        try:
            reply = json.loads(raw)
            record["reply"] = (
                shape(reply) if isinstance(reply, dict) else type(reply).__name__
            )
            if isinstance(reply, dict) and record["kind"] == "verification":
                record["challenge_echoed"] = json.loads(body).get(
                    "challenge"
                ) == reply.get("challenge")
        except ValueError:
            record["reply"] = f"non-json, {len(raw)} bytes"
        note(record)
        return status, raw

    phase1.events.signed_post = traced_post

    def shape(value):
        # Field names and types only; values (callback URL, secret, cursor) never leave the process.
        if isinstance(value, dict):
            return {k: shape(v) for k, v in value.items()}
        return type(value).__name__

    def diagnose(request, send):
        params = (
            request.get("params") if isinstance(request.get("params"), dict) else {}
        )
        delivery = (
            params.get("delivery") if isinstance(params.get("delivery"), dict) else {}
        )
        url = (
            urlsplit(delivery["url"]) if isinstance(delivery.get("url"), str) else None
        )
        record = {
            "method": request.get("method"),
            "params": shape(params),
            "callback": f"{url.scheme}://{url.hostname}" if url else None,
        }
        chunks = []

        async def capture(message):
            if message["type"] == "http.response.body":
                chunks.append(message.get("body", b""))
                if not message.get("more_body", False):
                    try:
                        reply = json.loads(b"".join(chunks))
                        err = reply.get("error") or {}
                        record["result"] = "error" if err else "ok"
                        record["error"] = (
                            {k: err.get(k) for k in ("code", "message", "data")}
                            if err
                            else None
                        )
                    except ValueError:
                        record["result"] = "unparseable"
                    fd = os.open(
                        diagnostics, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600
                    )
                    with os.fdopen(fd, "a") as stream:
                        stream.write(json.dumps(record) + "\n")
            await send(message)

        return capture

    # "No Authentication" connections (the hosted form's only non-OAuth choice) carry no credential:
    # supply the probe's own issued token, so phase1 still authenticates every request.
    async def inject(scope, receive, send):
        if scope["type"] != "http" or any(
            k == b"authorization" for k, _ in scope["headers"]
        ):
            await app(scope, receive, send)
            return
        scope = dict(scope, headers=[*scope["headers"], (b"authorization", header)])
        body, more = b"", True
        while more:
            message = await receive()
            body += message.get("body", b"")
            more = message.get("more_body", False)
        replayed = False

        async def replay():
            nonlocal replayed
            if replayed:
                return await receive()
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}

        try:
            request = json.loads(body)
            method = request.get("method")
        except (ValueError, AttributeError):
            request, method = {}, None
        if method in ("events/subscribe", "events/unsubscribe", "server/discover"):
            await app(scope, replay, diagnose(request, send))
            return
        if method != "tools/list":
            await app(scope, replay, send)
            return
        # A no-auth connection is rejected while a tool still declares an OAuth2 security scheme.
        start, chunks = None, []

        async def rewrite(message):
            nonlocal start
            if message["type"] == "http.response.start":
                start = message
                return
            chunks.append(message.get("body", b""))
            if message.get("more_body", False):
                return
            payload = b"".join(chunks)
            try:
                data = json.loads(payload)
                for tool in data["result"]["tools"]:
                    tool["securitySchemes"] = [{"type": "noauth"}]
                payload = json.dumps(data).encode()
            except (ValueError, KeyError, TypeError):
                pass
            headers = [
                (k, str(len(payload)).encode() if k == b"content-length" else v)
                for k, v in start["headers"]
            ]
            await send(dict(start, headers=headers))
            await send({"type": "http.response.body", "body": payload})

        await app(scope, replay, rewrite)

    return inject


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--allow-bearer",
        action="store_true",
        help="explicitly enable bearer authentication for this throwaway probe",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    issue = commands.add_parser("issue-bearer")
    issue.add_argument("--output", type=Path, required=True)
    emit = commands.add_parser("emit")
    emit.add_argument("occurrence_id")
    serve = commands.add_parser("serve")
    serve.add_argument(
        "--no-auth-ingress",
        type=Path,
        metavar="TOKEN_FILE",
        help="accept credential-less requests as this issued bearer token (loopback bearer probe only)",
    )
    args = parser.parse_args()
    settings = SpikeSettings(**tomllib.loads(args.config.read_text()))
    require_bearer_opt_in(settings, args.allow_bearer)
    if args.command == "issue-bearer" and settings.auth_mode != "bearer":
        raise ValueError("issue-bearer requires example bearer mode")
    store = Store(settings.state_dir)
    if args.command == "issue-bearer":
        fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(store.issue() + "\n")
    elif args.command == "emit":
        print(store.emit(args.occurrence_id))
    else:
        ingress = args.no_auth_ingress
        uvicorn.run(
            create_spike(
                settings,
                allow_bearer=args.allow_bearer,
                ingress_token=ingress.read_text().strip() if ingress else None,
                store=store,
                run_worker=True,
            ),
            host=settings.bind,
            port=settings.port,
            access_log=False,
            log_level="critical",
        )


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError):
        print(
            "Invalid spike configuration or local state; check settings locally.",
            file=sys.stderr,
        )
        sys.exit(1)
