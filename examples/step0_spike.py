"""Throwaway hosted-integration probe. Synthetic events only; never connects to xmsg."""

import argparse
import json
import os
import ssl
import sys
import tomllib
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import uvicorn

from phase1.app import MAX_REQUEST, create_app
from phase1.config import Settings
from phase1.store import Store
from phase1.transport import HTTPS, DestinationError


class SpikeSettings(Settings):
    # The shipped local-test profile keeps its original loopback-only constraint.
    auth_mode: Literal["oauth", "bearer"] = "oauth"


def require_bearer_opt_in(settings, allow_bearer):
    if settings.auth_mode == "bearer" and not allow_bearer:
        raise ValueError("example bearer mode requires --allow-bearer")


def create_spike(settings, *, allow_bearer=False, ingress_token=None, **kwargs):
    require_bearer_opt_in(settings, allow_bearer)
    if ingress_token is None:
        return create_app(settings, **kwargs)
    if settings.auth_mode != "bearer" or settings.bind != "127.0.0.1":
        raise ValueError("--no-auth-ingress requires bearer mode on 127.0.0.1")
    header = b"Bearer " + ingress_token.encode()
    diagnostics = Path(settings.state_dir) / "step0-diagnostics.jsonl"
    fields = {
        "name",
        "arguments",
        "delivery",
        "mode",
        "url",
        "secret",
        "cursor",
        "ttlMs",
        "_meta",
        "progressToken",
        "challenge",
    }

    def shape(value):
        if isinstance(value, dict):
            result = {k: shape(v) for k, v in value.items() if k in fields}
            unknown = sum(k not in fields for k in value)
            if unknown:
                result["other_fields"] = unknown
            return result
        return type(value).__name__

    def note(record):
        fd = os.open(diagnostics, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "a") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(json.dumps(record) + "\n")

    class TracedHTTP:
        def __init__(self, http):
            self.http = http

        def post(self, url, body, headers):
            verification = json.loads(body).get("type") == "verification"
            record = {
                "step": "callback_post",
                "kind": "verification" if verification else "event",
            }
            try:
                parsed = urlsplit(url)
                record["callback"] = f"{parsed.scheme}://{parsed.hostname}"
            except ValueError:
                record["callback"] = None
            try:
                status, raw = self.http.post(url, body, headers)
            except Exception as exc:
                record["failed_step"] = (
                    "tls"
                    if isinstance(exc, ssl.SSLError)
                    else "destination"
                    if isinstance(exc, DestinationError)
                    else "timeout"
                    if isinstance(exc, TimeoutError)
                    else "transport"
                )
                # Exceptions can contain the full callback, signing secret or response body.
                record["exception_type"] = type(exc).__name__
                note(record)
                raise
            record["status"] = status
            if not 200 <= status < 300:
                record["failed_step"] = "http_status"
            elif verification:
                try:
                    reply = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    record["failed_step"] = "response_json"
                else:
                    record["reply"] = shape(reply)
                    if not isinstance(reply, dict):
                        record["failed_step"] = "response_shape"
                    else:
                        echoed = json.loads(body).get("challenge") == reply.get(
                            "challenge"
                        )
                        record["challenge_echoed"] = echoed
                        if not echoed:
                            record["failed_step"] = "challenge_echo"
            note(record)
            return status, raw

    # Tracing stays local to this example app; phase1's signer and authentication are unchanged.
    http = TracedHTTP(kwargs.pop("http", None) or HTTPS())
    app = create_app(settings, http=http, **kwargs)

    async def inject(scope, receive, send):
        if scope["type"] != "http" or any(
            k == b"authorization" for k, _ in scope["headers"]
        ):
            await app(scope, receive, send)
            return
        scope = dict(scope, headers=[*scope["headers"], (b"authorization", header)])
        body = bytearray()

        async def capture_request():
            message = await receive()
            if message["type"] == "http.request":
                body.extend(
                    message.get("body", b"")[: max(0, MAX_REQUEST + 1 - len(body))]
                )
            return message

        start, chunks = None, []

        async def capture_response(message):
            nonlocal start
            if message["type"] == "http.response.start":
                start = message
                return
            if message["type"] != "http.response.body":
                await send(message)
                return
            chunks.append(message.get("body", b""))
            if message.get("more_body", False):
                return
            payload = b"".join(chunks)
            try:
                request, reply = json.loads(body), json.loads(payload)
            except (ValueError, UnicodeDecodeError):
                request, reply = {}, {}
            method = request.get("method") if isinstance(request, dict) else None
            if method in ("events/subscribe", "events/unsubscribe", "server/discover"):
                record = {"method": method, "params": shape(request.get("params", {}))}
                err = reply.get("error") if isinstance(reply, dict) else None
                record["result"] = "error" if err else "ok"
                if isinstance(err, dict):
                    messages = {
                        "Invalid Request",
                        "Invalid params",
                        "Method not found",
                        "Callback endpoint verification failed",
                        "Access revoked",
                        "Internal error",
                    }
                    record["error"] = {
                        "code": err.get("code")
                        if type(err.get("code")) is int
                        else None,
                        "message": err.get("message")
                        if err.get("message") in messages
                        else "other",
                    }
                    if err.get("code") == -32015:
                        record["failed_step"] = "verification"
                note(record)
            if method == "tools/list" and start["status"] == 200:
                try:
                    for tool in reply["result"]["tools"]:
                        tool["securitySchemes"] = [{"type": "noauth"}]
                    payload = json.dumps(reply).encode()
                except (KeyError, TypeError):
                    pass
            headers = [
                (k, str(len(payload)).encode() if k == b"content-length" else v)
                for k, v in start["headers"]
            ]
            await send(dict(start, headers=headers))
            await send({"type": "http.response.body", "body": payload})

        # The form's credential-less arm still goes through phase1's issued-token verifier.
        await app(scope, capture_request, capture_response)

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
