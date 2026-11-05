import json
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import anyio
from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .auth import PRINCIPAL, SCOPES, OAuth
from .events import CallbackError, subscribe, unsubscribe
from .schemas import (
    EVENT,
    PAYLOAD,
    RPC,
    Call,
    Empty,
    Initialize,
    ListEvents,
    Subscribe,
    Unsubscribe,
)
from .store import MAX_OUTBOX, Store
from .transport import HTTPS
from .worker import Worker

MAX_REQUEST = 65536


def error(code, message, identifier=None, reason=None):
    value = {"code": code, "message": message}
    if reason:
        value["data"] = {"reason": reason}
    return {"jsonrpc": "2.0", "id": identifier, "error": value}


def create_app(settings, store=None, http=None, oauth=None, run_worker=False):
    store = store or Store(settings.state_dir)
    http = http or HTTPS()
    if settings.auth_mode == "oauth":
        oauth = oauth or OAuth(settings)

    def dispatch(body, credential):
        try:
            request = RPC.model_validate(body)
        except ValidationError:
            return error(-32600, "Invalid Request")
        identifier = request.id
        try:
            match request.method:
                case "initialize":
                    init = Initialize.model_validate(request.params)
                    if init.protocolVersion not in (
                        "2025-03-26",
                        "2025-06-18",
                        "2025-11-25",
                    ):
                        raise ValueError("unsupported protocol version")
                    result = {
                        "protocolVersion": init.protocolVersion,
                        "capabilities": {"tools": {}, "events": {}},
                        "serverInfo": {
                            "name": "xmsg-mcp-gateway",
                            "version": "0.1.0",
                        },
                    }
                case "notifications/initialized":
                    Empty.model_validate(request.params)
                    return None
                case "ping":
                    Empty.model_validate(request.params)
                    result = {}
                case "tools/list":
                    Empty.model_validate(request.params)
                    result = {
                        "tools": [
                            {
                                "name": "xmsg_identity",
                                "description": "Read synthetic identity and subscription delivery health.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {},
                                    "additionalProperties": False,
                                },
                                "annotations": {
                                    "readOnlyHint": True,
                                    "destructiveHint": False,
                                    "openWorldHint": False,
                                },
                                "securitySchemes": [
                                    {"type": "oauth2", "scopes": SCOPES}
                                ],
                            }
                        ]
                    }
                case "tools/call":
                    Call.model_validate(request.params)
                    data = {
                        "identity": PRINCIPAL,
                        "scopes": SCOPES,
                        "limits": {
                            "max_request_bytes": MAX_REQUEST,
                            "max_event_bytes": 262144,
                            "max_outbox_entries": MAX_OUTBOX,
                            "max_delivery_attempts": 5,
                        },
                        "subscription_health": store.health(),
                    }
                    result = {
                        "content": [{"type": "text", "text": json.dumps(data)}],
                        "structuredContent": data,
                        "isError": False,
                    }
                case "events/list":
                    ListEvents.model_validate(request.params)
                    result = {
                        "events": [
                            {
                                "name": EVENT,
                                "description": "One synthetic message to this authenticated principal.",
                                "delivery": ["webhook"],
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {},
                                    "additionalProperties": False,
                                },
                                "payloadSchema": PAYLOAD,
                            }
                        ]
                    }
                case "events/subscribe":
                    result = subscribe(
                        store,
                        credential,
                        Subscribe.model_validate(request.params),
                        http,
                        oauth,
                    )
                case "events/unsubscribe":
                    result = unsubscribe(
                        store,
                        credential,
                        Unsubscribe.model_validate(request.params),
                        oauth,
                    )
                case _:
                    return error(-32601, "Method not found", identifier)
            return {"jsonrpc": "2.0", "id": identifier, "result": result}
        except CallbackError:
            return error(
                -32015,
                "Callback endpoint verification failed",
                identifier,
                "challenge_failed",
            )
        except (ValidationError, ValueError):
            return error(-32602, "Invalid params", identifier)
        except PermissionError:
            return error(-32001, "Access revoked", identifier)

    async def endpoint(request: Request):
        try:
            host = urlsplit("//" + request.headers.get("host", "")).hostname
            origin = request.headers.get("origin")
            origin_host = urlsplit(origin).hostname if origin else None
        except ValueError:
            return Response(status_code=403)
        allowed = {
            "localhost",
            "127.0.0.1",
            "::1",
            urlsplit(settings.resource or "").hostname,
            urlsplit(settings.public_url or "").hostname,
        }
        allowed.discard(None)
        if host not in allowed:
            return Response(status_code=403)
        if origin and origin_host not in allowed:
            return Response(status_code=403)
        header = request.headers.get("authorization", "")
        token = (
            header[7:] if header.startswith("Bearer ") and len(header) <= 8192 else ""
        )
        credential = (
            await run_in_threadpool(store.authenticate, token, oauth) if token else None
        )
        if not credential:
            challenge = "Bearer"
            if settings.resource:
                challenge += (
                    ' resource_metadata="'
                    + settings.resource.rstrip("/")
                    + '/.well-known/oauth-protected-resource"'
                )
            return Response(status_code=401, headers={"WWW-Authenticate": challenge})
        if request.method != "POST":
            return Response(status_code=405, headers={"Allow": "POST"})
        if request.headers.get("content-type", "").split(";")[0] != "application/json":
            return Response(status_code=415)
        protocol = request.headers.get("mcp-protocol-version")
        if protocol and protocol not in ("2025-03-26", "2025-06-18", "2025-11-25"):
            return Response(status_code=400)
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > MAX_REQUEST:
                return Response(status_code=413)
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return JSONResponse(error(-32700, "Parse error"))
        try:
            response = await run_in_threadpool(dispatch, body, credential)
        except Exception:
            return JSONResponse(error(-32603, "Internal error"))
        if response is None or (isinstance(body, dict) and "id" not in body):
            return Response(status_code=202)
        return JSONResponse(response)

    async def metadata(request):
        if settings.auth_mode != "oauth":
            return Response(status_code=404)
        return JSONResponse(
            {
                "resource": settings.resource,
                "authorization_servers": [settings.issuer],
                "scopes_supported": SCOPES,
            }
        )

    @asynccontextmanager
    async def lifespan(app):
        async def loop():
            while True:
                await run_in_threadpool(Worker(store, http, oauth).once)
                await anyio.sleep(1)

        async with anyio.create_task_group() as group:
            if run_worker:
                group.start_soon(loop)
            yield
            group.cancel_scope.cancel()

    resource_path = urlsplit(settings.resource or "").path.rstrip("/")
    paths = {
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource" + resource_path,
        resource_path + "/.well-known/oauth-protected-resource",
    }
    return Starlette(
        routes=[
            Route("/mcp", endpoint, methods=["POST", "GET", "DELETE"]),
            *[Route(p, metadata) for p in paths],
        ],
        lifespan=lifespan,
    )
