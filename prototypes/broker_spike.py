"""THROWAWAY: exercise a maintained OAuth proxy against disposable Kanidm."""

import base64
import hashlib
import logging
import secrets
import ssl
import time
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.auth.jwt_issuer import JWTIssuer
from fastmcp.server.auth.oauth_proxy import OAuthProxy
from joserfc.errors import JoseError
from key_value.aio.stores.memory import MemoryStore
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

logging.disable(logging.CRITICAL)


class Inputs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = {}

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "input" and "name" in a:
            self.values[a["name"]] = a.get("value", "")


async def run(
    upstream, req, upstream_id, upstream_secret, root, metadata, expected_subject
):
    report = {}
    ca = ssl.create_default_context(cafile=str(root / "chain.pem"))

    class KanidmVerifier(TokenVerifier):
        def __init__(self):
            super().__init__(required_scopes=["openid", "profile"])

        async def verify_token(self, token):
            async with httpx.AsyncClient(verify=ca, trust_env=False) as client:
                r = await client.post(
                    metadata["introspection_endpoint"], data={"token": token}
                )
            if r.status_code != 200:
                return None
            c = r.json()
            if not (
                c.get("active") is True
                and c.get("iss") == metadata["issuer"]
                and c.get("aud") == upstream_id
                and c.get("client_id") == upstream_id
                and c.get("sub") == expected_subject
                and c.get("exp", 0) > time.time()
            ):
                return None
            return AccessToken(
                token=token,
                client_id=c["client_id"],
                scopes=c["scope"].split(),
                expires_at=c["exp"],
                subject=c["sub"],
                claims=c,
            )

    class LocalProxy(OAuthProxy):
        def _create_upstream_oauth_client(self):
            # Trust only this experiment's CA; use the documented client factory.
            return AsyncOAuth2Client(
                client_id=upstream_id,
                client_secret=upstream_secret,
                token_endpoint_auth_method="client_secret_basic",
                verify=ca,
                trust_env=False,
                timeout=10,
            )

    # Register the broker callback only on this throwaway local client.
    req(
        "POST",
        f"/v1/oauth2/{upstream_id}/_attr/oauth2_rs_origin",
        json=["https://broker.example/auth/callback"],
    )
    proxy = LocalProxy(
        upstream_authorization_endpoint=metadata["authorization_endpoint"],
        upstream_token_endpoint=metadata["token_endpoint"],
        upstream_client_id=upstream_id,
        upstream_client_secret=upstream_secret,
        token_verifier=KanidmVerifier(),
        base_url="https://broker.example",
        allowed_client_redirect_uris=["https://hosted.example/callback"],
        valid_scopes=["openid", "profile"],
        forward_resource=False,
        forward_pkce=True,
        client_storage=MemoryStore(),
        jwt_signing_key=secrets.token_urlsafe(48),
        enable_cimd=False,
    )
    server = FastMCP("THROWAWAY OAuth feasibility", auth=proxy)

    @server.tool
    def synthetic_identity():
        return {"synthetic": True}

    app = server.http_app(path="/mcp")
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="https://broker.example",
            follow_redirects=False,
        ) as browser:
            registered = await browser.post(
                "/register",
                json={
                    "client_name": "Throwaway hosted client",
                    "redirect_uris": ["https://hosted.example/callback"],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                },
            )
            if registered.status_code != 201:
                raise RuntimeError("broker registration failed")
            downstream = registered.json()
            hosted_id = downstream["client_id"]
            verifier = secrets.token_urlsafe(48)
            challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                .decode()
                .rstrip("=")
            )
            params = {
                "client_id": hosted_id,
                "redirect_uri": "https://hosted.example/callback",
                "response_type": "code",
                "scope": "openid profile",
                "state": secrets.token_urlsafe(32),
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": "https://broker.example/mcp",
            }
            r = await browser.get("/authorize", params=params)
            if r.status_code != 302:
                raise RuntimeError("broker authorization failed")
            consent_url = r.headers["location"]
            r = await browser.get(consent_url)
            if r.status_code != 200:
                raise RuntimeError("broker consent page failed")
            form = Inputs()
            form.feed(r.text)
            fields = {k: form.values[k] for k in ["txn_id", "csrf_token"]}
            fields["action"] = "approve"
            rejected = await browser.post(
                consent_url, data={**fields, "csrf_token": "invalid"}
            )
            report["consent_csrf_rejected"] = rejected.status_code >= 400
            r = await browser.post(consent_url, data=fields)
            if r.status_code != 302:
                raise RuntimeError("broker consent failed")
            upstream_url = r.headers["location"]
            up_params = parse_qs(urlsplit(upstream_url).query)
            report["upstream_uses_dedicated_client"] = up_params.get("client_id") == [
                upstream_id
            ]
            report["upstream_pkce_s256"] = up_params.get("code_challenge_method") == [
                "S256"
            ]
            # Simulate this newly created local user's browser login/consent.
            r = req(
                "POST",
                "/oauth2/authorise",
                json={k: v[0] for k, v in up_params.items()},
            )
            consent = r.json()
            if "ConsentRequested" in consent:
                r = req(
                    "POST",
                    "/oauth2/authorise/permit",
                    json=consent["ConsentRequested"]["consent_token"],
                )
            r = await browser.get(r.headers["location"])
            if r.status_code != 302:
                raise RuntimeError("broker upstream callback failed")
            codes = parse_qs(urlsplit(r.headers["location"]).query)
            report["downstream_state_preserved"] = codes.get("state") == [
                params["state"]
            ]
            form = {
                "grant_type": "authorization_code",
                "code": codes["code"][0],
                "redirect_uri": params["redirect_uri"],
                "code_verifier": verifier,
                "resource": params["resource"],
            }
            auth = None
            form["client_id"] = hosted_id
            report["downstream_public_client_only"] = (
                downstream.get("token_endpoint_auth_method") == "none"
            )
            bad = await browser.post(
                "/token",
                data={**form, "code_verifier": secrets.token_urlsafe(48)},
                auth=auth,
            )
            report["wrong_pkce_rejected"] = bad.status_code >= 400
            r = await browser.post("/token", data=form, auth=auth)
            if r.status_code != 200:
                raise RuntimeError("broker code exchange failed")
            issued = r.json()
            claims = proxy.jwt_issuer.verify_token(issued["access_token"])
            report["downstream_exact_resource_audience"] = (
                claims.get("aud") == params["resource"]
            )
            report["downstream_hosted_client_preserved"] = (
                claims.get("client_id") == hosted_id
            )
            validated = await proxy.load_access_token(issued["access_token"])
            report["verified_upstream_owner_available"] = (
                validated is not None and validated.subject == expected_subject
            )
            report["library_result_uses_upstream_client"] = (
                validated is not None and validated.client_id == upstream_id
            )
            replay = await browser.post("/token", data=form, auth=auth)
            report["code_replay_rejected"] = replay.status_code >= 400
            r = await browser.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": issued["refresh_token"],
                    "resource": params["resource"],
                    "client_id": hosted_id,
                },
                auth=auth,
            )
            if r.status_code != 200:
                raise RuntimeError("broker refresh failed")
            renewed = r.json()
            renewed_claims = proxy.jwt_issuer.verify_token(renewed["access_token"])
            renewed_validation = await proxy.load_access_token(renewed["access_token"])
            report["refresh_keeps_resource_and_hosted_client"] = (
                renewed_claims.get("aud") == params["resource"]
                and renewed_claims.get("client_id") == hosted_id
            )
            report["refresh_keeps_verified_owner"] = (
                renewed_validation is not None
                and renewed_validation.subject == expected_subject
            )
            wrong_audience_verifier = JWTIssuer(
                issuer=proxy.jwt_issuer.issuer,
                audience="https://other.example/mcp",
                signing_key=proxy._jwt_signing_key,
            )
            try:
                wrong_audience_verifier.verify_token(renewed["access_token"])
                report["same_key_foreign_audience_rejected"] = False
            except JoseError:
                report["same_key_foreign_audience_rejected"] = True
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="https://broker.example",
                headers={"Authorization": "Bearer " + renewed["access_token"]},
            ) as api:
                async with streamable_http_client(
                    "https://broker.example/mcp", http_client=api
                ) as streams:
                    async with ClientSession(streams[0], streams[1]) as session:
                        await session.initialize()
                        result = await session.call_tool("synthetic_identity", {})
                        report["authenticated_synthetic_mcp_call"] = not result.is_error
            wrong_resource = await browser.get(
                "/authorize", params={**params, "resource": "https://other.example/mcp"}
            )
            report["foreign_resource_rejected"] = (
                wrong_resource.status_code >= 400
                or "error=" in wrong_resource.headers.get("location", "")
            )
            report["synthetic_mcp_unauthenticated_rejected"] = (
                await browser.post(
                    "/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {},
                    },
                )
            ).status_code == 401
    assert all(report.values()), "a broker feasibility control failed"
    return report
