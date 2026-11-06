"""Throwaway localhost Kanidm 1.11.2 experiment; no existing credentials."""

import argparse
import base64
import hashlib
import json
import os
import pathlib
import secrets
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, urlsplit

import httpx

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--kanidm-bin", type=pathlib.Path, required=True)
parser.add_argument("--results-dir", type=pathlib.Path, required=True)
args = parser.parse_args()
BIN = args.kanidm_bin.resolve()
args.results_dir.mkdir(parents=True, exist_ok=True)
ROOT = pathlib.Path(tempfile.mkdtemp(prefix="codex-kanidm-spike-"))
ROOT.chmod(0o700)
CONFIG = ROOT / "server.toml"
CONFIG.write_text(f'''domain = "localhost"
origin = "https://localhost:18443"
db_path = "{ROOT}/kanidm.db"
adminbindpath = "{ROOT}/admin.sock"
tls_chain = "{ROOT}/chain.pem"
tls_key = "{ROOT}/key.pem"
bindaddress = "127.0.0.1:18443"
thread_count = 2
''')
env = dict(
    os.environ,
    HOME=str(ROOT),
    XDG_CONFIG_HOME=str(ROOT / "config"),
    XDG_CACHE_HOME=str(ROOT / "cache"),
    KANIDM_CONFIG=str(CONFIG),
)
with (ROOT / "server.log").open("wb") as log:
    r = subprocess.run(
        [str(BIN / "kanidmd"), "cert-generate"], env=env, stdout=log, stderr=log
    )
    if r.returncode:
        print("certificate setup failed; isolated log", str(ROOT))
        raise SystemExit(1)
    proc = subprocess.Popen(
        [str(BIN / "kanidmd"), "server"], env=env, stdout=log, stderr=log
    )
    try:
        with httpx.Client(
            base_url="https://localhost:18443",
            verify=str(ROOT / "chain.pem"),
            trust_env=False,
            timeout=10,
        ) as c:
            for _ in range(200):
                if proc.poll() is not None:
                    print("server startup failed; isolated log", str(ROOT))
                    raise SystemExit(1)
                try:
                    if c.get("/status").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.1)
            else:
                raise RuntimeError("localhost provider not ready")
            recovered = subprocess.run(
                [str(BIN / "kanidmd"), "scripting", "recover-account", "idm_admin"],
                env=env,
                capture_output=True,
                timeout=30,
            )
            if recovered.returncode:
                print("local account setup failed", recovered.returncode)
                raise SystemExit(1)
            # Machine-readable recovery output is retained privately, never printed.
            (ROOT / "recovery.json").write_bytes(recovered.stdout)
            (ROOT / "recovery.json").chmod(0o600)
            password = json.loads(recovered.stdout)["output"]

            def req(method, url, **kwargs):
                r = c.request(method, url, **kwargs)
                if r.status_code >= 400:
                    raise RuntimeError(f"local request {url} returned {r.status_code}")
                return r

            r = req(
                "POST",
                "/v1/auth",
                json={
                    "step": {
                        "init2": {
                            "username": "idm_admin",
                            "issue": "token",
                            "privileged": True,
                        }
                    }
                },
            )
            sid = r.headers.get("x-kanidm-auth-session-id")
            ah = {"x-kanidm-auth-session-id": sid} if sid else {}
            r = req(
                "POST", "/v1/auth", headers=ah, json={"step": {"begin": "password"}}
            )
            if r.headers.get("x-kanidm-auth-session-id"):
                ah = {"x-kanidm-auth-session-id": r.headers["x-kanidm-auth-session-id"]}
            r = req(
                "POST",
                "/v1/auth",
                headers=ah,
                json={"step": {"cred": {"password": password}}},
            )
            token = r.json()["state"]["success"]
            c.headers["Authorization"] = "Bearer " + token
            client = "hosted-probe"
            req(
                "POST",
                "/v1/oauth2/_basic",
                json={
                    "attrs": {
                        "name": [client],
                        "displayname": ["Local hosted probe"],
                        "oauth2_rs_origin_landing": ["https://client.example/"],
                        "oauth2_rs_origin": ["https://client.example/callback"],
                    }
                },
            )
            req(
                "POST",
                f"/v1/oauth2/{client}/_scopemap/idm_admins",
                json=["openid", "profile"],
            )
            metadata = req(
                "GET", f"/oauth2/openid/{client}/.well-known/openid-configuration"
            ).json()
            secret = req("GET", f"/v1/oauth2/{client}/_basic_secret").json()
            verifier = secrets.token_urlsafe(48)
            challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                .decode()
                .rstrip("=")
            )
            resource = "https://mcp.example/mcp"
            state = secrets.token_urlsafe(32)
            redirect = "https://client.example/callback"
            r = req(
                "POST",
                "/oauth2/authorise",
                json={
                    "response_type": "code",
                    "client_id": client,
                    "redirect_uri": redirect,
                    "scope": "openid profile",
                    "state": state,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "resource": resource,
                },
            )
            consent = r.json()
            if "ConsentRequested" in consent:
                r = req(
                    "POST",
                    "/oauth2/authorise/permit",
                    json=consent["ConsentRequested"]["consent_token"],
                )
            params = parse_qs(urlsplit(r.headers["location"]).query)
            assert params["state"] == [state]
            basic = {
                "Authorization": "Basic "
                + base64.b64encode((client + ":" + secret).encode()).decode()
            }
            form = {
                "grant_type": "authorization_code",
                "code": params["code"][0],
                "redirect_uri": redirect,
                "code_verifier": verifier,
                "resource": resource,
            }
            issued = req("POST", "/oauth2/token", data=form, headers=basic).json()
            # Explicitly omit the admin Authorization header for introspection.
            with httpx.Client(
                base_url="https://localhost:18443",
                verify=str(ROOT / "chain.pem"),
                trust_env=False,
                timeout=10,
            ) as public:

                def introspect(access):
                    r = public.post(
                        "/oauth2/token/introspect",
                        data={"token": access, "token_type_hint": "access_token"},
                    )
                    if r.status_code != 200:
                        raise RuntimeError("local introspection failed")
                    return r.json()

                a = introspect(issued["access_token"])
                refreshed = req(
                    "POST",
                    "/oauth2/token",
                    data={
                        "grant_type": "refresh_token",
                        "refresh_token": issued["refresh_token"],
                        "resource": resource,
                    },
                    headers=basic,
                ).json()
                b = introspect(refreshed["access_token"])
                report = {
                    "localhost_provider_ready": True,
                    "kanidm_version": "1.11.2",
                    "s256_code_flow": True,
                    "refresh_succeeded": True,
                    "introspection_without_caller_auth": a.get("active") is True,
                    "introspection_auth_methods": metadata.get(
                        "introspection_endpoint_auth_methods_supported"
                    ),
                    "verified_hosted_client": a.get("client_id") == client,
                    "subject_present": bool(a.get("sub")),
                    "refresh_subject_stable": a.get("sub") == b.get("sub"),
                    "refresh_client_stable": a.get("client_id") == b.get("client_id"),
                    "audience_equals_client_name": a.get("aud") == client,
                    "audience_equals_requested_resource": a.get("aud") == resource,
                    "refresh_exact_resource_audience": b.get("aud") == resource,
                }
                print(json.dumps(report, sort_keys=True))
                (args.results_dir / "provider-result.json").write_text(
                    json.dumps(report, indent=2) + "\n"
                )
                import asyncio

                from broker_spike import run

                broker_report = asyncio.run(
                    run(c, req, client, secret, ROOT, metadata, a["sub"])
                )
                print(json.dumps(broker_report, sort_keys=True))
                (args.results_dir / "broker-result.json").write_text(
                    json.dumps(broker_report, indent=2) + "\n"
                )
                revocation = req(
                    "POST",
                    "/oauth2/token/revoke",
                    data={"token": refreshed["access_token"]},
                    headers=basic,
                )
                revoked = introspect(refreshed["access_token"])
                revocation_report = {
                    "revocation_http_success": revocation.status_code == 200,
                    "immediate_introspection_inactive": revoked.get("active") is False,
                }
                print(json.dumps(revocation_report, sort_keys=True))
                (args.results_dir / "revocation-result.json").write_text(
                    json.dumps(revocation_report, indent=2) + "\n"
                )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
