#!/usr/bin/env python3
"""Structural check over the reference Helm chart (charts/xmsg-mcp-gateway).

Renders the chart with every ci/*-values.yaml file and asserts:
1. One uid: every container and the pod run as the same uid and gid, and
   serving.json's messaging.xmsg.daemon_uid is the leaf container's uid.
2. Every container has readOnlyRootFilesystem and drops ALL capabilities.
3. The init chain is in the gateway's migration order, every migration has
   --if-needed, and no step runs enable or sets enablement.
4. No non-loopback bind without allow_non_loopback_bind.
5. Routes carry only the public OAuth paths (plus /mcp only when asked for).
6. One replica, Recreate, fsGroupChangePolicy OnRootMismatch.
7. A budget violation refuses to render.

Then it applies each mutant below to a copy of the chart and requires the named
assertion to fail: a check that cannot go red proves nothing.

Usage: check_k8s.py <chart-dir>   (needs helm on PATH and PyYAML)
"""

import ipaddress
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

import yaml

MIGRATIONS = [
    "migrate-custody",
    "migrate-outbound",
    "migrate-retirement",
    "migrate-custody-summaries",
    "migrate-events",
    "migrate-profiles",
    "migrate-attachments",
]
PUBLIC_PATHS = {
    ("PathPrefix", "/.well-known/oauth-protected-resource"),
    ("Exact", "/.well-known/oauth-authorization-server"),
    ("PathPrefix", "/oauth"),
    ("PathPrefix", "/oauth/authorize"),
}
ENABLEMENT = {"enable", "disable", "--enabled", "--disabled"}
HOOK = {
    "name": "pre-migrate-hook",
    "image": "registry.example.com/backup-hook@sha256:" + "0" * 64,
    "securityContext": {
        "runAsUser": 10001,
        "runAsGroup": 10001,
        "runAsNonRoot": True,
        "readOnlyRootFilesystem": True,
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
    },
}

# (assertion it must turn red, template file, text, replacement)
MUTANTS = [
    ("uid", "_helpers.tpl", '"daemon_uid" (int $v.uid)', '"daemon_uid" (add 1 (int $v.uid))'),
    ("uid", "_helpers.tpl", "runAsGroup: {{ int .Values.uid }}", "runAsGroup: 0"),
    ("hardening", "_helpers.tpl", "readOnlyRootFilesystem: true", "readOnlyRootFilesystem: false"),
    ("hardening", "_helpers.tpl", "drop: [ALL]", "drop: [NET_RAW]"),
    ("migration-order", "_helpers.tpl", '(concat (list "migrate-events") $key)\n  (list "migrate-profiles")',
     '(list "migrate-profiles")\n  (concat (list "migrate-events") $key)'),
    ("migration-order", "_helpers.tpl", '(list (first .) "--if-needed")', "(list (first .))"),
    ("migration-order", "deployment.yaml", '"--policy" (printf', '"--enabled" "--policy" (printf'),
    ("migration-order", "deployment.yaml", '(list "init" "--if-needed")', '(list "init")'),
    ("migration-order", "deployment.yaml", "{{- with .Values.store.preMigrate }}\n        {{- toYaml . | nindent 8 }}\n        {{- end }}\n", ""),
    ("bind", "_helpers.tpl", '(ternary "0.0.0.0" "127.0.0.1" $v.gateway.podNetwork)', '"0.0.0.0"'),
    ("bind", "_helpers.tpl", '{{- $_ := set $owned "allow_non_loopback_bind" true -}}', ""),
    ("routes", "httproute.yaml", '(list "PathPrefix" "/oauth"))', '(list "PathPrefix" "/"))'),
    ("routes", "httproute.yaml", "{{- if .Values.httpRoute.mcp }}", "{{- if true }}"),
    ("envelope", "deployment.yaml", "type: Recreate", "type: RollingUpdate"),
    ("envelope", "deployment.yaml", "fsGroupChangePolicy: OnRootMismatch", "fsGroupChangePolicy: Always"),
    ("budgets", "configmap.yaml", '{{- include "gw.checkBudgets" . -}}', ""),
    ("naming", "_helpers.tpl", "{{- if .Values.fullnameOverride -}}", "{{- if false -}}"),
    ("naming", "serviceaccount.yaml", 'name: {{ include "gw.serviceAccountName" . }}', 'name: {{ include "gw.fullname" . }}'),
    ("extra-volumes", "deployment.yaml", "{{- with .Values.extraVolumes }}\n        {{- toYaml . | nindent 8 }}\n        {{- end }}\n", ""),
]


def helm(chart, values, *extra):
    return subprocess.run(
        ["helm", "template", "t", str(chart), "-f", str(values), *extra],
        capture_output=True,
        text=True,
        check=False,
    )


def render(chart, values):
    r = helm(chart, values)
    if r.returncode != 0:
        raise RuntimeError(f"helm template {values.name} failed: {r.stderr.strip()}")
    return [d for d in yaml.safe_load_all(r.stdout) if d]


def values_of(values):
    with open(values) as f:
        return yaml.safe_load(f)


def is_loopback(bind):
    host = bind.rsplit(":", 1)[0].strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def assertions(docs, vals):
    """Yield (assertion name, ok, detail) over one render."""
    by_kind = {}
    for d in docs:
        by_kind.setdefault(d["kind"], []).append(d)
    dep = by_kind["Deployment"][0]["spec"]
    pod = dep["template"]["spec"]
    inits, mains = pod.get("initContainers", []), pod["containers"]
    every = inits + mains
    config = next(c for c in by_kind["ConfigMap"] if c["metadata"]["name"].endswith("-config"))
    serving = json.loads(config["data"]["serving.json"])
    psc = pod.get("securityContext", {})

    # 1. uid parity
    uid = psc.get("runAsUser")
    bad = [
        c["name"]
        for c in every
        if (c.get("securityContext", {}).get("runAsUser"), c.get("securityContext", {}).get("runAsGroup"))
        != (uid, uid)
    ]
    leaf = next(c for c in mains if c["name"] == "xmsg")
    daemon = serving.get("messaging", {}).get("xmsg", {}).get("daemon_uid")
    yield "uid", not bad and psc.get("runAsGroup") == uid and psc.get("fsGroup") == uid, bad
    yield "uid", daemon == leaf["securityContext"]["runAsUser"] == uid, (daemon, uid)

    # 2. hardening
    for c in every:
        sc = c.get("securityContext", {})
        caps = sc.get("capabilities", {})
        yield "hardening", sc.get("readOnlyRootFilesystem") is True, c["name"]
        yield "hardening", caps.get("drop") == ["ALL"] and not caps.get("add"), (c["name"], caps)
        yield "hardening", sc.get("allowPrivilegeEscalation") is False and sc.get("runAsNonRoot") is True, c["name"]

    # 3. migration chain
    store = vals.get("store", {})
    grants = [g["id"] for g in store.get("grants", [])]
    migs = MIGRATIONS + (["migrate-authorization-server"] if store.get("authorizationServer") else [])
    want = ["prepare"]
    if store.get("bootstrap", {}).get("enabled"):
        want += ["store-init"]
    want += [c["name"] for c in store.get("preMigrate", [])]
    want += [f"store-{m}" for m in migs]
    if store.get("bootstrap", {}).get("enabled"):
        want += [f"store-enroll-{g}" for g in grants]
    want += [f"store-apply-{g}" for g in grants]
    names = [c["name"] for c in inits]
    yield "migration-order", names == want, names
    for c in inits:
        args = c.get("args", [])
        if any(a.startswith("migrate-") or a in {"init", "enroll"} for a in args):
            yield "migration-order", "--if-needed" in args, (c["name"], args)
        yield "migration-order", not ENABLEMENT & set(args + c.get("command", [])), (c["name"], args)
        if c["name"].startswith("store-"):
            yield "migration-order", not c.get("command") and not c.get("env"), c["name"]
            yield "migration-order", len(args) >= 3 and args[:2] == ["--state", serving["grant_store"]], (c["name"], args)
    yield "migration-order", not any("staging" in str(c) for c in inits), names

    # 4. bind
    bind = serving.get("bind", "")
    yield "bind", is_loopback(bind) or serving.get("allow_non_loopback_bind") is True, (bind, serving.get("allow_non_loopback_bind"))
    yield "bind", is_loopback(bind) != bool(vals.get("gateway", {}).get("podNetwork")), bind

    # 5. routes
    paths = {
        (m["path"]["type"], m["path"]["value"])
        for r in by_kind.get("HTTPRoute", [])
        for rule in r["spec"]["rules"]
        for m in rule.get("matches", [])
    }
    if vals.get("httpRoute", {}).get("enabled"):
        extra = {("PathPrefix", "/mcp")} if vals["httpRoute"].get("mcp") else set()
        yield "routes", paths == PUBLIC_PATHS | extra, sorted(paths)
    else:
        yield "routes", paths == set(), sorted(paths)

    # 6. envelope
    yield "envelope", dep.get("replicas") == 1, dep.get("replicas")
    yield "envelope", dep.get("strategy", {}).get("type") == "Recreate", dep.get("strategy")
    yield "envelope", psc.get("fsGroupChangePolicy") == "OnRootMismatch", psc.get("fsGroupChangePolicy")


def run(chart):
    """Return {assertion: [failure details]} over every example values file."""
    failed = {}
    files = sorted((chart / "ci").glob("*-values.yaml"))
    if len(files) < 2:
        raise RuntimeError(f"expected the example values files in {chart}/ci")
    for values in files:
        for name, ok, detail in assertions(render(chart, values), values_of(values)):
            if not ok:
                failed.setdefault(name, []).append(f"{values.name}: {detail}")
    # The preMigrate slot (where a pre-migration backup goes) sits between init
    # and the real store's migrations.
    vals = values_of(files[0])
    vals.setdefault("store", {})["preMigrate"] = [HOOK]
    r = helm(chart, files[0], "--set-json", "store.preMigrate=" + json.dumps([HOOK]))
    if r.returncode != 0:
        raise RuntimeError(f"helm template with a preMigrate hook failed: {r.stderr.strip()}")
    for name, ok, detail in assertions([d for d in yaml.safe_load_all(r.stdout) if d], vals):
        if not ok:
            failed.setdefault(name, []).append(f"preMigrate hook: {detail}")
    # 7. budgets: an impossible request budget must refuse to render.
    r = helm(chart, files[0], "--set", "serving.request_timeout_ms=30000")
    if r.returncode == 0 or "request_timeout_ms" not in r.stderr:
        failed.setdefault("budgets", []).append("a 30 s request budget rendered")

    # 8. naming: default unchanged; fullnameOverride and serviceAccount.name reach every object.
    def check_naming(docs, label, expected_full, expected_sa):
        by_kind = {}
        for d in docs:
            by_kind.setdefault(d["kind"], []).append(d)
        dep = by_kind["Deployment"][0]
        pod = dep["spec"]["template"]["spec"]
        vols = {v["name"]: v for v in pod.get("volumes", [])}
        checks = [
            ("Deployment", dep["metadata"]["name"] == expected_full, dep["metadata"]["name"]),
            ("ServiceAccount", [s["metadata"]["name"] for s in by_kind.get("ServiceAccount", [])] == [expected_sa], by_kind.get("ServiceAccount", [])),
            ("pod.serviceAccountName", pod.get("serviceAccountName") == expected_sa, pod.get("serviceAccountName")),
            ("Service", [s["metadata"]["name"] for s in by_kind.get("Service", [])] == [expected_full], by_kind.get("Service", [])),
            ("PVC", [p["metadata"]["name"] for p in by_kind.get("PersistentVolumeClaim", [])] == [expected_full], by_kind.get("PersistentVolumeClaim", [])),
            ("volume.data.claimName", vols.get("data", {}).get("persistentVolumeClaim", {}).get("claimName") == expected_full, vols.get("data")),
            ("volume.peers", vols.get("peers", {}).get("configMap", {}).get("name") == f"{expected_full}-peers", vols.get("peers")),
            ("volume.config", vols.get("config", {}).get("configMap", {}).get("name") == f"{expected_full}-config", vols.get("config")),
            ("ConfigMaps", all(c["metadata"]["name"].startswith(f"{expected_full}-") for c in by_kind.get("ConfigMap", [])), [c["metadata"]["name"] for c in by_kind.get("ConfigMap", [])]),
            ("HTTPRoutes", all(
                hr["metadata"]["name"] == expected_full or hr["metadata"]["name"].startswith(f"{expected_full}-")
                for hr in by_kind.get("HTTPRoute", [])
            ), [hr["metadata"]["name"] for hr in by_kind.get("HTTPRoute", [])]),
            ("HTTPRoute.backendRefs", all(
                b["name"] == expected_full
                for hr in by_kind.get("HTTPRoute", [])
                for rule in hr["spec"]["rules"]
                for b in rule.get("backendRefs", [])
            ), "backendRefs"),
        ]
        for what, ok, detail in checks:
            if not ok:
                failed.setdefault("naming", []).append(f"{label} ({what}): {detail}")

    check_naming(render(chart, files[1]), "default", "t-xmsg-mcp-gateway", "t-xmsg-mcp-gateway")
    for label, sets, exp_full, exp_sa in [
        ("fullnameOverride", ["--set", "fullnameOverride=xmsg-gateway"], "xmsg-gateway", "xmsg-gateway"),
        ("fullnameOverride+serviceAccount.name", ["--set", "fullnameOverride=xmsg-gateway", "--set", "serviceAccount.name=xmsg-gateway-sa"], "xmsg-gateway", "xmsg-gateway-sa"),
    ]:
        r = helm(chart, files[1], *sets)
        if r.returncode != 0:
            failed.setdefault("naming", []).append(f"{label} render failed: {r.stderr.strip()}")
        else:
            check_naming([d for d in yaml.safe_load_all(r.stdout) if d], label, exp_full, exp_sa)

    # 9. extraVolumes: additional pod volumes render on the Deployment pod spec.
    r = helm(chart, files[0], "--set-json", 'extraVolumes=[{"name":"hook-vol","emptyDir":{}}]')
    if r.returncode != 0:
        failed.setdefault("extra-volumes", []).append(f"render failed: {r.stderr.strip()}")
    else:
        docs = [d for d in yaml.safe_load_all(r.stdout) if d]
        pod_vols = {v["name"] for d in docs if d["kind"] == "Deployment" for v in d["spec"]["template"]["spec"].get("volumes", [])}
        if "hook-vol" not in pod_vols:
            failed.setdefault("extra-volumes", []).append(f"hook-vol missing from {sorted(pod_vols)}")

    return failed


def main():
    chart = pathlib.Path(sys.argv[1]).resolve()
    failed = run(chart)
    for name, details in failed.items():
        for d in details:
            print(f"FAIL {name}: {d}")
    if failed:
        sys.exit(1)
    print("green: every assertion holds on the chart")

    survivors = []
    with tempfile.TemporaryDirectory() as tmp:
        for i, (name, file, old, new) in enumerate(MUTANTS):
            copy = pathlib.Path(tmp) / str(i)
            shutil.copytree(chart, copy, copy_function=shutil.copyfile)
            target = copy / "templates" / file
            text = target.read_text()
            if text.count(old) != 1:
                sys.exit(f"mutant {i} ({name}): its text occurs {text.count(old)} times in {file}")
            target.write_text(text.replace(old, new))
            try:
                red = run(copy)
            except RuntimeError as e:
                red = {"render": [str(e)]}
            if name in red:
                print(f"red: mutant {i} ({name}, {file}) fails {name}")
            else:
                survivors.append(f"mutant {i} ({name}, {file}) survived: {sorted(red)}")
    for s in survivors:
        print(f"FAIL {s}")
    if survivors:
        sys.exit(1)
    print(f"k8s-check-complete:{len(MUTANTS)}")


if __name__ == "__main__":
    main()
