#!/usr/bin/env python3
"""Ensure Keycloak argocd-browser wrapper: identify then realm role argocd-access.

Vanilla Keycloak has no "member of group" authenticator. The gate requires realm
role argocd-access (Terraform assigns it only to group /argocd-admins).

Top-level argocd-browser is REQUIRED + CONDITIONAL only (no ALTERNATIVE mix):

  argocd-identify REQUIRED  — clone of built-in browser (Cookie / IdP / Forms)
  argocd-admins-gate CONDITIONAL — deny unless argocd-access
"""

from __future__ import annotations

import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

WRAPPER = "argocd-browser"
IDENTIFY = "argocd-identify"
GATE = "argocd-admins-gate"
GATE_CONFIG_ALIAS = "argocd-admins-group-gate"
CLIENT_ID = "argocd"
SOURCE_BROWSER = "browser"
ROLE = "argocd-access"

SUBFLOW_ALIASES = {
    "forms": "argocd-forms",
    "Forms": "argocd-forms",
    "Browser - Conditional OTP": "argocd-conditional-otp",
    "browser-conditional-otp": "argocd-conditional-otp",
}

changed_reasons: list[str] = []


def note(reason: str) -> None:
    changed_reasons.append(reason)


def write_status(text: str) -> bool:
    path = os.environ.get("KEYCLOAK_FLOW_STATUS_FILE", "").strip()
    if not path:
        return True
    payload = text if text.endswith("\n") else f"{text}\n"
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(payload)
    except OSError as exc:
        print(f"status file write failed: {exc}", file=sys.stderr)
        return False
    return True


def success_status() -> str:
    if changed_reasons:
        return "\n".join(changed_reasons) + "\nCHANGED"
    return "OK"


def error_status(message: str) -> str:
    return f"ERROR\n{message}"


def env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"missing environment variable {name}")
    return value


def quote(value: str) -> str:
    return urllib.parse.quote(value, safe="")


class ApiError(Exception):
    def __init__(self, method: str, url: str, status: int, body: str) -> None:
        super().__init__(f"{method} {url} -> {status}: {body[:800]}")
        self.status = status
        self.body = body


class Keycloak:
    def __init__(self, base_url: str, realm: str, token: str) -> None:
        self.base = base_url.rstrip("/")
        self.realm = realm
        self.token = token
        self.ctx = ssl._create_unverified_context()

    def url(self, path: str) -> str:
        return f"{self.base}/auth/admin/realms/{quote(self.realm)}/{path.lstrip('/')}"

    def request(
        self,
        method: str,
        path: str,
        body: Any | None = None,
        expected: tuple[int, ...] = (200, 201, 204),
    ) -> Any:
        data = None
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.url(path), data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=30) as resp:
                status = resp.status
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise ApiError(method, self.url(path), exc.code, raw) from exc
        if status not in expected:
            raise ApiError(method, self.url(path), status, raw)
        if not raw:
            return None
        return json.loads(raw)


def dest_subflow_alias(src_alias: str) -> str:
    if src_alias in SUBFLOW_ALIASES:
        return SUBFLOW_ALIASES[src_alias]
    slug = re.sub(r"[^a-z0-9]+", "-", src_alias.lower()).strip("-")
    return f"argocd-{slug}" if slug else "argocd-subflow"


def level0(kc: Keycloak, alias: str) -> list[dict[str, Any]]:
    execs = kc.request("GET", f"authentication/flows/{quote(alias)}/executions") or []
    return [item for item in execs if item.get("level") == 0]


def find_l0(
    kc: Keycloak, alias: str, *, display_name: str | None = None, provider_id: str | None = None
) -> dict[str, Any] | None:
    for item in level0(kc, alias):
        if display_name is not None and item.get("displayName") == display_name:
            return item
        if provider_id is not None and item.get("providerId") == provider_id:
            return item
    return None


def flows(kc: Keycloak) -> list[dict[str, Any]]:
    return kc.request("GET", "authentication/flows") or []


def flow_by_alias(kc: Keycloak, alias: str) -> dict[str, Any] | None:
    for item in flows(kc):
        if item.get("alias") == alias:
            return item
    return None


def unbind_browser_if(kc: Keycloak, flow_id: str) -> None:
    listed = kc.request("GET", f"clients?clientId={quote(CLIENT_ID)}") or []
    if not listed:
        return
    client_uuid = listed[0]["id"]
    client = kc.request("GET", f"clients/{client_uuid}")
    overrides = dict(client.get("authenticationFlowBindingOverrides") or {})
    if overrides.get("browser") != flow_id:
        return
    client.pop("access", None)
    overrides.pop("browser", None)
    client["authenticationFlowBindingOverrides"] = overrides
    kc.request("PUT", f"clients/{client_uuid}", client)
    refreshed = kc.request("GET", f"clients/{client_uuid}")
    got = (refreshed.get("authenticationFlowBindingOverrides") or {}).get("browser")
    if got == flow_id:
        raise SystemExit(
            f"browser flow unbind did not stick on client {CLIENT_ID}: "
            f"still bound to {flow_id}"
        )
    note("cleared legacy browser flow bind")


def delete_flow(kc: Keycloak, alias: str) -> bool:
    item = flow_by_alias(kc, alias)
    if item is None:
        return False
    unbind_browser_if(kc, item["id"])
    kc.request("DELETE", f"authentication/flows/{item['id']}")
    note(f"deleted flow {alias}")
    return True


def set_requirement(kc: Keycloak, flow_alias: str, execution: dict[str, Any], requirement: str) -> None:
    # Early-return is required: PUT of a full authenticator object with
    # authenticationFlow=false and no flowId is Keycloak 26 "Illegal execution".
    if execution.get("requirement") == requirement:
        return
    body = dict(execution)
    body["requirement"] = requirement
    kc.request("PUT", f"authentication/flows/{quote(flow_alias)}/executions", body)
    key = execution.get("displayName") or execution.get("providerId")
    refreshed = find_l0(
        kc,
        flow_alias,
        display_name=execution.get("displayName") if execution.get("authenticationFlow") else None,
        provider_id=None if execution.get("authenticationFlow") else execution.get("providerId"),
    )
    if refreshed is None or refreshed.get("requirement") != requirement:
        raise SystemExit(
            f"requirement {requirement} did not stick on {flow_alias}/{key}: "
            f"{None if refreshed is None else refreshed.get('requirement')}"
        )
    note(f"{flow_alias}/{key} requirement={requirement}")


def copy_config(kc: Keycloak, src: dict[str, Any], dest: dict[str, Any], dest_alias: str) -> None:
    src_cfg_id = src.get("authenticationConfig") or ""
    if not src_cfg_id:
        return
    src_cfg = kc.request("GET", f"authentication/config/{src_cfg_id}")
    wanted = {str(k): str(v) for k, v in (src_cfg.get("config") or {}).items()}
    dest_cfg_id = dest.get("authenticationConfig") or ""
    if dest_cfg_id and dest_cfg_id == src_cfg_id:
        src_alias = src_cfg.get("alias") or dest_alias
        try:
            kc.request(
                "POST",
                f"authentication/executions/{dest['id']}/config",
                {"alias": dest_alias, "config": wanted},
            )
        except ApiError as exc:
            if exc.status == 409:
                raise SystemExit(
                    f"authenticator config alias {dest_alias} already exists "
                    f"(may be shared with built-in browser)"
                ) from exc
            raise
        refreshed = kc.request("GET", f"authentication/executions/{dest['id']}") or {}
        bound_id = (
            refreshed.get("authenticatorConfig") or refreshed.get("authenticationConfig") or ""
        )
        if bound_id == src_cfg_id:
            kc.request(
                "PUT",
                f"authentication/config/{src_cfg_id}",
                {"alias": src_alias, "config": wanted},
            )
            raise SystemExit(
                f"private config did not rebind; dest still shares {src_cfg_id}"
            )
        note(f"created private config {dest_alias}")
        return
    if dest_cfg_id:
        dest_cfg = kc.request("GET", f"authentication/config/{dest_cfg_id}")
        have = {str(k): str(v) for k, v in (dest_cfg.get("config") or {}).items()}
        if have == wanted:
            return
        kc.request(
            "PUT",
            f"authentication/config/{dest_cfg_id}",
            {"alias": dest_cfg.get("alias") or dest_alias, "config": wanted},
        )
        note(f"updated config {dest_alias}")
        return
    cfg_alias = dest_alias
    try:
        kc.request(
            "POST",
            f"authentication/executions/{dest['id']}/config",
            {"alias": cfg_alias, "config": wanted},
        )
    except ApiError as exc:
        if exc.status == 409:
            raise SystemExit(
                f"authenticator config alias {cfg_alias} already exists "
                f"(may be shared with built-in browser)"
            ) from exc
        raise
    note(f"created config {cfg_alias}")


def add_subflow(
    kc: Keycloak,
    parent_alias: str,
    alias: str,
    *,
    flow_type: str,
    description: str,
    priority: int | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "alias": alias,
        "type": flow_type or "basic-flow",
        "provider": "basic-flow",
        "description": description or "",
    }
    if priority is not None:
        body["priority"] = int(priority)
    kc.request("POST", f"authentication/flows/{quote(parent_alias)}/executions/flow", body)
    created = find_l0(kc, parent_alias, display_name=alias)
    if created is None:
        raise SystemExit(f"subflow {alias} missing under {parent_alias} after create")
    note(f"added subflow {parent_alias}/{alias}")
    return created


def add_execution(
    kc: Keycloak, parent_alias: str, provider: str, priority: int | None
) -> dict[str, Any]:
    body: dict[str, Any] = {"provider": provider}
    if priority is not None:
        body["priority"] = int(priority)
    kc.request("POST", f"authentication/flows/{quote(parent_alias)}/executions/execution", body)
    created = find_l0(kc, parent_alias, provider_id=provider)
    if created is None:
        raise SystemExit(f"execution {provider} missing under {parent_alias} after create")
    note(f"added execution {parent_alias}/{provider}")
    return created


def nested_flow_type(kc: Keycloak, src: dict[str, Any]) -> str:
    # GET /authentication/flows lists top-level only; nested type is on GET by id.
    flow_id = src.get("flowId") or ""
    if not flow_id:
        return "basic-flow"
    try:
        flow = kc.request("GET", f"authentication/flows/{quote(str(flow_id))}")
    except ApiError as exc:
        if exc.status == 404:
            return "basic-flow"
        raise
    return (flow or {}).get("providerId") or "basic-flow"


def clone_executions(kc: Keycloak, src_alias: str, dest_alias: str) -> None:
    for src in level0(kc, src_alias):
        if src.get("authenticationFlow"):
            src_sub = src.get("displayName") or ""
            dest_sub = dest_subflow_alias(src_sub)
            dest = find_l0(kc, dest_alias, display_name=dest_sub)
            flow_type = nested_flow_type(kc, src)
            if dest is None:
                dest = add_subflow(
                    kc,
                    dest_alias,
                    dest_sub,
                    flow_type=flow_type,
                    description=src.get("description") or "",
                    priority=src.get("priority"),
                )
            set_requirement(kc, dest_alias, dest, src.get("requirement") or "DISABLED")
            clone_executions(kc, src_sub, dest_sub)
            continue
        provider = src.get("providerId") or ""
        dest = find_l0(kc, dest_alias, provider_id=provider)
        if dest is None:
            dest = add_execution(kc, dest_alias, provider, src.get("priority"))
        set_requirement(kc, dest_alias, dest, src.get("requirement") or "DISABLED")
        cfg_alias = f"argocd-{provider}"
        copy_config(kc, src, dest, cfg_alias)


def ensure_wrapper(kc: Keycloak) -> dict[str, Any]:
    existing = flow_by_alias(kc, WRAPPER)
    if existing is not None:
        l0 = level0(kc, WRAPPER)
        if any(item.get("providerId") == "auth-cookie" for item in l0):
            delete_flow(kc, WRAPPER)
            existing = None
    for orphan in (IDENTIFY, GATE, "argocd-forms", "argocd-conditional-otp"):
        item = flow_by_alias(kc, orphan)
        if item is not None and item.get("topLevel"):
            delete_flow(kc, orphan)
    if existing is None:
        kc.request(
            "POST",
            "authentication/flows",
            {
                "alias": WRAPPER,
                "description": "Argo CD browser: identify then realm role argocd-access gate",
                "providerId": "basic-flow",
                "topLevel": True,
                "builtIn": False,
            },
        )
        note(f"created flow {WRAPPER}")
        existing = flow_by_alias(kc, WRAPPER)
    if existing is None:
        raise SystemExit(f"flow {WRAPPER} missing after create")
    return existing


def ensure_identify(kc: Keycloak) -> None:
    ident = find_l0(kc, WRAPPER, display_name=IDENTIFY)
    if ident is None:
        ident = add_subflow(
            kc,
            WRAPPER,
            IDENTIFY,
            flow_type="basic-flow",
            description="Clone of built-in browser (Cookie / IdP / Forms)",
            priority=10,
        )
    clone_executions(kc, SOURCE_BROWSER, IDENTIFY)
    ident = find_l0(kc, WRAPPER, display_name=IDENTIFY)
    if ident is None:
        raise SystemExit(f"{IDENTIFY} missing under {WRAPPER}")
    set_requirement(kc, WRAPPER, ident, "REQUIRED")


def ensure_gate_config(kc: Keycloak, execution: dict[str, Any]) -> None:
    wanted = {"condUserRole": ROLE, "negate": "true"}
    cfg_id = execution.get("authenticationConfig") or ""
    if cfg_id:
        cfg = kc.request("GET", f"authentication/config/{cfg_id}")
        have = {str(k): str(v) for k, v in (cfg.get("config") or {}).items()}
        if have.get("condUserRole") == ROLE and have.get("negate", "").lower() == "true":
            return
        kc.request(
            "PUT",
            f"authentication/config/{cfg_id}",
            {"alias": cfg.get("alias") or GATE_CONFIG_ALIAS, "config": wanted},
        )
        note(f"updated {GATE_CONFIG_ALIAS}")
        return
    try:
        kc.request(
            "POST",
            f"authentication/executions/{execution['id']}/config",
            {"alias": GATE_CONFIG_ALIAS, "config": wanted},
        )
    except ApiError as exc:
        if exc.status == 409:
            raise SystemExit(
                f"authenticator config alias {GATE_CONFIG_ALIAS} already exists "
                f"but is not bound to execution {execution['id']}"
            ) from exc
        raise
    note(f"created {GATE_CONFIG_ALIAS}")


def ensure_gate(kc: Keycloak) -> None:
    gate = find_l0(kc, WRAPPER, display_name=GATE)
    if gate is None:
        gate = add_subflow(
            kc,
            WRAPPER,
            GATE,
            flow_type="basic-flow",
            description="Deny login unless realm role argocd-access (group /argocd-admins)",
            priority=20,
        )
    role_cond = find_l0(kc, GATE, provider_id="conditional-user-role")
    if role_cond is None:
        role_cond = add_execution(kc, GATE, "conditional-user-role", 10)
    deny = find_l0(kc, GATE, provider_id="deny-access-authenticator")
    if deny is None:
        deny = add_execution(kc, GATE, "deny-access-authenticator", 20)
    role_cond = find_l0(kc, GATE, provider_id="conditional-user-role")
    deny = find_l0(kc, GATE, provider_id="deny-access-authenticator")
    if role_cond is None or deny is None:
        raise SystemExit("gate inner executions missing")
    set_requirement(kc, GATE, role_cond, "REQUIRED")
    set_requirement(kc, GATE, deny, "REQUIRED")
    role_cond = find_l0(kc, GATE, provider_id="conditional-user-role")
    if role_cond is None:
        raise SystemExit("conditional-user-role missing after requirement update")
    ensure_gate_config(kc, role_cond)
    gate = find_l0(kc, WRAPPER, display_name=GATE)
    if gate is None:
        raise SystemExit(f"{GATE} missing under {WRAPPER}")
    set_requirement(kc, WRAPPER, gate, "CONDITIONAL")


def bind_client(kc: Keycloak, wrapper_id: str) -> None:
    listed = kc.request("GET", f"clients?clientId={quote(CLIENT_ID)}") or []
    if not listed:
        raise SystemExit(f"client {CLIENT_ID} not found")
    client_uuid = listed[0]["id"]
    client = kc.request("GET", f"clients/{client_uuid}")
    client.pop("access", None)
    overrides = dict(client.get("authenticationFlowBindingOverrides") or {})
    if overrides.get("browser") == wrapper_id:
        return
    overrides["browser"] = wrapper_id
    client["authenticationFlowBindingOverrides"] = overrides
    kc.request("PUT", f"clients/{client_uuid}", client)
    refreshed = kc.request("GET", f"clients/{client_uuid}")
    got = (refreshed.get("authenticationFlowBindingOverrides") or {}).get("browser")
    if got != wrapper_id:
        raise SystemExit(
            f"browser flow bind did not stick on client {CLIENT_ID}: "
            f"wanted {wrapper_id}, got {got}"
        )
    note(f"bound {WRAPPER} browser flow on client {CLIENT_ID}")


def main() -> int:
    kc = Keycloak(env("KEYCLOAK_URL"), env("KEYCLOAK_REALM"), env("KEYCLOAK_TOKEN"))
    wrapper = ensure_wrapper(kc)
    ensure_identify(kc)
    ensure_gate(kc)
    bind_client(kc, wrapper["id"])
    if changed_reasons:
        for reason in changed_reasons:
            print(reason)
        print("CHANGED")
    else:
        print("OK")
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except ApiError as exc:
        write_status(error_status(str(exc)))
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    except SystemExit as exc:
        if isinstance(exc.code, str):
            write_status(error_status(exc.code))
        elif exc.code not in (0, None):
            write_status(error_status(f"exit code {exc.code}"))
        raise
    except Exception as exc:
        write_status(error_status(f"{type(exc).__name__}: {exc}"))
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
    write_status(success_status())
    sys.exit(code)
