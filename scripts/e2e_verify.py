#!/usr/bin/env python3
"""Manual end-to-end verification for Phase 1 IAM flows."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE = "http://localhost:8080"
MAILHOG = "http://localhost:8025"
PLATFORM_EMAIL = "superadmin@admin.com"
PLATFORM_PASSWORD = "admin@123456789"
FIRM_SLUG = f"acme-{int(time.time())}"
ADMIN_EMAIL = f"admin.{FIRM_SLUG}@acme.test"
USER_EMAIL = f"analyst.{FIRM_SLUG}@acme.test"


def request(method: str, path: str, body: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
    payload = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path,
        data=payload,
        headers={"Content-Type": "application/json", **(headers or {})},
        method=method,
    )
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw) if raw else {"error": {"message": str(exc)}}


def schema_for_slug(slug: str) -> str:
    return f"firm_{slug.replace('-', '_')}"


def latest_invite_token(firm_slug: str, recipient: str) -> str:
    """Read pending invite token from DB (works with Gmail SMTP in dev)."""
    schema = schema_for_slug(firm_slug)
    email = recipient.lower()
    sql = (
        f"SELECT i.token_plain FROM \"{schema}\".invitations i "
        f"JOIN \"{schema}\".users u ON u.id = i.user_id "
        f"WHERE lower(u.email) = '{email}' AND i.accepted_at IS NULL "
        f"ORDER BY i.created_at DESC LIMIT 1;"
    )
    proc = subprocess.run(
        ["docker", "compose", "exec", "-T", "postgres", "psql", "-U", "forensic", "-d", "forensic", "-t", "-A", "-c", sql],
        capture_output=True,
        text=True,
        cwd=r"e:\rag_new2",
    )
    token = (proc.stdout or "").strip()
    if token:
        return token
    try:
        return latest_mailhog_token(recipient)
    except RuntimeError as exc:
        raise RuntimeError(f"Invite token not found for {recipient}: {proc.stderr or exc}") from exc
    with urllib.request.urlopen(f"{MAILHOG}/api/v2/messages") as resp:
        data = json.load(resp)
    items = data.get("items") or []
    if not items:
        raise RuntimeError("No messages in MailHog")
    for item in items:
        to_text = json.dumps(item.get("To"))
        local, _, domain = recipient.partition("@")
        if local.lower() not in to_text.lower() or domain.lower() not in to_text.lower():
            continue
        body = item["Content"]["Body"]
        if "Activate your account" in body or "Invitation token:" in body:
            segment = body.split("token=", 1)[1] if "token=" in body else body.split("Invitation token:", 1)[1]
            match = re.search(r"([A-Za-z0-9_-]{40,})", segment)
            if match:
                return match.group(1)
        match = re.search(r"token=([^&]+)", body)
        if match:
            return re.sub(r"\s+", "", match.group(1))
    raise RuntimeError(f"Invite token not found for {recipient}")


def main() -> int:
    print("1. Platform login...")
    status, login = request(
        "POST",
        "/api/auth/login",
        {"email": PLATFORM_EMAIL, "password": PLATFORM_PASSWORD},
        {"X-Tenant": "platform"},
    )
    if status != 200:
        print("FAIL login:", status, login)
        return 1
    platform_auth = {
        "Authorization": f"Bearer {login['access_token']}",
        "X-Tenant": "platform",
    }

    print("2. Provision firm...")
    status, firm = request(
        "POST",
        "/api/tenants",
        {
            "name": "Acme Forensics",
            "slug": FIRM_SLUG,
            "plan": "standard",
            "admin_email": ADMIN_EMAIL,
        },
        platform_auth,
    )
    if status not in (200, 400):
        print("FAIL provision:", status, firm)
        return 1
    if status == 400:
        print("FAIL provision:", firm)
        return 1

    print("3. Firm admin invite activation...")
    time.sleep(1)
    token = latest_invite_token(FIRM_SLUG, ADMIN_EMAIL)
    status, preview = request(
        "GET",
        f"/api/auth/invite/status?token={token}&tenant={FIRM_SLUG}",
        None,
        {"X-Tenant": FIRM_SLUG},
    )
    if status != 200 or not preview.get("valid"):
        print("FAIL invite preview:", status, preview)
        return 1
    status, activate = request(
        "POST",
        "/api/auth/activate",
        {"token": token, "new_password": "AcmeAdmin!2026X", "tenant": FIRM_SLUG},
        {"X-Tenant": FIRM_SLUG},
    )
    if status != 200:
        print("FAIL admin activate:", status, activate, "(token length:", len(token), ")")
        return 1

    print("4. Firm admin login...")
    status, flogin = request(
        "POST",
        "/api/auth/login",
        {"email": ADMIN_EMAIL, "password": "AcmeAdmin!2026X"},
        {"X-Tenant": FIRM_SLUG},
    )
    if status != 200:
        print("FAIL firm login:", status, flogin)
        return 1
    firm_auth = {
        "Authorization": f"Bearer {flogin['access_token']}",
        "X-Tenant": FIRM_SLUG,
    }

    print("5. Invite firm user...")
    status, roles = request("GET", "/api/roles", None, firm_auth)
    user_role = next(r for r in roles if r["name"] == "user")
    status, user = request(
        "POST",
        "/api/users",
        {
            "email": USER_EMAIL,
            "role_ids": [user_role["id"]],
            "profile": {"first_name": "Case", "last_name": "Analyst"},
        },
        firm_auth,
    )
    if status != 200:
        print("FAIL invite:", status, user)
        return 1

    print("6. User activation + login...")
    time.sleep(1)
    token = latest_invite_token(FIRM_SLUG, USER_EMAIL)
    status, _ = request(
        "POST",
        "/api/auth/activate",
        {"token": token, "new_password": "AnalystUser!2026X", "tenant": FIRM_SLUG},
        {"X-Tenant": FIRM_SLUG},
    )
    if status != 200:
        print("FAIL user reset:", status, _)
        return 1

    status, ulogin = request(
        "POST",
        "/api/auth/login",
        {"email": USER_EMAIL, "password": "AnalystUser!2026X"},
        {"X-Tenant": FIRM_SLUG},
    )
    if status != 200:
        print("FAIL user login:", status, ulogin)
        return 1
    user_auth = {
        "Authorization": f"Bearer {ulogin['access_token']}",
        "X-Tenant": FIRM_SLUG,
    }

    print("7. Firm user isolation (profile only)...")
    status, denied = request("GET", "/api/users", None, user_auth)
    if status != 403:
        print("FAIL user should not list users:", status, denied)
        return 1
    status, roles_denied = request("GET", "/api/roles", None, user_auth)
    if status != 403:
        print("FAIL user should not list roles:", status, roles_denied)
        return 1
    status, me = request("GET", "/api/users/me", None, user_auth)
    if status != 200:
        print("FAIL user profile:", status, me)
        return 1

    print("Phase 1 E2E verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
