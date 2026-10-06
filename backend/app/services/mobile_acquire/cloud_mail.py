"""Optional cloud mailbox acquisition (Gmail / Outlook via IMAP).

Device USB collection only sees mail that is on the handset. Full cloud
mailboxes require examiner-supplied credentials (app password / OAuth IMAP).
This module downloads folders over IMAP into the case package.
"""

from __future__ import annotations

import email
import imaplib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_SAFE = re.compile(r"[^A-Za-z0-9_.@+-]+")


@dataclass
class CloudMailboxCredential:
    provider: str  # gmail | outlook | imap
    address: str
    secret: str  # app password or account password
    host: str = ""
    port: int = 993

    def as_public_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "address": self.address,
            "host": self.resolved_host(),
            "port": self.port,
            "secret_present": bool(self.secret),
        }

    def resolved_host(self) -> str:
        if self.host:
            return self.host
        p = (self.provider or "").lower().strip()
        if p == "gmail":
            return "imap.gmail.com"
        if p in ("outlook", "office365", "hotmail", "live"):
            return "outlook.office365.com"
        return self.host or "imap.gmail.com"


@dataclass
class CloudMailResult:
    ok: bool = False
    accounts: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    output_root: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "accounts": self.accounts,
            "errors": self.errors,
            "output_root": self.output_root,
        }


def _safe_name(value: str) -> str:
    return _SAFE.sub("_", (value or "mailbox").strip())[:120] or "mailbox"


def _parse_credentials(raw: list[dict[str, Any]] | None) -> list[CloudMailboxCredential]:
    out: list[CloudMailboxCredential] = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        address = str(item.get("address") or item.get("email") or "").strip()
        secret = str(item.get("secret") or item.get("password") or item.get("app_password") or "")
        if not address or not secret:
            continue
        out.append(
            CloudMailboxCredential(
                provider=str(item.get("provider") or "imap"),
                address=address,
                secret=secret,
                host=str(item.get("host") or ""),
                port=int(item.get("port") or 993),
            )
        )
    return out


def collect_cloud_mailboxes(
    dest_root: Path,
    credentials: list[dict[str, Any]] | None,
    *,
    max_messages_per_folder: int = 2000,
    progress: Any = None,
) -> CloudMailResult:
    """Download IMAP mail for each credential into dest_root/cloud_mail/<address>/."""
    result = CloudMailResult()
    creds = _parse_credentials(credentials)
    if not creds:
        return result

    root = Path(dest_root) / "cloud_mail"
    root.mkdir(parents=True, exist_ok=True)
    result.output_root = str(root)

    for cred in creds:
        account_dir = root / _safe_name(cred.address)
        account_dir.mkdir(parents=True, exist_ok=True)
        account: dict[str, Any] = {
            **cred.as_public_dict(),
            "folders": [],
            "messages": 0,
            "ok": False,
            "error": "",
        }
        if progress:
            try:
                progress({
                    "stage": "acquire",
                    "item": f"cloud_mail/{cred.address}",
                    "detail": f"Fetching cloud mailbox {cred.address} via IMAP…",
                    "category": "Cloud mail",
                })
            except Exception:
                pass
        try:
            client = imaplib.IMAP4_SSL(cred.resolved_host(), cred.port)
            client.login(cred.address, cred.secret)
            typ, folder_data = client.list()
            folders: list[str] = []
            if typ == "OK" and folder_data:
                for raw in folder_data:
                    line = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                    # Last token is folder name (possibly quoted).
                    parts = line.rsplit(" ", 1)
                    name = parts[-1].strip().strip('"') if parts else ""
                    if name:
                        folders.append(name)
            if not folders:
                folders = ["INBOX"]

            for folder in folders:
                safe_folder = _safe_name(folder)
                folder_dir = account_dir / safe_folder
                folder_dir.mkdir(parents=True, exist_ok=True)
                try:
                    typ, _ = client.select(f'"{folder}"', readonly=True)
                    if typ != "OK":
                        typ, _ = client.select(folder, readonly=True)
                    if typ != "OK":
                        continue
                    typ, data = client.search(None, "ALL")
                    if typ != "OK" or not data or not data[0]:
                        account["folders"].append({"folder": folder, "messages": 0})
                        continue
                    ids = data[0].split()
                    ids = ids[-max_messages_per_folder:]
                    count = 0
                    for num in ids:
                        typ, msg_data = client.fetch(num, "(RFC822)")
                        if typ != "OK" or not msg_data or not msg_data[0]:
                            continue
                        raw_email = msg_data[0][1]
                        if not isinstance(raw_email, (bytes, bytearray)):
                            continue
                        path = folder_dir / f"{int(num)}.eml"
                        path.write_bytes(raw_email)
                        count += 1
                    account["folders"].append({"folder": folder, "messages": count})
                    account["messages"] += count
                except Exception as exc:
                    account["folders"].append({"folder": folder, "error": str(exc)})

            client.logout()
            account["ok"] = account["messages"] > 0
            (account_dir / "account_manifest.json").write_text(
                json.dumps({
                    **account,
                    "collected_utc": datetime.now(timezone.utc).isoformat(),
                }, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            account["error"] = str(exc)
            account["ok"] = False
            result.errors.append(f"{cred.address}: {exc}")
            (account_dir / "account_error.txt").write_text(str(exc), encoding="utf-8")

        result.accounts.append(account)

    result.ok = any(a.get("ok") for a in result.accounts)
    return result
