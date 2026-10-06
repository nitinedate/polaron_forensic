"""Read already-accessible Android private app/system files over ADB + existing su.

Forensic guardrails:
- Does not root, exploit, unlock, bypass a screen lock, or alter boot state.
- Runs only when ``su -c id`` already returns uid=0 (or adbd itself is uid=0).
- Reads files one-by-one with ``adb exec-out ... cat`` and writes them into the
  acquisition directory. No temporary files are created on the handset.
- Paths are allow-listed to known app/system evidence roots.

This module is used by the Windows host acquisition helper because ``adb pull
/data/data`` cannot use ``su`` on production Android builds even when a root
manager is already available to the examiner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile
import threading
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from app.services.mobile_acquire.app_catalog import ANDROID_SOCIAL_PACKAGES

# Native/system providers that contain high-value mobile artifacts.
SYSTEM_PRIVATE_ROOTS: tuple[str, ...] = (
    "/data/user_de/0/com.android.providers.telephony/databases",
    "/data/user/0/com.android.providers.telephony/databases",
    "/data/data/com.android.providers.telephony/databases",
    "/data/user_de/0/com.android.providers.contacts/databases",
    "/data/user/0/com.android.providers.contacts/databases",
    "/data/data/com.android.providers.contacts/databases",
    "/data/user_de/0/com.android.providers.calendar/databases",
    "/data/user/0/com.android.providers.calendar/databases",
    "/data/data/com.android.providers.calendar/databases",
    "/data/user_de/0/com.android.providers.media/databases",
    "/data/user/0/com.android.providers.media/databases",
    "/data/data/com.android.providers.media/databases",
    "/data/system/users",
    "/data/system_ce",
    "/data/system_de",
)

# Chromium private data is useful for browser history/downloads. Keep package
# roots explicit so this helper cannot become an arbitrary remote-file reader.
EXTRA_APP_PACKAGES: tuple[str, ...] = (
    "com.android.chrome",
    "com.sec.android.app.sbrowser",
    "org.mozilla.firefox",
    "com.brave.browser",
    "com.microsoft.emmx",
)


def _run(args: list[str], *, timeout: int = 30, binary: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
        text=not binary,
    )


def _adb_prefix(adb: str, serial: str) -> list[str]:
    return [adb] + (["-s", serial] if serial else [])


def _root_mode(adb: str, serial: str) -> str | None:
    prefix = _adb_prefix(adb, serial)
    try:
        direct = _run(prefix + ["shell", "id"], timeout=10)
        if direct.returncode == 0 and re.search(r"\buid=0(?:\D|$)", direct.stdout or ""):
            return "adbd_root"
    except Exception:
        pass
    try:
        su = _run(prefix + ["shell", "su", "-c", "id"], timeout=12)
        if su.returncode == 0 and re.search(r"\buid=0(?:\D|$)", su.stdout or ""):
            return "su"
    except Exception:
        pass
    return None


def _command(adb: str, serial: str, mode: str, command: str, *, binary=False):
    # ADB concatenates remote arguments for a remote shell. Quote the complete
    # -c argument, otherwise su/run-as can execute a bare cat without its path.
    if mode == "su":
        remote = f"su -c {shlex.quote(command)}"
    elif mode.startswith("run_as:"):
        package = mode.split(":", 1)[1]
        remote = f"run-as {shlex.quote(package)} sh -c {shlex.quote(command)}"
    else:
        remote = f"sh -c {shlex.quote(command)}"
    return _adb_prefix(adb, serial) + ["exec-out" if binary else "shell", remote]


def _android_users(adb: str, serial: str) -> list[int]:
    try:
        cp = _run(_adb_prefix(adb, serial) + ["shell", "pm list users"], timeout=20)
        return sorted({0, *(int(value) for value in re.findall(r"UserInfo\{(\d+):", cp.stdout or ""))})
    except Exception:
        return [0]


def _remote_exists(adb: str, serial: str, mode: str, remote: str) -> bool:
    quoted = shlex.quote(remote)
    cmd = f"test -e {quoted} && echo EXISTS"
    args = _command(adb, serial, mode, cmd)
    try:
        cp = _run(args, timeout=12)
        return "EXISTS" in (cp.stdout or "")
    except Exception:
        return False


def _list_files(adb: str, serial: str, mode: str, root: str) -> list[str]:
    quoted = shlex.quote(root)
    # NUL delimiters preserve spaces, newlines and Unicode in evidence names.
    cmd = f"find {quoted} -xdev -type f -print0 2>/dev/null"
    args = _command(adb, serial, mode, cmd)
    try:
        cp = _run(args, timeout=180, binary=True)
    except Exception:
        return []
    output = cp.stdout or b""
    if isinstance(output, bytes):
        output = output.decode("utf-8", "surrogateescape")
    return [path for path in output.split("\x00") if path.startswith(root + "/")]


def _safe_rel(remote: str) -> Path:
    parts = [p for p in PurePosixPath(remote).parts if p not in {"/", "", ".", ".."}]
    return Path(*parts)


def _cat_file(adb: str, serial: str, mode: str, remote: str, dest: Path) -> tuple[bool, str]:
    quoted = shlex.quote(remote)
    args = _command(adb, serial, mode, f"cat {quoted}", binary=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=dest.parent,prefix=".acquire-",delete=False) as output, tempfile.TemporaryFile() as errors:
            temporary = Path(output.name)
            with subprocess.Popen(args,stdout=subprocess.PIPE,stderr=errors) as process:
                key_read = "com.whatsapp" in remote and PurePosixPath(remote).name.lower() in {"key", "encrypted_backup.key"}
                timer = threading.Timer(30 if key_read else 1800, process.kill)
                timer.daemon = True
                timer.start()
                try:
                    for block in iter(lambda:process.stdout.read(1024*1024),b""):
                        output.write(block)
                    code = process.wait()
                finally:
                    timer.cancel()
                if code:
                    errors.seek(0)
                    message = errors.read(240).decode("utf-8","replace")
                    return False,message or f"exit {code}"
            output.flush()
            os.fsync(output.fileno())
        if "com.whatsapp" in remote:
            from app.services.mobile_forensic.whatsapp_crypt import is_acquisition_error, parse_key_material

            with temporary.open("rb") as evidence:
                head = evidence.read(512)
            name = PurePosixPath(remote).name.lower()
            if is_acquisition_error(head):
                return False, "Command error output rejected; no evidence file written"
            if name in {"key", "encrypted_backup.key"} and (
                temporary.stat().st_size > 512 or parse_key_material(head) is None
            ):
                return False, "Invalid WhatsApp key material rejected; no key file written"
        temporary.replace(dest)
        return True,""
    except Exception as exc:
        return False,str(exc)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def _write_progress(path: str, payload: dict[str, Any]) -> None:
    if not path:
        return
    try:
        Path(path).write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        pass


def _candidate_roots(packages: Iterable[str], include_system: bool, users: Iterable[int] = (0,)) -> list[str]:
    roots: list[str] = []
    seen: set[str] = set()
    for pkg in packages:
        pkg = (pkg or "").strip()
        if not pkg or not all(c.isalnum() or c in "._" for c in pkg):
            continue
        app_roots = [f"/data/{scope}/{user}/{pkg}" for user in users for scope in ("user", "user_de")]
        for root in (*app_roots, f"/data/data/{pkg}"):
            if root not in seen:
                roots.append(root)
                seen.add(root)
    if include_system:
        system_roots = [root.replace("/0/", f"/{user}/") for user in users for root in SYSTEM_PRIVATE_ROOTS]
        for root in system_roots:
            if root not in seen:
                roots.append(root)
                seen.add(root)
    return roots


def _priority_files(adb: str, serial: str, mode: str, root: str, *, keys_only: bool = False):
    """Read key files before a potentially slow or denied recursive listing."""
    seen = set()
    if root.rsplit("/", 1)[-1] in {"com.whatsapp", "com.whatsapp.w4b"}:
        for name in ("key", "encrypted_backup.key"):
            remote = f"{root}/files/{name}"
            if _remote_exists(adb, serial, mode, remote):
                seen.add(remote)
                yield remote
    if keys_only:
        return
    for remote in sorted(_list_files(adb, serial, mode, root),
                         key=lambda path: (0 if path.endswith(("/files/key", "/files/encrypted_backup.key")) else
                                           1 if "/databases/" in path else 2, path)):
        if remote not in seen:
            seen.add(remote)
            yield remote


def _record_key_capture(result, remote: str, dest: Path) -> None:
    if "com.whatsapp" not in remote or PurePosixPath(remote).name not in {"key", "encrypted_backup.key"}:
        return
    from app.services.mobile_forensic.whatsapp_crypt import parse_key_material
    try:
        with dest.open("rb") as stream:
            material = stream.read(513)
        key = parse_key_material(material) if len(material) <= 512 else None
        if not key:
            return
        record = {"source_path": remote, "case_file": str(dest), "size_bytes": len(material),
                  "sha256": hashlib.sha256(material).hexdigest(), "key_kind": key.kind}
        if len(material) == 158:
            record["key_offset"] = 126
        result.setdefault("whatsapp_key_files", []).append(record)
    except OSError:
        pass


def pull_private_evidence(
    *,
    adb: str,
    serial: str,
    out: Path,
    progress_file: str = "",
    packages: Iterable[str] = (),
    include_system: bool = True,
    max_files: int = 0,
    cancel=None,
    keys_only: bool = False,
) -> dict[str, Any]:
    mode = _root_mode(adb, serial)
    result: dict[str, Any] = {
        "ok": False,
        "root_mode": mode or "unavailable",
        "files": 0,
        "bytes": 0,
        "roots_scanned": 0,
        "roots_present": 0,
        "errors": [],
        "limitations": [],
        "whatsapp_key_files": [],
    }
    if not mode:
        result["limitations"].append(
            "Private application data was not acquired because the device did not already provide root/su access. "
            "No rooting or lock bypass was attempted."
        )
        return result

    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    pkg_set = list(dict.fromkeys(tuple(packages) or (ANDROID_SOCIAL_PACKAGES + EXTRA_APP_PACKAGES)))
    if keys_only:
        pkg_set = [package for package in pkg_set if package in {"com.whatsapp", "com.whatsapp.w4b"}]
        include_system = False
    rank = {"com.whatsapp":0,"com.whatsapp.w4b":1,**{p:2+i for i,p in enumerate(EXTRA_APP_PACKAGES)}}
    pkg_set.sort(key=lambda pkg:(rank.get(pkg,99),pkg))
    users = _android_users(adb, serial)
    result["android_users"] = users
    roots = _candidate_roots(pkg_set, include_system, users)

    collected_app_packages: set[tuple[int, str]] = set()
    for root in roots:
        if cancel and cancel():
            result["interrupted"] = True
            result["limitations"].append("Acquisition paused by examiner before reading private app data.")
            break
        # /data/data/<pkg> is normally an alias of /data/user/0/<pkg>. Prefer
        # user/0 and do not duplicate the same private app tree when both exist.
        app_identity = None
        match = re.match(r"^/data/user/(\d+)/([^/]+)$", root)
        if match:
            app_identity = (int(match[1]), match[2])
        elif root.startswith("/data/data/"):
            app_identity = (0, root[len("/data/data/"):].split("/", 1)[0])
            if app_identity in collected_app_packages:
                continue
        if max_files and int(result["files"]) >= max_files:
            result["limitations"].append(f"Stopped after configured max_files={max_files}.")
            break
        result["roots_scanned"] += 1
        if not _remote_exists(adb, serial, mode, root):
            continue
        result["roots_present"] += 1
        if app_identity:
            collected_app_packages.add(app_identity)
        files = _priority_files(adb, serial, mode, root, keys_only=keys_only)
        for remote in files:
            if not remote.startswith(root + "/"):
                continue
            if cancel and cancel():
                result["interrupted"] = True
                break
            if max_files and int(result["files"]) >= max_files:
                break
            dest = out / _safe_rel(remote)
            ok, err = _cat_file(adb, serial, mode, remote, dest)
            if not ok:
                if len(result["errors"]) < 100:
                    result["errors"].append(f"{remote}: {err}")
                continue
            try:
                size = dest.stat().st_size
            except OSError:
                size = 0
            result["files"] += 1
            result["bytes"] += int(size)
            _record_key_capture(result, remote, dest)
            if int(result["files"]) % 10 == 0:
                _write_progress(
                    progress_file,
                    {
                        "stage": "acquire",
                        "item": "android_private_apps",
                        "files_seen": int(result["files"]),
                        "bytes_done": int(result["bytes"]),
                        "detail": f"Private app/system data: {result['files']} file(s)",
                        "category": "Collecting private application data",
                    },
                )

    result["ok"] = int(result["files"]) > 0
    _write_progress(
        progress_file,
        {
            "stage": "acquire",
            "item": "android_private_apps",
            "files_seen": int(result["files"]),
            "bytes_done": int(result["bytes"]),
            "detail": f"Private app/system acquisition complete: {result['files']} file(s)",
            "category": "Collected private application data",
        },
    )
    return result


def pull_debuggable_evidence(*, adb: str, serial: str, out: Path, packages=(), cancel=None, keys_only=False, **_kwargs):
    """Use run-as only when Android already permits it for that installed app."""
    result = {"ok": False, "root_mode": "run_as", "files": 0, "bytes": 0, "errors": [], "limitations": [], "apps_accessible": [], "whatsapp_key_files": []}
    for package in packages or ("com.whatsapp", "com.whatsapp.w4b"):
        if cancel and cancel():
            result["interrupted"] = True
            break
        if not re.fullmatch(r"[A-Za-z0-9_.]+", package):
            continue
        try:
            cp = _run(_adb_prefix(adb, serial) + ["shell", f"run-as {shlex.quote(package)} pwd"], timeout=12)
            root = (cp.stdout or "").strip()
        except Exception:
            continue
        if cp.returncode or not re.fullmatch(rf"/data/(?:user/\d+|data)/{re.escape(package)}", root):
            result["limitations"].append(f"run-as unavailable for {package}; private databases/keys were not collected by this route.")
            continue
        result["apps_accessible"].append(package)
        mode = f"run_as:{package}"
        for remote in _priority_files(adb, serial, mode, root, keys_only=keys_only):
            if cancel and cancel():
                result["interrupted"] = True
                break
            if not remote.startswith(root + "/"):
                continue
            dest = Path(out) / _safe_rel(remote)
            ok, error = _cat_file(adb, serial, mode, remote, dest)
            if ok:
                result["files"] += 1
                result["bytes"] += dest.stat().st_size
                _record_key_capture(result, remote, dest)
            elif len(result["errors"]) < 100:
                result["errors"].append(f"{remote}: {error}")
    result["ok"] = result["files"] > 0
    return result


def pull_whatsapp_key_evidence(*, adb: str, serial: str, out: Path, cancel=None, progress_file="", **_kwargs):
    """Small acquisition step for every live Android route; existing privileges only."""
    arguments = {"adb": adb, "serial": serial, "out": out, "cancel": cancel,
                 "packages": ("com.whatsapp", "com.whatsapp.w4b"), "keys_only": True}
    result = pull_private_evidence(**arguments, include_system=False, progress_file=progress_file)
    if result.get("root_mode") == "unavailable":
        result = pull_debuggable_evidence(**arguments)
    if not result.get("whatsapp_key_files"):
        result["limitations"].append("No readable matching WhatsApp device key was collected. A fuller authorized acquisition or an acquired key-file upload in Intake is required.")
    _write_progress(progress_file, {"stage": "acquire", "item": "whatsapp_keys", "files_seen": result["files"],
                                   "bytes_done": result["bytes"], "detail": f"WhatsApp key capture: {len(result.get('whatsapp_key_files', []))} validated file(s)"})
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Read already-accessible Android private evidence via existing root/su")
    p.add_argument("--adb", default="adb")
    p.add_argument("--serial", default="")
    p.add_argument("--out", required=True)
    p.add_argument("--progress", default="")
    p.add_argument("--packages", default="")
    p.add_argument("--no-system", action="store_true")
    p.add_argument("--max-files", type=int, default=0)
    p.add_argument("--run-as", action="store_true", help="Read already-debuggable apps without root")
    p.add_argument("--keys-only", action="store_true", help="Prioritize WhatsApp key files without walking private app trees")
    args = p.parse_args(argv)
    packages = [x.strip() for x in args.packages.split(",") if x.strip()] if args.packages else []
    reader = pull_whatsapp_key_evidence if args.keys_only else (pull_debuggable_evidence if args.run_as else pull_private_evidence)
    result = reader(
        adb=args.adb,
        serial=args.serial,
        out=Path(args.out),
        progress_file=args.progress,
        packages=packages,
        include_system=not args.no_system,
        max_files=max(0, int(args.max_files or 0)),
    )
    print(json.dumps(result))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
