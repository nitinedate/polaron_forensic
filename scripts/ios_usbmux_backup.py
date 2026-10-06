#!/usr/bin/env python3
"""iTunes-style backup via Apple usbmux (no idevicebackup2 required).

Uses the repo examiner kit: tools\\host-python + pymobiledevice3.
Writes a short Windows staging tree, then the host helper junctions that
folder into the case. Never write Snapshot hashes under a long CASE- path.

Windows MAX_PATH is 260. A case-folder dest such as
.../02_Original_Extraction/<long_run>/ios_image/<UDID>/Snapshot/ab/<40-hex>
overflows that and pymobiledevice3 raises FileNotFoundError mid-backup.

A dropped USB session (ConnectionTerminatedError) is retried as a resume
(full=False). An empty Manifest.plist that pymobiledevice3 touches at start
is not a finished backup.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

# dest/UDID/Snapshot/xx/40-hex  (~80 chars under dest). Stay under 240.
_MAX_SAFE_ABS = 240
_RETRY_SLEEP_SEC = int(os.environ.get("IOS_BACKUP_RETRY_SLEEP_SEC") or "8")
_MAX_ATTEMPTS = int(os.environ.get("IOS_BACKUP_MAX_ATTEMPTS") or "16")
_CANDIDATE_LETTERS = ("F", "D", "C", "E")
# Earlier iPhone collection on this examiner was ~69 GiB. Skip a volume that
# cannot hold another Advanced Logical (E: filled and then looked like Manifest-missing).
_MIN_FREE_GB = float(os.environ.get("IOS_BACKUP_MIN_FREE_GB") or "80")
_DEFAULT_BACKUP_RESERVE_GB = float(os.environ.get("IOS_BACKUP_RESERVE_GB") or "12")


def backup_tree_would_exceed_max_path(dest: str, udid: str) -> bool:
    sample = os.path.join(os.path.abspath(dest), udid, "Snapshot", "aa", "a" * 40)
    return len(sample) >= _MAX_SAFE_ABS


def _drive_free_bytes(letter: str) -> int:
    try:
        return int(shutil.disk_usage(f"{letter}:/").free)
    except OSError:
        return -1


def _as_int(value) -> int:
    try:
        if isinstance(value, str):
            value = value.strip().replace(",", "")
        return int(value)
    except (TypeError, ValueError):
        return 0


def _device_used_bytes(lockdown) -> tuple[int, dict]:
    """Return a conservative iPhone data-used estimate from lockdownd.

    Apple exposes TotalDataCapacity / TotalDataAvailable under com.apple.disk_usage
    on supported versions.  The exact backup can be smaller than used storage, but
    sizing to used+reserve prevents the old 80 GiB fixed threshold from filling a
    volume late in a 100+ GiB collection.
    """
    info: dict = {}
    try:
        value = lockdown.get_value(domain="com.apple.disk_usage")
        if isinstance(value, dict):
            info = value
    except Exception:
        try:
            value = lockdown.get_value("com.apple.disk_usage")
            if isinstance(value, dict):
                info = value
        except Exception:
            info = {}
    capacity = _as_int(info.get("TotalDataCapacity"))
    available = _as_int(info.get("TotalDataAvailable"))
    if capacity > 0 and 0 <= available <= capacity:
        return max(0, capacity - available), info
    return 0, info


def required_backup_free_bytes(lockdown=None, override: int = 0) -> tuple[int, dict]:
    if override and override > 0:
        return int(override), {"source": "cli_override"}
    env_override = _as_int(os.environ.get("IOS_BACKUP_REQUIRED_FREE_BYTES"))
    if env_override > 0:
        return env_override, {"source": "environment"}
    floor = int(_MIN_FREE_GB * 1024**3)
    if lockdown is None:
        return floor, {"source": "fallback_minimum"}
    used, disk_info = _device_used_bytes(lockdown)
    if used <= 0:
        return floor, {"source": "fallback_minimum", "disk_usage": disk_info}
    reserve = max(int(_DEFAULT_BACKUP_RESERVE_GB * 1024**3), int(used * 0.10))
    required = max(floor, used + reserve)
    return required, {
        "source": "device_disk_usage",
        "used_bytes": used,
        "reserve_bytes": reserve,
        "disk_usage": disk_info,
    }


def _volume_inventory() -> list[dict]:
    out: list[dict] = []
    for letter in _CANDIDATE_LETTERS:
        try:
            if not Path(f"{letter}:/").exists():
                continue
        except OSError:
            continue
        out.append({"letter": letter, "free_bytes": _drive_free_bytes(letter)})
    return sorted(out, key=lambda row: int(row.get("free_bytes") or -1), reverse=True)


def _is_disk_full(exc: BaseException) -> bool:
    name = type(exc).__name__
    if name in {"NotEnoughDiskSpaceError", "ENOSPC", "DiskFull"}:
        return True
    lowered = (str(exc) or "").lower()
    return any(
        token in lowered
        for token in (
            "notenoughdiskspace",
            "not enough disk",
            "no space left",
            "there is not enough space",
            "disk full",
            "winerror 112",
        )
    )


def short_staging_root(
    udid: str,
    stamp: str = "",
    exclude_letters: set[str] | None = None,
    min_free_bytes: int | None = None,
    preferred_letter: str = "",
    require_fit: bool = False,
) -> Path:
    tail = "".join(ch for ch in udid if ch.isalnum())[-8:] or "ios"
    safe_stamp = re.sub(r"[^\w\-]", "", stamp or "")[:20]
    if not safe_stamp:
        safe_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    need = int(_MIN_FREE_GB * 1024**3) if min_free_bytes is None else int(min_free_bytes)
    skip = {letter.upper() for letter in (exclude_letters or set())}

    ranked: list[tuple[int, str]] = []
    for letter in _CANDIDATE_LETTERS:
        if letter in skip:
            continue
        try:
            if not Path(f"{letter}:/").exists():
                continue
        except OSError:
            continue
        ranked.append((_drive_free_bytes(letter), letter))
    ranked.sort(reverse=True)

    chosen = ""
    preferred = (preferred_letter or "").upper().rstrip(":")
    if preferred and preferred not in skip:
        for free, letter in ranked:
            if letter == preferred and free >= need:
                chosen = letter
                break
    if not chosen:
        for free, letter in ranked:
            if free >= need:
                chosen = letter
                break
    if not chosen and not require_fit and ranked and ranked[0][0] > 5 * 1024**3:
        chosen = ranked[0][1]
    if chosen:
        dest = Path(f"{chosen}:/ib") / tail / safe_stamp
        dest.mkdir(parents=True, exist_ok=True)
        return dest
    if require_fit:
        best = ranked[0][0] if ranked else -1
        raise OSError(f"No iOS staging volume has required free space: required={need} best_free={best}")
    dest = Path(os.environ.get("TEMP") or ".") / "ib" / tail / safe_stamp
    dest.mkdir(parents=True, exist_ok=True)
    return dest


def _staging_free_bytes(root: Path) -> int:
    try:
        return int(shutil.disk_usage(root.anchor or str(root)).free)
    except OSError:
        return -1


def _progress(pct) -> None:
    try:
        value = float(pct)
    except (TypeError, ValueError):
        value = 0.0
    print(json.dumps({"progress": round(value, 2), "pct": round(value, 2)}), flush=True)


def _manifest_complete(root: Path, udid: str) -> Path | None:
    """Real finished backup only — empty Manifest.plist.touch() does not count."""
    nested = root / udid
    db = nested / "Manifest.db"
    if db.is_file() and db.stat().st_size > 64:
        return nested
    plist = nested / "Manifest.plist"
    if plist.is_file() and plist.stat().st_size > 64:
        return nested
    return None


def _is_transient(exc: BaseException) -> bool:
    if _is_disk_full(exc):
        return False
    name = type(exc).__name__
    msg = str(exc) or ""
    if name in {
        "ConnectionTerminatedError",
        "ConnectionAbortedError",
        "BrokenPipeError",
        "ConnectionResetError",
        "TimeoutError",
        "MuxException",
        "ConnectionError",
        "SSLError",
        "ProtocolError",
    }:
        return True
    lowered = msg.lower()
    return any(
        token in lowered
        for token in (
            "connection terminated",
            "connection aborted",
            "broken pipe",
            "winerror 10054",
            "winerror 10053",
            "timed out",
            "mux",
            "ssl",
            "eof",
            "device disconnected",
            "not connected",
        )
    )


def classify_backup_failure(exc: BaseException | None, dest: Path | None = None) -> dict:
    """Map a backup exception to a stable error code.

    Disk-full must never become Manifest-missing / unlock-the-phone.
    """
    payload: dict = {"ok": False, "dest": str(dest) if dest else ""}
    if dest is not None:
        payload["drive_free_bytes"] = _staging_free_bytes(dest)
    if exc is not None and _is_disk_full(exc):
        payload["error"] = "ios_backup_not_enough_disk_space"
        payload["type"] = "ios_backup_not_enough_disk_space"
        payload["detail"] = str(exc) or type(exc).__name__
        return payload
    if exc is None:
        payload["error"] = "ios_backup_incomplete_no_manifest_usb_may_have_dropped"
        payload["type"] = "ios_backup_incomplete"
        return payload
    err = str(exc) or type(exc).__name__
    code = type(exc).__name__
    if isinstance(exc, FileNotFoundError) or "Snapshot" in err or "No such file or directory" in err:
        code = "ios_backup_windows_path_too_long"
    payload["error"] = err
    payload["type"] = code
    return payload


def _emit(payload: dict) -> None:
    print(json.dumps(payload), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Backup a paired iPhone over usbmux")
    parser.add_argument("--udid", required=True)
    parser.add_argument("--dest", required=True, help="Requested backup root (used only if short enough)")
    parser.add_argument("--stamp", default="", help="Unique per-run staging folder name")
    parser.add_argument("--required-free-bytes", type=int, default=0,
                        help="Minimum free bytes required on the iOS staging volume")
    args = parser.parse_args()

    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)

    try:
        from pymobiledevice3.lockdown import create_using_usbmux
        from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
    except Exception as exc:
        _emit({"ok": False, "error": f"import_failed: {exc}", "type": type(exc).__name__})
        return 1

    try:
        from app.services.mobile_acquire.ios_usbmux import resolve_ios_udid

        udid = resolve_ios_udid(args.udid)
        if not udid:
            _emit({"ok": False, "error": "ios_udid_unresolved", "type": "DeviceNotFoundError"})
            return 1

        # Query the device before choosing a staging volume.  The previous fixed
        # 80 GiB floor allowed a ~120 GiB-used phone to fill F:\ib near the end.
        sizing_lockdown = create_using_usbmux(serial=udid)
        need_bytes, sizing = required_backup_free_bytes(sizing_lockdown, args.required_free_bytes)
        try:
            sizing_lockdown.close()
        except Exception:
            pass
        preferred = str(dest.resolve())[:1] if len(str(dest.resolve())) > 1 and str(dest.resolve())[1:2] == ":" else ""
        _emit({
            "stage": "storage_preflight",
            "required_free_bytes": need_bytes,
            "sizing": sizing,
            "volumes": _volume_inventory(),
            "requested_dest": str(dest),
        })

        # Always stage on Windows. Unique stamp keeps leftover X:\ib\<tail> from mixing runs.
        if os.name == "nt" or backup_tree_would_exceed_max_path(str(dest), udid):
            try:
                write_root = short_staging_root(
                    udid, args.stamp, min_free_bytes=need_bytes,
                    preferred_letter=preferred, require_fit=True,
                )
            except OSError as exc:
                payload = classify_backup_failure(
                    RuntimeError(f"NotEnoughDiskSpaceError {exc}"), None
                )
                payload["required_free_bytes"] = need_bytes
                payload["volumes"] = _volume_inventory()
                _emit(payload)
                return 1
            staged = True
            _emit({"stage": "short_path", "dest": str(write_root), "requested_dest": str(dest)})
        else:
            write_root = dest
            staged = False

        free_now = _staging_free_bytes(write_root)
        _emit({
            "stage": "staging_volume",
            "dest": str(write_root),
            "drive_free_bytes": free_now,
            "min_free_bytes": need_bytes,
        })
        if 0 <= free_now < need_bytes:
            payload = classify_backup_failure(
                RuntimeError(f"NotEnoughDiskSpaceError free={free_now} required={need_bytes}"),
                write_root,
            )
            payload["required_free_bytes"] = need_bytes
            payload["volumes"] = _volume_inventory()
            _emit(payload)
            return 1

        last_exc: BaseException | None = None
        force_full = False
        nested: Path | None = None
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            full = attempt == 1 or force_full
            force_full = False
            try:
                _emit({"stage": "attempt", "attempt": attempt, "full": full, "dest": str(write_root)})
                lockdown = create_using_usbmux(serial=udid)
                try:
                    svc = Mobilebackup2Service(lockdown)
                    svc.backup(full=full, backup_directory=str(write_root), progress_callback=_progress)
                finally:
                    try:
                        lockdown.close()
                    except Exception:
                        pass
                last_exc = None
                nested = _manifest_complete(write_root, udid)
                if nested is not None:
                    break
                last_exc = RuntimeError("ios_backup_incomplete_no_manifest_usb_may_have_dropped")
                if attempt < _MAX_ATTEMPTS:
                    _emit({
                        "stage": "retry_missing_manifest",
                        "attempt": attempt,
                        "dest": str(write_root),
                    })
                    time.sleep(_RETRY_SLEEP_SEC)
                    continue
                break
            except FileNotFoundError as exc:
                if staged:
                    last_exc = exc
                    break
                write_root = short_staging_root(udid, args.stamp, preferred_letter=preferred)
                write_root.mkdir(parents=True, exist_ok=True)
                staged = True
                _emit({"stage": "retry_short_path", "dest": str(write_root), "prior": str(exc)})
                last_exc = exc
                continue
            except Exception as exc:
                last_exc = exc
                if _is_disk_full(exc):
                    current = str(write_root)[:1]
                    try:
                        alt = short_staging_root(
                            udid, args.stamp, exclude_letters={current},
                            min_free_bytes=need_bytes, preferred_letter=preferred, require_fit=True,
                        )
                    except OSError:
                        break
                    if str(alt) != str(write_root) and _staging_free_bytes(alt) >= need_bytes:
                        write_root = alt
                        staged = True
                        force_full = True
                        _emit({
                            "stage": "retry_other_volume",
                            "dest": str(write_root),
                            "prior": type(exc).__name__,
                            "drive_free_bytes": _staging_free_bytes(write_root),
                            "required_free_bytes": need_bytes,
                        })
                        continue
                    break
                if attempt < _MAX_ATTEMPTS and _is_transient(exc):
                    _emit({
                        "stage": "retry_connection",
                        "attempt": attempt,
                        "type": type(exc).__name__,
                        "error": str(exc) or type(exc).__name__,
                    })
                    time.sleep(_RETRY_SLEEP_SEC)
                    continue
                break

        if nested is None:
            nested = _manifest_complete(write_root, udid)
        if nested is None:
            _emit(classify_backup_failure(last_exc, write_root))
            return 1
    except Exception as exc:
        _emit(classify_backup_failure(exc, None))
        return 1

    files = sum(1 for p in nested.rglob("*") if p.is_file())
    _emit({
        "ok": True,
        "backup_path": str(nested),
        "files": files,
        "staged": staged,
        "requested_dest": str(dest),
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
