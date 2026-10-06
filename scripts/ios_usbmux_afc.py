#!/usr/bin/env python3
"""iOS-only AFC + house_arrest supplement after an iTunes-style backup.

Android must not import or call this module. This pulls shared media (DCIM,
PhotoData, Downloads, ...) and WhatsApp app containers that iTunes backup
does not always materialise as examiner-readable trees.

Writes under --dest/afc_media and --dest/house_arrest/<bundle>.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Shared media visible over AFC without jailbreak. Do not pull the whole AFC root.
# PhotoData includes live library + Recently Deleted assets Apple exposes over AFC.
AFC_TARGETS: tuple[str, ...] = (
    "/DCIM",
    "/PhotoData",
    "/PhotoData/CPLAssets",
    "/PhotoData/Thumbnails",
    "/Downloads",
    "/Books",
    "/Recordings",
    "/Purchases",
    "/iTunes_Control",
    "/MediaAnalysis",
    "/Podcasts",
    "/Photos",
    "/Videos",
)

WHATSAPP_BUNDLES: tuple[str, ...] = (
    "net.whatsapp.WhatsApp",
    "net.whatsapp.WhatsAppSMB",
)


def _emit(payload: dict) -> None:
    print(json.dumps(payload), flush=True)


def _safe_name(name: str) -> str:
    return re.sub(r'[<>:"|?*]', "_", name).rstrip(" .")


def _count_files(root: Path) -> tuple[int, int]:
    n = 0
    b = 0
    if not root.is_dir():
        return 0, 0
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            n += 1
            try:
                b += (Path(dirpath) / name).stat().st_size
            except OSError:
                pass
    return n, b


def main() -> int:
    parser = argparse.ArgumentParser(description="iOS AFC + house_arrest pull (iosagent only)")
    parser.add_argument("--udid", required=True)
    parser.add_argument("--dest", required=True, help="Case original folder (afc_media is created here)")
    args = parser.parse_args()

    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)
    media_dir = dest / "afc_media"
    house_dir = dest / "house_arrest"
    media_dir.mkdir(parents=True, exist_ok=True)
    house_dir.mkdir(parents=True, exist_ok=True)

    try:
        from pymobiledevice3.lockdown import create_using_usbmux
        from pymobiledevice3.services.afc import AfcService
        from pymobiledevice3.services.house_arrest import HouseArrestService
    except Exception as exc:
        _emit({"ok": False, "error": f"import_failed: {exc}", "agent": "iosagent"})
        return 1

    try:
        from app.services.mobile_acquire.ios_usbmux import resolve_ios_udid

        udid = resolve_ios_udid(args.udid)
        if not udid:
            _emit({"ok": False, "error": "ios_udid_unresolved", "agent": "iosagent"})
            return 1
    except Exception as exc:
        _emit({"ok": False, "error": str(exc), "agent": "iosagent"})
        return 1

    warnings: list[str] = []
    pulled = 0

    try:
        lockdown = create_using_usbmux(serial=udid)
        afc = AfcService(lockdown)
        targets = list(AFC_TARGETS)
        try:
            root_names = list(afc.listdir("/"))
            for name in root_names:
                remote = "/" + str(name).lstrip("/")
                if remote in targets:
                    continue
                low = remote.lower()
                if any(
                    tok in low
                    for tok in (
                        "dcim",
                        "photo",
                        "download",
                        "record",
                        "podcast",
                        "book",
                        "video",
                        "camera",
                        "media",
                        "trash",
                    )
                ):
                    targets.append(remote)
        except Exception as exc:
            warnings.append(f"AFC listdir failed: {exc}")

        for remote in targets:
            local = media_dir.joinpath(*remote.strip("/").split("/"))
            local.mkdir(parents=True, exist_ok=True)
            _emit({"stage": "afc", "item": remote, "agent": "iosagent"})
            try:
                if not afc.exists(remote):
                    continue
                afc.pull(remote, str(local))
                n, _b = _count_files(local)
                pulled += n
            except Exception as exc:
                warnings.append(f"AFC {remote}: {exc}")
        closer = getattr(afc, "close", None)
        if callable(closer):
            try:
                closer()
            except Exception:
                pass
    except Exception as exc:
        warnings.append(f"AFC session failed: {exc}")

    for bundle in WHATSAPP_BUNDLES:
        local = house_dir / bundle
        local.mkdir(parents=True, exist_ok=True)
        _emit({"stage": "house_arrest", "item": bundle, "agent": "iosagent"})
        try:
            lockdown = create_using_usbmux(serial=udid)
            svc = HouseArrestService(lockdown, bundle_id=bundle, documents_only=False)
            try:
                svc.pull("/", str(local))
            except Exception as exc:
                warnings.append(f"house_arrest {bundle} pull: {exc}")
                try:
                    svc.pull("/Documents", str(local / "Documents"))
                except Exception as exc2:
                    warnings.append(f"house_arrest {bundle} Documents: {exc2}")
            n, _b = _count_files(local)
            pulled += n
            try:
                svc.close()
            except Exception:
                pass
        except Exception as exc:
            warnings.append(f"house_arrest {bundle}: {exc}")

    files, bytes_done = _count_files(dest)
    _emit({
        "ok": True,
        "agent": "iosagent",
        "afc_files": _count_files(media_dir)[0],
        "house_arrest_files": _count_files(house_dir)[0],
        "pulled": pulled,
        "files": files,
        "bytes": bytes_done,
        "warnings": warnings,
        "dest": str(dest),
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
