"""Windows registry hive parser — SAM last logon / password set + ProfileList."""

from __future__ import annotations

import io
import re
import struct
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from typing import Any

REGF_MAGIC = b"regf"

# SAM\Domains\Account\Users\<RID>\F binary layout (common XP–Win11)
_F_LAST_LOGON = 0x08
_F_LAST_LOGOFF = 0x10
_F_PASSWORD_LAST_SET = 0x18
_F_ACCOUNT_EXPIRES = 0x20
_F_LAST_BAD_PWD = 0x28
_F_RID = 0x30

_NEVER_FT = {0, 0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}


def _filetime_to_iso(raw: int) -> str | None:
    if raw in _NEVER_FT or raw < 0:
        return None
    try:
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=raw // 10)
        if dt.year < 1980 or dt.year > 2100:
            return None
        return dt.isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def _read_filetime(buf: bytes, offset: int) -> str | None:
    if offset + 8 > len(buf):
        return None
    return _filetime_to_iso(struct.unpack_from("<Q", buf, offset)[0])


def _hive_kind(path: str) -> str:
    name = PurePosixPath(path.replace("\\", "/")).name.lower()
    if name == "sam":
        return "sam"
    if name == "software":
        return "software"
    if name == "system":
        return "system"
    if name == "security":
        return "security"
    if name == "default":
        return "default"
    if name == "amcache.hve" or name.endswith(".hve"):
        return "amcache"
    if name == "ntuser.dat":
        return "ntuser"
    if name == "usrclass.dat":
        return "usrclass"
    return "hive"


def _parse_sam_f(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if len(data) < 0x40:
        return out
    ll = _read_filetime(data, _F_LAST_LOGON)
    if ll:
        out["last_logon"] = ll
    lo = _read_filetime(data, _F_LAST_LOGOFF)
    if lo:
        out["last_logoff"] = lo
    pls = _read_filetime(data, _F_PASSWORD_LAST_SET)
    if pls:
        out["password_last_set"] = pls
    lbp = _read_filetime(data, _F_LAST_BAD_PWD)
    if lbp:
        out["last_bad_password"] = lbp
    try:
        rid = struct.unpack_from("<I", data, _F_RID)[0]
        if 0 < rid < 0xFFFFFF:
            out["rid"] = rid
    except struct.error:
        pass
    return out


def _username_from_v(data: bytes) -> str | None:
    """Extract account name from SAM Users V value."""
    if len(data) < 0x4C:
        return None
    try:
        name_off = struct.unpack_from("<I", data, 0x0C)[0] + 0xCC
        name_len = struct.unpack_from("<I", data, 0x10)[0]
        if name_len <= 0 or name_len > 256 or name_off + name_len > len(data):
            return None
        raw = data[name_off : name_off + name_len]
        name = raw.decode("utf-16-le", errors="ignore").strip("\x00").strip()
        if name and re.match(r"^[\w .@\-]+$", name) and len(name) < 64:
            return name
    except (struct.error, UnicodeError):
        return None
    return None


def _parse_with_python_registry(data: bytes, path: str) -> list[dict[str, Any]] | None:
    try:
        from Registry import Registry  # type: ignore
    except ImportError:
        return None

    records: list[dict[str, Any]] = []
    kind = _hive_kind(path)
    try:
        reg = Registry.Registry(io.BytesIO(data))
    except Exception as exc:
        return [{"hive_path": path, "valid": False, "error": str(exc)[:200]}]

    records.append({
        "hive_path": path,
        "format": "regf",
        "hive_kind": kind,
        "size_bytes": len(data),
        "valid": True,
        "parser": "python-registry",
    })

    if kind == "sam":
        records.extend(_sam_via_registry(reg, path))
    elif kind == "software":
        records.extend(_os_currentversion_via_registry(reg, path))
        records.extend(_profilelist_via_registry(reg, path))
        records.extend(_installed_programs_via_registry(reg, path))
        records.extend(_feature_usage_via_registry(reg, path))
        records.extend(_your_phone_via_software(reg, path))
    elif kind == "system":
        records.extend(_system_identity_via_registry(reg, path))
        # USB Enum/USBSTOR already appended inside _system_identity via _usb_devices_via_registry
    elif kind == "ntuser":
        records.extend(_ntuser_via_registry(reg, path))
        records.extend(_feature_usage_via_registry(reg, path))
        records.extend(_rdp_via_ntuser(reg, path))
        records.extend(_your_phone_via_ntuser(reg, path))
    else:
        # Generic: surface a few high-value keys for RAG
        for key_path in (
            "Microsoft\\Windows NT\\CurrentVersion",
            "Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
        ):
            try:
                key = reg.open(key_path)
                for val in key.values()[:20]:
                    try:
                        records.append({
                            "registry_key": key_path,
                            "value_name": val.name(),
                            "value": str(val.value())[:500],
                            "source": "python-registry",
                        })
                    except Exception:
                        continue
            except Exception:
                continue
    return records


_OS_VALUE_NAMES = (
    "ProductName",
    "DisplayVersion",
    "CurrentVersion",
    "CurrentBuild",
    "CurrentBuildNumber",
    "CurrentMajorVersionNumber",
    "CurrentMinorVersionNumber",
    "BuildLabEx",
    "BuildLab",
    "BuildBranch",
    "EditionID",
    "CompositionEditionID",
    "InstallationType",
    "RegisteredOwner",
    "RegisteredOrganization",
    "InstallDate",
    "InstallTime",
    "ProductId",
    "DigitalProductId",
    "DigitalProductId4",
    "CSDVersion",
    "UBR",
    "ReleaseId",
    "PathName",
    "SystemRoot",
    "SoftwareType",
)

# Classic Windows product-key alphabet (DigitalProductId decode)
_PRODUCT_KEY_DIGITS = "BCDFGHJKMPQRTVWXY2346789"


def _decode_digital_product_id(data: bytes) -> str | None:
    """Decode Windows DigitalProductId (bytes 52–66) into XXXXX-XXXXX-… key."""
    if not data or len(data) < 67:
        return None
    try:
        key = list(data[52:67])
        out: list[str] = []
        for i in range(25):
            acc = 0
            for j in range(14, -1, -1):
                acc = (acc << 8) + key[j]
                key[j] = acc // 24
                acc %= 24
            out.append(_PRODUCT_KEY_DIGITS[acc])
            if (i + 1) % 5 == 0 and i != 24:
                out.append("-")
        return "".join(reversed(out))
    except Exception:
        return None


def _os_currentversion_via_registry(reg: Any, path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        key = reg.open("Microsoft\\Windows NT\\CurrentVersion")
    except Exception:
        return records

    fields: dict[str, Any] = {}
    product_key = None
    product_key4 = None
    for val in key.values():
        name = val.name() or ""
        if name not in _OS_VALUE_NAMES:
            continue
        try:
            raw = val.value()
        except Exception:
            continue
        if name == "InstallDate" and isinstance(raw, int) and raw > 0:
            try:
                fields[name] = datetime.fromtimestamp(raw, tz=timezone.utc).isoformat().replace("+00:00", "Z")
            except (OverflowError, OSError, ValueError):
                fields[name] = str(raw)
        elif name == "InstallTime" and isinstance(raw, int) and raw > 0:
            iso = _filetime_to_iso(raw)
            if iso:
                fields[name] = iso
        elif name == "DigitalProductId" and isinstance(raw, (bytes, bytearray)):
            product_key = _decode_digital_product_id(bytes(raw))
        elif name == "DigitalProductId4" and isinstance(raw, (bytes, bytearray)):
            product_key4 = _decode_digital_product_id(bytes(raw))
        elif isinstance(raw, (bytes, bytearray)):
            continue
        else:
            fields[name] = str(raw).strip() if raw is not None else None

    if not fields and not product_key:
        return records

    product = fields.get("ProductName") or "Windows"
    display = fields.get("DisplayVersion") or fields.get("ReleaseId")
    build = fields.get("CurrentBuild") or fields.get("CurrentBuildNumber")
    edition = fields.get("EditionID")
    major = fields.get("CurrentMajorVersionNumber")
    minor = fields.get("CurrentMinorVersionNumber")
    version_number = None
    if major is not None:
        version_number = f"{major}.{minor or 0}"
    parts = [f"Operating system: {product}"]
    if display:
        parts.append(f"display version: {display}")
    if version_number:
        parts.append(f"version number: {version_number}")
    if build:
        ubr = fields.get("UBR")
        parts.append(f"build: {build}" + (f".{ubr}" if ubr else ""))
    if edition:
        parts.append(f"edition: {edition}")
    if fields.get("CurrentVersion"):
        parts.append(f"operating system version (NT): {fields['CurrentVersion']}")
    if fields.get("InstallDate"):
        parts.append(f"installed date: {fields['InstallDate']}")
    if fields.get("InstallTime"):
        parts.append(f"install time: {fields['InstallTime']}")
    if fields.get("ProductId"):
        parts.append(f"product ID: {fields['ProductId']}")
    if product_key:
        parts.append(f"product key: {product_key}")
    if fields.get("PathName") or fields.get("SystemRoot"):
        parts.append(f"system root / path: {fields.get('PathName') or fields.get('SystemRoot')}")
    if fields.get("RegisteredOwner"):
        parts.append(f"registered owner: {fields['RegisteredOwner']}")

    rec = {
        "record_type": "windows_os",
        "product_name": fields.get("ProductName"),
        "display_version": display,
        "version_number": version_number,
        "current_version": fields.get("CurrentVersion"),
        "current_build": build,
        "ubr": fields.get("UBR"),
        "edition_id": edition,
        "composition_edition_id": fields.get("CompositionEditionID"),
        "install_date": fields.get("InstallDate"),
        "install_time": fields.get("InstallTime"),
        "product_id": fields.get("ProductId"),
        "product_key": product_key,
        "product_key_alt": product_key4,
        "build_lab": fields.get("BuildLabEx") or fields.get("BuildLab"),
        "build_branch": fields.get("BuildBranch"),
        "registered_owner": fields.get("RegisteredOwner"),
        "registered_organization": fields.get("RegisteredOrganization"),
        "installation_type": fields.get("InstallationType"),
        "system_root": fields.get("PathName") or fields.get("SystemRoot"),
        "path_name": fields.get("PathName") or fields.get("SystemRoot"),
        "source": "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "hive_path": path,
        "text": "; ".join(parts),
    }
    records.append(rec)
    return records


def _system_identity_via_registry(reg: Any, path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    # Prefer ControlSet001, fall back to CurrentControlSet if present as a key
    for cs in ("ControlSet001", "ControlSet002", "CurrentControlSet"):
        try:
            key = reg.open(f"{cs}\\Control\\ComputerName\\ComputerName")
            for val in key.values():
                if (val.name() or "").lower() in ("computername", ""):
                    name = str(val.value()).strip()
                    if name and name.lower() != "mnmsrvc":
                        records.append({
                            "record_type": "computer_name",
                            "computer_name": name,
                            "source": f"SYSTEM\\{cs}\\Control\\ComputerName",
                            "hive_path": path,
                            "text": f"Computer name: {name}",
                        })
                        break
        except Exception:
            continue
        if any(r.get("record_type") == "computer_name" for r in records):
            break

    for cs in ("ControlSet001", "CurrentControlSet"):
        try:
            key = reg.open(f"{cs}\\Control\\Windows")
            for val in key.values():
                n = val.name() or ""
                try:
                    raw = val.value()
                except Exception:
                    continue
                if n == "SystemRoot" or n == "Directory":
                    root = str(raw).strip()
                    if root:
                        records.append({
                            "record_type": "system_root",
                            "system_root": root,
                            "source": f"SYSTEM\\{cs}\\Control\\Windows",
                            "hive_path": path,
                            "text": f"SystemRoot: {root}",
                        })
                elif n == "ShutdownTime" and isinstance(raw, (bytes, bytearray)) and len(raw) >= 8:
                    ft = struct.unpack_from("<Q", bytes(raw), 0)[0]
                    iso = _filetime_to_iso(ft)
                    if iso:
                        records.append({
                            "record_type": "last_shutdown",
                            "last_shutdown": iso,
                            "source": f"SYSTEM\\{cs}\\Control\\Windows\\ShutdownTime",
                            "hive_path": path,
                            "text": f"Last shutdown date/time: {iso}",
                        })
                elif n == "SystemDirectory":
                    records.append({
                        "record_type": "system_directory",
                        "system_directory": str(raw).strip(),
                        "source": f"SYSTEM\\{cs}\\Control\\Windows",
                        "hive_path": path,
                        "text": f"System directory: {raw}",
                    })
        except Exception:
            continue
        break

    for cs in ("ControlSet001", "CurrentControlSet"):
        try:
            key = reg.open(f"{cs}\\Control\\Session Manager\\Environment")
            env: dict[str, str] = {}
            for val in key.values():
                n = val.name() or ""
                try:
                    raw = val.value()
                except Exception:
                    continue
                if isinstance(raw, (bytes, bytearray)):
                    continue
                if n in ("Path", "OS", "windir", "ComSpec", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "PROCESSOR_IDENTIFIER"):
                    env[n] = str(raw).strip()
            if env.get("Path"):
                records.append({
                    "record_type": "system_path",
                    "path": env["Path"],
                    "source": f"SYSTEM\\{cs}\\Control\\Session Manager\\Environment",
                    "hive_path": path,
                    "text": f"Path: {env['Path']}",
                })
            if env:
                records.append({
                    "record_type": "system_environment",
                    "os_env": env.get("OS"),
                    "windir": env.get("windir"),
                    "processor_architecture": env.get("PROCESSOR_ARCHITECTURE"),
                    "processor_identifier": env.get("PROCESSOR_IDENTIFIER"),
                    "number_of_processors": env.get("NUMBER_OF_PROCESSORS"),
                    "source": f"SYSTEM\\{cs}\\Control\\Session Manager\\Environment",
                    "hive_path": path,
                    "text": "; ".join(f"{k}: {v}" for k, v in env.items() if k != "Path"),
                })
        except Exception:
            continue
        break
    records.extend(_usb_devices_via_registry(reg, path))
    return records


def _usb_devices_via_registry(reg: Any, path: str) -> list[dict[str, Any]]:
    """Enumerate USBSTOR + Enum\\USB devices from SYSTEM hive (Axiom USB Devices)."""
    records: list[dict[str, Any]] = []
    devices: list[dict[str, Any]] = []

    for cs in ("ControlSet001", "ControlSet002", "CurrentControlSet"):
        # Mass-storage (USBSTOR) — unique drives with serials
        try:
            root = reg.open(f"{cs}\\Enum\\USBSTOR")
        except Exception:
            root = None
        if root is not None:
            for device in root.subkeys():
                friendly = device.name()
                ven = prod = rev = None
                m = re.search(r"Ven_([^&]+)&Prod_([^&]+)(?:&Rev_([^\\]+))?", friendly, re.I)
                if m:
                    ven, prod, rev = m.group(1), m.group(2), m.group(3)
                for instance in device.subkeys():
                    serial = instance.name()
                    device_desc = None
                    friendly_name = None
                    last_write = None
                    try:
                        ts = instance.timestamp()
                        if hasattr(ts, "astimezone"):
                            last_write = ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                        elif isinstance(ts, (int, float)):
                            last_write = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
                    except Exception:
                        last_write = None
                    for val in instance.values():
                        n = (val.name() or "").lower()
                        try:
                            raw = val.value()
                        except Exception:
                            continue
                        if n == "friendlyname":
                            friendly_name = str(raw)
                        elif n == "devicedesc":
                            device_desc = str(raw)
                    label = friendly_name or device_desc or f"{ven or ''} {prod or ''}".strip() or friendly
                    devices.append({
                        "record_type": "usb_device",
                        "bus": "USBSTOR",
                        "device_name": label.strip(),
                        "vendor": ven,
                        "product": prod,
                        "revision": rev,
                        "serial": serial,
                        "class_id": friendly,
                        "last_write": last_write,
                        "source": f"SYSTEM\\{cs}\\Enum\\USBSTOR",
                        "hive_path": path,
                        "text": (
                            f"Connected USB storage device: {label.strip()}"
                            + (f" (vendor={ven}, product={prod})" if ven or prod else "")
                            + (f", serial={serial}" if serial else "")
                            + (f", registry last write={last_write}" if last_write else "")
                        ),
                    })
                    if last_write:
                        devices.append({
                            "record_type": "usb_usage_event",
                            "event_kind": "usbstor_key_last_write",
                            "event_time": last_write,
                            "device_id": label.strip(),
                            "serial": serial,
                            "vendor": ven,
                            "product": prod,
                            "source": f"SYSTEM\\{cs}\\Enum\\USBSTOR",
                            "hive_path": path,
                            "text": (
                                f"USB usage evidence (USBSTOR key last write) at {last_write}: "
                                f"{label.strip()} serial={serial}"
                            ),
                        })

        # All USB class devices (Axiom "USB Devices" artifact set — hubs, HID, storage, MTP, …)
        try:
            usb_root = reg.open(f"{cs}\\Enum\\USB")
        except Exception:
            usb_root = None
        if usb_root is not None:
            for device in usb_root.subkeys():
                vid_pid = device.name()
                ven = prod = None
                m = re.search(r"VID_([0-9A-Fa-f]{4}).*PID_([0-9A-Fa-f]{4})", vid_pid, re.I)
                if m:
                    ven, prod = m.group(1), m.group(2)
                for instance in device.subkeys():
                    serial = instance.name()
                    friendly_name = device_desc = None
                    last_write = None
                    try:
                        ts = instance.timestamp()
                        if hasattr(ts, "astimezone"):
                            last_write = ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                    except Exception:
                        pass
                    for val in instance.values():
                        n = (val.name() or "").lower()
                        try:
                            raw = val.value()
                        except Exception:
                            continue
                        if n == "friendlyname":
                            friendly_name = str(raw)
                        elif n == "devicedesc":
                            device_desc = str(raw)
                    # Resolve INF placeholder descriptions like @usb.inf,%usb\composite...
                    label = friendly_name or device_desc or vid_pid
                    if isinstance(label, str) and label.startswith("@") and "%" in label:
                        # Keep trailing human part after last ';'
                        if ";" in label:
                            label = label.split(";")[-1].strip() or vid_pid
                    devices.append({
                        "record_type": "usb_device",
                        "bus": "USB",
                        "device_name": str(label).strip(),
                        "vendor": ven,
                        "product": prod,
                        "serial": serial,
                        "class_id": vid_pid,
                        "last_write": last_write,
                        "source": f"SYSTEM\\{cs}\\Enum\\USB",
                        "hive_path": path,
                        "text": (
                            f"USB device (Enum\\USB): {str(label).strip()} "
                            f"({vid_pid}\\{serial})"
                        ),
                    })

        # USB-attached disks may also be enumerated by Windows under Enum\SCSI when
        # the device uses UASP. Magnet AXIOM surfaces these as external disk evidence
        # (for example Seagate Expansion) even when the USBSTOR key is absent.  Only
        # keep models with strong external/removable markers; internal NVMe/SATA disks
        # must never be promoted into the USB device count.
        try:
            scsi_root = reg.open(f"{cs}\\Enum\\SCSI")
        except Exception:
            scsi_root = None
        if scsi_root is not None:
            for device in scsi_root.subkeys():
                class_id = device.name()
                if not re.search(r"^Disk&", class_id, re.I):
                    continue
                if re.search(r"NVMe|SKHynix|Samsung_NVMe|Intel.*NVMe", class_id, re.I):
                    continue
                for instance in device.subkeys():
                    serial = instance.name()
                    friendly_name = device_desc = None
                    last_write = None
                    try:
                        ts = instance.timestamp()
                        if hasattr(ts, "astimezone"):
                            last_write = ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                    except Exception:
                        pass
                    for val in instance.values():
                        n = (val.name() or "").lower()
                        try:
                            raw = val.value()
                        except Exception:
                            continue
                        if n == "friendlyname":
                            friendly_name = str(raw)
                        elif n == "devicedesc":
                            device_desc = str(raw)
                    label = (friendly_name or device_desc or class_id).strip()
                    external_marker = re.search(
                        r"portable|external|expansion|passport|elements|usb|apacer|sandisk|seagate\s+expansion",
                        f"{class_id} {label}",
                        re.I,
                    )
                    if not external_marker:
                        continue
                    devices.append({
                        "record_type": "usb_device",
                        "bus": "SCSI_STORAGE",
                        "device_name": label,
                        "serial": serial,
                        "class_id": class_id,
                        "last_write": last_write,
                        "source": f"SYSTEM\\{cs}\\Enum\\SCSI",
                        "hive_path": path,
                        "text": f"External storage disk: {label}" + (f", serial={serial}" if serial else ""),
                    })

        # Portable / MTP devices (phone pairing evidence) — exclude USBSTOR volumes
        for wpd_path in (f"{cs}\\Enum\\SWD\\WPDBUSENUM", f"{cs}\\Enum\\WpdBusEnumRoot\\UMB"):
            try:
                wpd = reg.open(wpd_path)
            except Exception:
                continue
            for device in wpd.subkeys():
                name = device.name()
                if "USBSTOR" in name.upper():
                    continue
                last_write = None
                try:
                    ts = device.timestamp()
                    if hasattr(ts, "astimezone"):
                        last_write = ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                except Exception:
                    pass
                devices.append({
                    "record_type": "phone_device",
                    "device_name": name,
                    "serial": name,
                    "last_write": last_write,
                    "source": f"SYSTEM\\{wpd_path}",
                    "hive_path": path,
                    "text": f"Portable / phone-related device: {name}",
                })
        # Continue to next control set to capture unique instances across sets
        # (dedupe below) — do not break early.
    # MountedDevices drive letters pointing at USBSTOR
    try:
        md = reg.open("MountedDevices")
    except Exception:
        md = None
    if md:
        for val in md.values():
            name = val.name() or ""
            try:
                raw = val.value()
            except Exception:
                continue
            if not isinstance(raw, (bytes, bytearray)):
                continue
            try:
                decoded = bytes(raw).decode("utf-16-le", errors="ignore")
            except Exception:
                decoded = ""
            if "USBSTOR" not in decoded.upper() and "USBSTOR" not in name.upper():
                continue
            devices.append({
                "record_type": "usb_mount",
                "device_name": name,
                "mount_hint": decoded[:200],
                "source": "SYSTEM\\MountedDevices",
                "hive_path": path,
                "text": f"USB mount point: {name} → {decoded[:120]}",
            })

    seen: set[str] = set()
    for d in devices:
        key = f"{d.get('bus')}|{d.get('serial')}|{d.get('device_name')}|{d.get('record_type')}|{d.get('class_id')}"
        if key in seen:
            continue
        seen.add(key)
        records.append(d)

    usb_axiom = [r for r in records if r.get("record_type") == "usb_device"]
    if usb_axiom:
        names = sorted({r.get("device_name") for r in usb_axiom if r.get("device_name")})
        records.insert(0, {
            "record_type": "usb_summary",
            "device_count": len(usb_axiom),
            "usbstor_count": len([r for r in usb_axiom if r.get("bus") == "USBSTOR"]),
            "enum_usb_count": len([r for r in usb_axiom if r.get("bus") == "USB"]),
            "devices": names[:40],
            "source": "SYSTEM\\Enum\\USB+USBSTOR",
            "hive_path": path,
            "text": (
                f"USB devices (Axiom-style Enum\\USB+USBSTOR): {len(usb_axiom)} — "
                + ", ".join(names[:30])
            ),
        })
    return records


def _installed_programs_via_registry(reg: Any, path: str) -> list[dict[str, Any]]:
    """SOFTWARE Uninstall entries — Axiom Installed Programs counts."""
    records: list[dict[str, Any]] = []
    roots = (
        "Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    )
    seen: set[str] = set()
    for root_path in roots:
        try:
            root = reg.open(root_path)
        except Exception:
            continue
        for sk in root.subkeys():
            display = publisher = version = None
            for val in sk.values():
                n = (val.name() or "").lower()
                try:
                    raw = val.value()
                except Exception:
                    continue
                if isinstance(raw, (bytes, bytearray)):
                    continue
                if n == "displayname":
                    display = str(raw).strip()
                elif n == "publisher":
                    publisher = str(raw).strip()
                elif n == "displayversion":
                    version = str(raw).strip()
            if not display:
                continue
            # Artifact-record identity is the native Uninstall registry entry.
            # The same DisplayName may legitimately appear in 32/64-bit roots or
            # side-by-side versions; do not collapse those independent records.
            key = f"{root_path}|{sk.name()}".lower()
            if key in seen:
                continue
            seen.add(key)
            # Skip Windows Update KB noise and empty system stubs
            if re.match(r"^(kb\d+|update for|security update)", display, re.I):
                continue
            if re.search(r"\bkb\d{6,}\b", display, re.I) and "update" in display.lower():
                continue
            pub_l = (publisher or "").lower()
            is_ms = any(
                x in pub_l
                for x in ("microsoft", "windows", "microsoft corporation")
            ) or display.lower().startswith("microsoft ")
            records.append({
                "record_type": "installed_program",
                "display_name": display,
                "publisher": publisher,
                "version": version,
                "is_microsoft": is_ms,
                "uninstall_key": sk.name(),
                "source": f"SOFTWARE\\{root_path}",
                "hive_path": path,
                "text": (
                    f"Installed program: {display}"
                    + (f" (publisher={publisher})" if publisher else "")
                    + (f" version={version}" if version else "")
                    + (" [Microsoft]" if is_ms else " [Non-Microsoft]")
                ),
            })
    if records:
        ms = sum(1 for r in records if r.get("is_microsoft"))
        records.insert(0, {
            "record_type": "installed_programs_summary",
            "total": len(records),
            "microsoft_count": ms,
            "non_microsoft_count": len(records) - ms,
            "source": "SOFTWARE\\Uninstall",
            "hive_path": path,
            "text": (
                f"Installed programs from Uninstall registry: {len(records)} "
                f"(Microsoft={ms}, Non-Microsoft={len(records) - ms})"
            ),
        })
    return records


def _feature_usage_via_registry(reg: Any, path: str) -> list[dict[str, Any]]:
    """FeatureUsage / AppSwitcher-style keys when present."""
    records: list[dict[str, Any]] = []
    kind = _hive_kind(path)
    if kind in ("ntuser", "usrclass"):
        roots = ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage",)
        source_prefix = "NTUSER\\Software"
    else:
        roots = ("Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage",)
        source_prefix = "SOFTWARE"
    count_subkeys = ("AppLaunch", "AppSwitched", "ShowJumpView", "AppBadgeUpdated", "TrayButtonClicked")
    for root_path in roots:
        try:
            root = reg.open(root_path)
        except Exception:
            continue
        for sk in root.subkeys():
            name = sk.name() or ""
            try:
                vals = list(sk.values())
            except Exception:
                vals = []
            n = len(vals)
            if n <= 0:
                continue
            if name in count_subkeys:
                records.append({
                    "record_type": "feature_usage",
                    "key_path": f"{root_path}\\{name}",
                    "entry_count": n,
                    "source": f"{source_prefix}\\{root_path}\\{name}",
                    "hive_path": path,
                    "text": f"FeatureUsage registry entries under {root_path}\\{name}: {n}",
                })
    return records


def _your_phone_via_software(reg: Any, path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for key_path in (
        "Microsoft\\YourPhone",
        "Microsoft\\Windows\\CurrentVersion\\TaskFlow\\DeviceEnrollment",
        "Microsoft\\Windows\\CurrentVersion\\CrossDevice",
    ):
        try:
            key = reg.open(key_path)
        except Exception:
            continue
        for sk in key.subkeys():
            name = sk.name()
            records.append({
                "record_type": "phone_device",
                "device_name": name,
                "source": f"SOFTWARE\\{key_path}",
                "hive_path": path,
                "text": f"Your Phone / CrossDevice linked device: {name}",
            })
        for val in key.values():
            n = val.name() or ""
            if n.lower() in {"", "default", "(default)"}:
                continue
            try:
                raw = val.value()
            except Exception:
                continue
            if isinstance(raw, (bytes, bytearray)):
                continue
            records.append({
                "record_type": "phone_device",
                "device_name": f"{n}={raw}",
                "source": f"SOFTWARE\\{key_path}",
                "hive_path": path,
                "text": f"Your Phone / CrossDevice value: {n}={raw}",
            })
    return records


def _rdp_via_ntuser(reg: Any, path: str) -> list[dict[str, Any]]:
    """Terminal Server Client MRU / Servers — Axiom RDP connection artifacts."""
    records: list[dict[str, Any]] = []
    m = re.search(r"Users[\\/]([^\\/]+)[\\/]NTUSER\.DAT", path.replace("\\", "/"), re.I)
    username = m.group(1) if m else None
    try:
        key = reg.open("Software\\Microsoft\\Terminal Server Client\\Servers")
    except Exception:
        key = None
    if key is not None:
        for sk in key.subkeys():
            host = sk.name()
            username_hint = None
            for val in sk.values():
                if (val.name() or "").lower() == "usernamehint":
                    try:
                        username_hint = str(val.value())
                    except Exception:
                        pass
            records.append({
                "record_type": "rdp_connection",
                "host": host,
                "username_hint": username_hint,
                "user": username,
                "source": "Software\\Microsoft\\Terminal Server Client\\Servers",
                "hive_path": path,
                "text": (
                    f"RDP connection to {host}"
                    + (f" (user hint={username_hint})" if username_hint else "")
                    + (f" from Windows user {username}" if username else "")
                ),
            })
    # Default MRU string list (unique hosts only)
    try:
        default = reg.open("Software\\Microsoft\\Terminal Server Client\\Default")
        for val in default.values():
            n = (val.name() or "").lower()
            if not n.startswith("mru"):
                continue
            try:
                raw = str(val.value()).strip()
            except Exception:
                continue
            if not raw:
                continue
            records.append({
                "record_type": "rdp_connection",
                "host": raw,
                "user": username,
                "source": "Software\\Microsoft\\Terminal Server Client\\Default",
                "hive_path": path,
                "text": f"RDP MRU host: {raw} (user={username or 'unknown'})",
            })
    except Exception:
        pass
    return records


def _your_phone_via_ntuser(reg: Any, path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    m = re.search(r"Users[\\/]([^\\/]+)[\\/]NTUSER\.DAT", path.replace("\\", "/"), re.I)
    username = m.group(1) if m else None
    for key_path in (
        "Software\\Microsoft\\YourPhone",
        "Software\\Microsoft\\Windows\\CurrentVersion\\TaskFlow",
    ):
        try:
            key = reg.open(key_path)
        except Exception:
            continue
        for sk in key.subkeys():
            records.append({
                "record_type": "phone_device",
                "device_name": sk.name(),
                "user": username,
                "source": key_path,
                "hive_path": path,
                "text": f"Your Phone device '{sk.name()}' for user {username or 'unknown'}",
            })
    return records


def _sam_via_registry(reg: Any, path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    rid_to_name: dict[int, str] = {}
    try:
        names = reg.open("SAM\\Domains\\Account\\Users\\Names")
        for sk in names.subkeys():
            try:
                # Default value type encodes RID on some hives; also try value data
                name = sk.name()
                for val in sk.values():
                    raw = val.value()
                    if isinstance(raw, int) and raw > 0:
                        rid_to_name[raw] = name
                    elif isinstance(raw, bytes) and len(raw) >= 4:
                        rid_to_name[struct.unpack_from("<I", raw, 0)[0]] = name
            except Exception:
                continue
    except Exception:
        pass

    try:
        users = reg.open("SAM\\Domains\\Account\\Users")
    except Exception:
        return records

    for sk in users.subkeys():
        if sk.name().lower() == "names":
            continue
        try:
            rid = int(sk.name(), 16)
        except ValueError:
            continue
        username = rid_to_name.get(rid)
        f_data = None
        v_data = None
        for val in sk.values():
            n = (val.name() or "").upper()
            try:
                if n == "F":
                    f_data = val.value()
                    if not isinstance(f_data, (bytes, bytearray)):
                        f_data = bytes(f_data) if f_data is not None else None
                elif n == "V":
                    v_data = val.value()
                    if not isinstance(v_data, (bytes, bytearray)):
                        v_data = bytes(v_data) if v_data is not None else None
            except Exception:
                continue
        if not username and isinstance(v_data, (bytes, bytearray)):
            username = _username_from_v(bytes(v_data))
        facts = _parse_sam_f(bytes(f_data)) if isinstance(f_data, (bytes, bytearray)) else {}
        if not username and not facts:
            continue
        rec: dict[str, Any] = {
            "record_type": "sam_user",
            "username": username or f"RID-{rid}",
            "rid": rid,
            "source": "SAM",
            "hive_path": path,
        }
        rec.update(facts)
        # Searchable prose for RAG
        parts = [f"Windows local account: {rec['username']} (RID {rid})"]
        if rec.get("last_logon"):
            parts.append(f"last logon: {rec['last_logon']}")
        if rec.get("password_last_set"):
            parts.append(f"password last changed: {rec['password_last_set']}")
        if rec.get("last_logoff"):
            parts.append(f"last logoff: {rec['last_logoff']}")
        rec["text"] = "; ".join(parts)
        records.append(rec)
    return records


def _profilelist_via_registry(reg: Any, path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        root = reg.open("Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
    except Exception:
        return records

    for sk in root.subkeys():
        sid = sk.name()
        if not sid.upper().startswith("S-1-5-"):
            continue
        profile_path = None
        for val in sk.values():
            if (val.name() or "").lower() == "profileimagepath":
                try:
                    profile_path = str(val.value())
                except Exception:
                    pass
        last_write = None
        try:
            ts = sk.timestamp()
            if ts:
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                last_write = ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            pass
        username = None
        if profile_path:
            m = re.search(r"[\\/]Users[\\/]([^\\/]+)", profile_path.replace("/", "\\"), re.I)
            if m:
                username = m.group(1)
        rec = {
            "record_type": "profile_list",
            "sid": sid,
            "profile_image_path": profile_path,
            "username": username,
            "profile_key_last_write": last_write,
            "source": "SOFTWARE\\ProfileList",
            "hive_path": path,
        }
        parts = [f"ProfileList SID {sid}"]
        if username:
            parts.append(f"user: {username}")
        if profile_path:
            parts.append(f"path: {profile_path}")
        if last_write:
            parts.append(f"profile key last write (approx last profile load): {last_write}")
        rec["text"] = "; ".join(parts)
        records.append(rec)
    return records


def _ntuser_via_registry(reg: Any, path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    m = re.search(r"Users[\\/]([^\\/]+)[\\/]NTUSER\.DAT", path.replace("\\", "/"), re.I)
    username = m.group(1) if m else None
    try:
        root = reg.root()
        ts = root.timestamp()
        last_write = None
        if ts:
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            last_write = ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        rec = {
            "record_type": "ntuser_hive",
            "username": username,
            "hive_path": path,
            "ntuser_last_write": last_write,
            "source": "NTUSER.DAT",
        }
        parts = [f"NTUSER.DAT for user {username or 'unknown'}"]
        if last_write:
            parts.append(f"hive last write (approx last interactive use): {last_write}")
        rec["text"] = "; ".join(parts)
        records.append(rec)
    except Exception:
        pass
    return records


def _scan_fallback(data: bytes, path: str) -> list[dict[str, Any]]:
    """Lightweight scan when python-registry is unavailable.

    Never UTF-16-decode an entire multi-100MB SOFTWARE hive (OOM). Sample windows instead.
    """
    records: list[dict[str, Any]] = []
    kind = _hive_kind(path)
    records.append({
        "hive_path": path,
        "format": "regf",
        "hive_kind": kind,
        "size_bytes": len(data),
        "valid": True,
        "parser": "hive_scan",
    })

    window = 4 * 1024 * 1024
    samples: list[bytes] = [data[:window]]
    if len(data) > window * 2:
        mid = max(0, (len(data) // 2) - (window // 2))
        samples.append(data[mid : mid + window])
    if len(data) > window:
        samples.append(data[-window:])
    text = "\n".join(s.decode("utf-16-le", errors="ignore") for s in samples)
    if kind == "software" or "ProfileImagePath" in text:
        for m in re.finditer(
            r"ProfileImagePath[\x00-\x20]{0,8}((?:%[A-Z_]+%|[A-Za-z]:)?(?:\\Users\\[^\\\x00]{1,64}))",
            text,
            re.I,
        ):
            profile_path = m.group(1)
            um = re.search(r"\\Users\\([^\\]+)", profile_path, re.I)
            username = um.group(1) if um else None
            records.append({
                "record_type": "profile_list",
                "profile_image_path": profile_path,
                "username": username,
                "source": "SOFTWARE_scan",
                "hive_path": path,
                "text": f"ProfileImagePath {profile_path}"
                + (f" user: {username}" if username else ""),
            })

    if kind == "sam":
        # Heuristic: find utf-16 usernames near F-like FILETIME clusters is unreliable;
        # still surface any readable account-ish strings under Users.
        for name in sorted(set(re.findall(r"(?:Administrator|Guest|[\w]{2,32})", text))):
            if name.lower() in {"microsoft", "windows", "system", "software", "security"}:
                continue
            if len(name) < 3:
                continue
            records.append({
                "record_type": "sam_username_hint",
                "username": name,
                "source": "SAM_scan",
                "hive_path": path,
                "text": f"SAM username hint: {name}",
            })

    keys = set(re.findall(r"\\(?:Software|System|SAM|Security|Users)[\\/\w\s.-]{3,80}", text, re.I))
    for k in sorted(keys)[:40]:
        records.append({"registry_key": k.strip(), "source": "hive_scan"})
    return records


def parse_registry_hive(data: bytes, path: str) -> list[dict[str, Any]]:
    if len(data) < 4096 or not data.startswith(REGF_MAGIC):
        return [{"hive_path": path, "size_bytes": len(data), "valid": False}]

    parsed = _parse_with_python_registry(data, path)
    if parsed is not None:
        return parsed
    return _scan_fallback(data, path)
