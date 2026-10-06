# Aetheris V16 - Android / iPhone Device Detection Fix

## Problem fixed
The Device Wizard could show:

- `android_adb unavailable`
- `android_mtp unavailable`
- `ios_lockdown unavailable`
- `No USB tools in the API container and host drive helper is offline`

The API runs in Docker while USB/WPD/ADB devices exist on the Windows examiner host. The helper therefore must be running on Windows and reachable from both the browser (`127.0.0.1:9876`) and Docker (`host.docker.internal:9876`).

## V16 changes

1. HostDrive helper now supports Docker-reachable wildcard binding (`http://+:9876/`).
2. A one-time URL ACL and restricted Docker/WSL firewall rule is configured automatically (UAC may appear once).
3. Failure to install optional iOS tooling no longer prevents Android MTP/ADB helper startup.
4. Portable Android `adb.exe` is installed on a best-effort basis even when the complete examiner kit fails.
5. Startup now actively starts the HostDrive helper instead of relying only on a future logon task.
6. The React Device Wizard also probes the Windows helper directly, so a connected phone can be displayed even while the Docker bridge is being repaired.
7. Backend HostDrive bridge tries both `host.docker.internal` and `gateway.docker.internal`.
8. Added one-click repair/diagnostics: `Repair-Mobile-USB.cmd` / `scripts\repair-mobile-usb.ps1`.

## After replacing the project

Open PowerShell in the project root and run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\repair-mobile-usb.ps1
```

Or double-click:

```text
Repair-Mobile-USB.cmd
```

Accept the Windows UAC prompt the first time. The repair verifies:

- HostDrive helper health
- Android ADB availability
- Windows WPD/MTP device detection
- ADB authorization state
- Docker -> Windows helper connectivity
- `/acquisition/adapters`
- `/acquisition/devices`

## Android phone preparation

1. Use a USB **data cable** (not charge-only).
2. Unlock the phone.
3. Change USB mode to **File transfer / Android Auto / MTP**.
4. For ADB acquisition, enable **Developer options -> USB debugging**.
5. When Android asks, tap **Allow USB debugging**.
6. Click **Scan for devices** again.

MTP detection does not require USB debugging. ADB detection does.

## Manual checks

```powershell
Invoke-RestMethod http://127.0.0.1:9876/health
Invoke-RestMethod http://127.0.0.1:9876/acquisition/adapters
Invoke-RestMethod http://127.0.0.1:9876/acquisition/devices
.\tools\platform-tools\adb.exe devices -l
```

If ADB shows `unauthorized`, unlock the phone and approve the RSA prompt. If it shows `offline`, replug the cable and select File transfer/MTP.
