# Aetheris Mobile USB Detection Fix V17

Date: 2026-09-18

## Problem fixed

The Device Acquisition page could show all USB adapters as unavailable even when an Android phone was physically attached. The UI warning reported that the HostDrive helper on TCP 9876 was offline.

The main startup failure fixed in V17 was in the Windows helper bootstrap: `Start-Process` flattened its argument list and the `host-drive-helper.ps1` path was not explicitly quoted. If Aetheris was extracted into a Windows path containing spaces, the hidden PowerShell helper could exit immediately. Because it was hidden, the examiner only saw "port 9876 offline" in the browser.

V17 also repairs stale Windows HTTP URL reservations created by another user/older checkout, rebuilds the Docker/WSL firewall rule, captures helper startup logs, and self-elevates the one-click USB repair utility.

## V17 changes

- Quotes the HostDrive helper script path when started in the background.
- Saves helper stdout/stderr under `%LOCALAPPDATA%\Aetheris`.
- Displays startup errors when the helper exits early.
- Detects and replaces a stale `http://+:9876/` URL ACL owned by another Windows account.
- Recreates the TCP 9876 firewall rule for private Docker/WSL address ranges.
- `Repair-Mobile-USB.cmd` now triggers a UAC prompt automatically; no separate Administrator PowerShell is required.
- Mobile USB repair checks Windows PnP/WPD/MTP state and reports bad Android USB drivers.
- HostDrive helper version bumped to 5.3; an old helper is restarted automatically.
- Server startup invokes the one-click repair automatically if the helper remains offline.
- UI preserves direct Windows-host adapter availability if the Docker API cannot reach the helper yet.
- Fixed the report preview source syntax around Windows path detection so the frontend remains buildable.

## Recommended deployment

1. Extract the V17 full merged ZIP to a normal Windows folder.
2. Close any older Aetheris stack/helper windows.
3. Double-click `Repair-Mobile-USB.cmd` once and accept the UAC prompt.
4. Start Aetheris with `Start-Server.cmd` or the normal project startup command.
5. On Android, unlock the phone and select **File transfer / MTP**. For ADB, enable **USB debugging** and accept **Allow USB debugging**.
6. Click **Scan for devices**.

## Manual verification

```powershell
Invoke-RestMethod http://127.0.0.1:9876/health
Invoke-RestMethod http://127.0.0.1:9876/acquisition/adapters
Invoke-RestMethod http://127.0.0.1:9876/acquisition/devices
.\tools\platform-tools\adb.exe devices -l
```

Expected adapter state for Android after the helper is running:

- `android_mtp` = available
- `android_adb` = available when `adb.exe` is present

If ADB reports `unauthorized`, unlock the phone and accept the RSA debugging prompt. If Windows PnP shows a non-OK Android/MTP entry, update/reinstall the phone's MTP/OEM USB driver in Device Manager.

## Logs

If helper startup still fails, inspect:

```text
%LOCALAPPDATA%\Aetheris\host-drive-helper.err.log
%LOCALAPPDATA%\Aetheris\host-drive-helper.out.log
```

The V17 repair script prints the tail of both logs automatically on failure.
