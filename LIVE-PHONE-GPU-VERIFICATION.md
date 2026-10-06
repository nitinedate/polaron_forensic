# Run actual phone, WhatsApp and GPU verification on the central host

The project includes an executable live acceptance path. Hardware success is recorded only after it runs on the host with the authorized Android phone connected and the selected product containers running. This editing workspace has no USB/ADB, Docker socket or NVIDIA device; it has not passed a live hardware test.

## Central Windows host

Connect the Android phone to the Windows host running the acquisition helper, unlock it and authorize USB debugging. The default script checks the `aetheris-mobile-android` Docker project. A different existing deployment can be selected with `-ProjectName`; Disk uses `-Product forensic` and legacy Mobile uses `-Product mobile-extract`.

Pause active Disk/Mobile jobs before replacing bind-mounted code. Preserve deployment credentials, overlays and evidence directories while extracting the updated source. Then run these complete commands from PowerShell:

```powershell
Set-Location H:\GIT\polaron
.\scripts\Apply-Disk-Mobile-Serial.ps1 -Products @('mobile-android') -PrepareVisionModel
if ($LASTEXITCODE -ne 0) { throw 'Deployment failed; review the deployment output before verification.' }
.\scripts\Test-Live-Phone-GPU.ps1 -Product mobile-android
```

The deployment script prepares the configured Ollama vision model. The verification script uses an existing host Python 3.11+ installation and ADB; it also recognizes the project's host Python kit and Android SDK platform-tools. Host-side private acquisition/key validation now loads without importing SQLAlchemy or GPU libraries. Docker API and OCR worker dependencies must be installed by the normal deployment build.

If more than one authorized phone is connected, supply `-DeviceSerial '<adb-serial>'`. The script deliberately refuses to select an arbitrary device.

## Include an existing acquisition or externally acquired key

Selected source files and all supplied key candidates are checked. Replace the example paths with the actual acquired directory and key file:

```powershell
Set-Location H:\GIT\polaron
.\scripts\Test-Live-Phone-GPU.ps1 -Product mobile-android `
    -EvidencePath 'D:\cases\android-dump' `
    -KeyFiles @('D:\cases\android-private\key')
```

`-EvidencePath` accepts an acquired directory or one acquired msgstore backup/database file, not a complete ZIP/image container. For image/ZIP acquisitions, select the already extracted evidence directory. Multiple `-KeyFiles` are supported. Do not enter raw keys into command lines or chat.

Phone collection reads available WhatsApp/WhatsApp Business databases, SQLite companions, key files and supported shared-storage backups. It uses only already granted `adbd` root, existing `su`, or permitted `run-as`; it does not install a root tool, unlock a bootloader, reset the phone, force-stop WhatsApp or bypass Android protection. Public/shared-storage backups can be acquired without private access, but crypt12/14/15 still need a matching valid key to authenticate. An ADB error saved as a key is rejected.

Supplying an acquisition cannot hide an absent phone: the **live_phone** check remains blocked until the actual phone responds and selected WhatsApp bytes can be acquired from it. Supplying the matching key can resolve backup decryption without granting private ADB access. Plaintext msgstore sources are parsed without a backup key.

## What must pass

| Check | Required evidence |
| --- | --- |
| Phone | One authorized Android device and selected WhatsApp bytes read from that device |
| Input/key validation | Supported key bytes; original acquisition inputs remain unchanged |
| Backup authentication | Every selected supported encrypted backup authenticates; partial recovery remains blocked |
| Message parsing | Production WhatsApp parser reads actual message rows from integrity-checked SQLite working copies; aliases with identical database/WAL bytes are deduplicated |
| GPU admission | Existing product-local and shared-host GPU permits are acquired; busy/hot lanes are reported as blocked |
| CUDA | A real device matrix calculation produces the expected numeric result |
| OCR | Production GLM-OCR reads the known `VERIFY7392` marker while its model resides on CUDA |
| Vision | Configured Ollama vision model describes the marker and `/api/ps` reports GPU memory residency; a CPU response cannot pass |
| Cleanup | Vision model unload is checked while admission is still held, then owned permits are released |

The printed image is a generated diagnostic pattern, not case evidence. It is never inserted into case artifacts or reports. Marker checks verify the working hardware/model path; they do not measure accuracy on every acquired image or establish suspicious activity in a case. Deleted-message availability depends on surviving acquired bytes; this test does not manufacture deleted records.

GPU inference has a default 600-second owned-process deadline and a 15-second permit-wait budget. The phone/WhatsApp step defaults to a 3,600-second command budget. Use `-GpuTimeoutSeconds` or `-PhoneTimeoutSeconds` for a slower valid run. Native commands print progress every 15 seconds. Timeouts stop only the diagnostic's owned process; no broadcast worker termination or global lease clearing is used.

## Results and next action

The script prints the output directory and **LIVE-VERIFICATION-RESULTS.zip**. This ZIP includes status, counts, hashes, device-serial hash, runtime/model information and individual failure checks. It explicitly excludes acquired key bytes, encrypted/plaintext databases and chat bodies. Raw selected evidence and successfully decrypted databases remain local in the printed output directory. Keep them with the case evidence.

Exit `0` means all required live checks passed; exit `2` means a failed or blocked check needs attention. Missing tools, private permissions, keys, models or GPU admission do not become a success. A blocked run still writes a diagnostic ZIP whenever PowerShell can create the output directory. Return that ZIP to review the actual host results; do not return the raw evidence/key folders for routine diagnostics.

After a successful run, ingest the local acquired/derived evidence through the existing Mobile workflow, or reprocess its existing case. Verify current/historical/deleted-state counts, browser/media/document coverage and source previews, then regenerate the report and review Suspicious Activity pictures and examiner notes. This script does not silently create a case, edit database records or approve a report; it records case ingestion/report verification as a separate application check.

## Validation completed for this release

235 focused regression tests plus 9 acquisition tests pass. New tests cover independent crypt12/14/15 vectors, missing/invalid/wrong keys, partial recovery, source preservation, actual message rows, duplicate snapshots, device ambiguity, missing phone with supplied evidence, CPU rejection, GPU-residency rejection and clean host-Python imports. The actual command-line entry points were run locally: independent fixture decryption passes; absent phone and GPU return **blocked**. Python 3.11 syntax and PowerShell grammar pass. No live handset/CUDA pass is claimed from those tests.

Primary interface references: [Android ADB authorization](https://developer.android.com/tools/adb), [Ollama running-model GPU residency](https://docs.ollama.com/api/ps).
