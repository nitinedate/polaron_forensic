# Polaron Expert Review V45 — 2026-10-04

Scope: full read of `polaron.zip` (backend 101 k LOC services, compose, `.env`) and
`laptop-scanner.zip`, the three screenshots, the agent log, the Fundfox Gap report and
the Nessus SOP. Every finding below is confirmed in the shipped code — several project
docs describe fixes that were never merged.

Production target: single RTX 3060 12 GB, Docker Desktop on Windows, evidence on `G:\`.

---

## 0. Bundle contents

```
POLARON_EXPERT_REVIEW_V45_20261004.md      this file
patches/01_extracted_disk_v45_wiring.patch  extracted_disk.py + virtual_disk.py (streaming worker wiring, DB-free opener, vendor filter hook)
patches/02_worker_db_pool_gpu_env.patch     docker-compose.yml + .env (pool 2+2 -> 4+8, /scratch mount, GPU admission, extraction tunables)
patches/03_mobile_whatsapp_messaging.patch  messaging.py (modern-schema routing, decrypted freelist carve, decrypt diagnostics)
patches/04_emlx_preview.patch               email_mime_parser.py (EMLX plist + sidecar attachments)
patches/05_laptop_scanner_nessus_parity.patch gmp_local.py + docker-compose.yml + .env (timeouts, port profile, UDP, concurrency)
patches/06_ocr_gpu_unload_ollama.patch      ocr_gpu.py (evict Ollama before GLM-OCR load)
patches/07_tests_whatsapp_key_offset.patch  tests/test_whatsapp_crypt.py (test encoded the wrong offset)
backend/app/services/extract_shard_v45.py           NEW streaming / DB-free / semaphore shard worker
backend/app/services/extract_os_vendor_noise.py     NEW AXIOM-aligned OS/vendor tree exclusion
backend/app/services/mobile_forensic/whatsapp_crypt.py        REPLACEMENT crypt12/14/15 decrypter
backend/app/services/mobile_forensic/parsers/whatsapp_modern.py NEW modern msgstore resolver + deleted recovery
backend/app/parsers/emlx_sidecar.py                 NEW Apple Mail plist / Attachments sidecar
backend/app/services/{extracted_disk,virtual_disk,ocr_gpu}.py, parsers/email_mime_parser.py, mobile_forensic/parsers/messaging.py
                                             full post-patch copies (same content as patches)
laptop-scanner/{docker-compose.yml,.env.v45,scanner-agent/agent/gmp_local.py}  post-patch copies
docker-compose.yml.v45, .env.v45.example     post-patch copies (secrets stripped from .env)
tests/test_whatsapp_crypt_v45.py             9 new tests (crypt12/14/15 round-trip, key kinds, fail-closed)
```

Apply from the repo root: `git apply patches/*.patch`, then copy the NEW/REPLACEMENT
files into place. All seven patches apply cleanly to the shipped tree (`git apply --check`),
every touched module compiles, and the existing suites for touched modules show
**0 new failures** (the 9 failures that remain fail identically on the untouched tree —
see §7).

---

## 1. Disk extraction — Image 1 error and Image 2 throughput

### 1.1 `QueuePool limit of size 2 overflow 2 reached` (Image 1)

Root cause is arithmetic, not load.

* `docker-compose.yml` `x-worker-env`: `DB_POOL_SIZE=${WORKER_DB_POOL_SIZE:-2}`,
  `DB_MAX_OVERFLOW=2`, `DB_POOL_TIMEOUT=30`. `.env` does not override them.
* Inside one extraction task: the task's own session + `_ProgressFlusher` thread +
  `_StopPoller` thread + `disk_log_heartbeat` thread = **4 connections = the whole pool**.
* `_shard_worker` then opened `firm_session` for the shard start log, for
  `_check_stop()` every `EXTRACT_STOP_CHECK_INTERVAL` files, and for every unreadable-file
  log. The first shard that needed one waited 30 s and raised exactly the message in
  the screenshot. With `EXTRACT_SHARD_COUNT=14` the failure is deterministic.

Fix (patch 01 + `extract_shard_v45.py`): shard threads **never touch the DB**. They push
events on a `ShardEventBus`; the flusher (already the single DB writer) drains it.
`_check_stop` DB polling inside shards is dropped — `_StopPoller` already exists.
Patch 02 raises the worker pool to 4+8 with a 90 s timeout as belt-and-braces
(Postgres has `max_connections=200`; `worker-disk` 8 children × 12 + `worker-parse`
6 × 12 fits).

### 1.2 21.6 GB in 2 h 15 m ≈ 2.7 MB/s (Image 2)

Four compounding causes, all verified:

1. **V41 never shipped.** `DISK_PERFORMANCE_V41_20260930.md` claims streaming reads,
   HDD-aware single-reader mode and `EXTRACT_SCRATCH_DIR`. In the code:
   `disk_io_profile.py` is imported nowhere; `EXTRACT_HDD_READERS` /
   `EXTRACT_SOURCE_PROFILE` / `EXTRACT_SCRATCH_DIR` are absent from `config.py`;
   `_shard_worker` still does `read_full_file_from_disk()` → `io.BytesIO()` (whole file in
   RAM, then a local `.tar.zst`, then upload); and `tests/test_extract_stream_reader.py`
   imports `_IterFileReader` from `extracted_disk`, a class that does not exist — the
   test errors at collection on the shipped tree.
2. **Up to 14 independent pyewf handles** on one E01 (`plan_ewf_extract_io`, `hi=12`
   on a 16-core host, `EXTRACT_DISK_WORKERS=12`). Each shard is inode-ordered internally
   but the 12 handles seek against each other. On a rotational/USB source behind
   Docker Desktop's Windows file-sharing layer this collapses to single-digit MB/s.
3. **The file set is ~3× too large.** `defensible` mode keeps any file under `Windows\`
   with an extension and ≤ 512 KB (`matches_defensible_include` → `return bool(ext) or
   size_bytes <= cap`) plus anything ≤ `EXTRACT_UNCERTAIN_MAX_BYTES=16 MB` elsewhere.
   That is WinSxS, `.mui`, `.cat`, `.manifest`, `.pnf`, DriverStore — the 180 826 files.
   `EXTRACT_SKIP_SYSTEM_PATHS` is **ignored by design** in `defensible`/`forensic`
   (`resolve_skip_system_paths`), and no NSRL index is configured, so filtering is
   path-only.
4. **GPU overcommit.** `OCR_CUDA_MEMORY_FRACTION=0.62 + RAG_CUDA_MEMORY_FRACTION=0.40 =
   1.02` with `GPU_HEAVY_MAX_CONCURRENT=2` and `RESOURCE_GOVERNOR_GPU_MAX_SLOTS=4` on a
   12 GB card that also serves `qwen2.5:14b` (~9 GB). `_prepare_cuda_for_ocr_load`
   evicts the embedder but not Ollama. OCR eligibility itself (clear-photo detector,
   documents-only gate, 4 KB floor) is already good; admission was the problem.

Also found: `_open_filesystem` mounts **only the single highest-scored partition**.
A second data partition (D:, dual-boot, recovery with user data) is silently skipped,
unlike AXIOM. Not patched here (needs a `VirtualDisk` → multi-FS refactor); see §6.

### 1.3 What V45 does

`extract_shard_v45.shard_worker_v45` (drop-in for `_shard_worker`, same checkpoint /
part / index / return contract so resume and Phase-3 are unchanged):

| Change | Effect |
|---|---|
| Stream `iter_file_from_disk` chunks (4 MiB; 8 MiB on HDD) through a `SpooledTemporaryFile` (RAM ≤ 32 MB, else `/scratch`) straight into the tar; SHA-256 in the same pass | no whole-file RAM copies; big files never blow the 14 GB worker limit |
| `threading.BoundedSemaphore(EXTRACT_READ_SEMAPHORE=8)` around every image read | the **8–10 thread semaphore you asked for**; shard count can stay at 14 for resumability while concurrent seeks are bounded |
| `plan_readers()` wires `disk_io_profile`: HDD/network → ≤ `EXTRACT_HDD_READERS=2`; unknown media (Docker Desktop) → half the semaphore; SSD/NVMe → semaphore | rotational sources stop thrashing |
| Async upload pool (`EXTRACT_UPLOAD_CONCURRENCY=4`); a shard still waits for *its own* upload before completing | readers never block on MinIO; checkpoints stay correct |
| `open_virtual_disk_from_paths()` + `vd_plan` in payloads | shard VD open without a DB session |
| Per-shard throughput line in the disk log (`MiB/s`) | you can see which shard/source is slow |

`extract_os_vendor_noise.py` (hooked into `_filter_nodes`, enabled by
`EXTRACT_OS_VENDOR_TREES=skip`) drops regenerable vendor trees — WinSxS, servicing,
DriverStore, WindowsApps, Installer, SoftwareDistribution\Download, .NET, Defender
platform, Program Files binaries, AppData\Local\Programs, UWP packages, etc. — **unless
`scope_claim_strength(path) == "specific"`**, i.e. the AXIOM scope pack names it.
Verified: hives, `.evtx`, Prefetch, Amcache, SRUM, `$MFT`, `$UsnJrnl:$J`, Chrome
`History`, `.lnk`, scheduled tasks, VSS and `Packages\*\LocalState\*.db` all stay
(see §7). Expect the Reception-laptop file set to drop from ~180 k to ~40–60 k with
no loss of catalogued artifacts.

GPU (patch 02 + 06): `GPU_HEAVY_MAX_CONCURRENT=1`, `RESOURCE_GOVERNOR_GPU_MAX_SLOTS=1`,
OCR fraction 0.80 / RAG 0.35 (they no longer coexist), `OLLAMA_KEEP_ALIVE=2m`, and
OCR now evicts Ollama before loading GLM-OCR (`GPU_THERMAL_UNLOAD_OLLAMA_BEFORE_OCR`).
The order on the 3060 is strictly OCR → embeddings → LLM, one resident at a time.
OCR itself stays on one GPU worker (`--pool=solo`); `OCR_CPU_WORKERS=6` pre-rasterise
and run the clear-photo / blank-page gate on CPU so the GPU only sees scanned pages.

### 1.4 Expected result

With the vendor filter, 2 sequential-ish readers on HDD (8 on SSD), streaming I/O and
scratch on NVMe, a 50 GB image on a USB-3 HDD (~80–100 MB/s sustained) should reach
*Evidence Ready* in **12–20 min** instead of >2 h; on internal NVMe, 5–8 min. The hard
floor is the source read rate: Docker Desktop's `G:\` bind mount tops out well below
the drive. Two host-side changes outrank any code: (a) copy the E01 set to an NVMe
folder under `AETHERIS_BACKUP_DIR` first (one sequential copy at full drive speed,
then extraction is NVMe-bound), or (b) expose the drive through WSL2 (`/mnt/g`) and
bind that, which bypasses the 9p/gRPC-FUSE path. Set `DISK_SOURCE_MEDIA=nvme|hdd`
explicitly because Docker Desktop hides the block device from `/sys`.

---

## 2. AXIOM-aligned extraction and EML(X)

* The scope packs under `os_artifact_scope/` are already the AXIOM artifact catalogue;
  the vendor filter above uses them as the hard "never drop" set, so extraction now
  pulls *exactly* the trees AXIOM reads plus user data, not the OS.
* `.emlx`: the length-prefix framing was handled, but the trailing plist was discarded
  and `.partial.emlx` sidecars were invisible. `emlx_sidecar.py` decodes `flags`
  (read / deleted / answered / flagged / junk …), `date-received`, `date-sent`,
  `remote-id` (IMAP UID), `gmail-labels`, and links `Attachments/<msgnum>/<part>/<file>`
  by message number. Patch 04 surfaces this as `preview["emlx"]` and appends sidecar
  attachments with `source="apple_mail_sidecar"`, so the Artifacts pane shows the real
  attachment set. Callers that have the job inventory should pass `sibling_paths=`
  (the paths under the same `Data/<n>/<n>/` folder) — one `LIKE 'prefix%'` on
  `job_artifacts.file_path` indexed by `(job_id, file_path)` is enough.

---

## 3. Android WhatsApp — 0 messages / 0 deleted

### 3.1 The decrypter could never work

`whatsapp_crypt.cipher_key_from_material` took the AES key from **offset 30** of the
158-byte `files/key`. Bytes 30–62 are the `t1` header checksum (compared to crypt12
header `[3:35]`); the AES-256 key is the **last 32 bytes (126–158)**. Every decrypt was
fail-closed → `whatsapp_messages = 0` whenever the source was a `.crypt14/.crypt15`.
`tests/test_whatsapp_crypt.py` asserted the wrong offset, so CI was green (patch 07).

Also missing: crypt15 key derivation (the 64-digit backup key is HKDF-SHA256'd with
zero salt and info `"backup encryption"` before use) and crypt14/15 header parsing
(only a list of guessed body offsets existed).

The replacement `whatsapp_crypt.py`:

* parses 158-byte key file / 32-byte raw / 64-hex (spaces, dashes tolerated); keeps
  `t1` and reports whether it matches the crypt12 header (wrong-device diagnosis);
* crypt12 fixed layout; crypt14/15 via a dependency-free protobuf walker that
  harvests 16-byte IV fields from the `BackupPrefix` plus the historical fixed offsets;
* AES-256-GCM (tag position differs per release, so decrypt-without-verify) → zlib
  inflate → hard oracle `SQLite format 3\0`. ≤ ~40 deterministic candidates with a
  known key; not brute force;
* `last_decrypt_diagnostics()` tells the examiner *why* a decrypt failed
  (`key_kind`, `container`, `t1_match`, notes such as "crypt15 needs
  `encrypted_backup.key`, not `files/key`"). Patch 03 writes this into the
  `app_backup_encrypted` artifact instead of silently yielding nothing.

Validation: 9 new tests round-trip crypt12/14/15 fixtures built from the documented
layouts. **Caveat:** the crypt14/15 header fixtures are generated by this module's
own encoder; before release, run `try_decrypt_whatsapp_crypt` on one real
`msgstore.db.crypt15` + its 64-digit key from a test handset and keep that pair as a
CI fixture (encrypted file + key only — no decrypted content in the repo).

### 3.2 The parser targeted the pre-2021 schema

`_parse_messages` probed columns generically. On the modern schema that silently
degrades: `chat_row_id` / `sender_jid_row_id` were emitted as integers (never joined
through `chat → jid.raw_string`), media lives in `message_media` so `media_path` was
always NULL, and "deleted" looked for `is_deleted` / `revoke_timestamp` columns that do
not exist — "Delete for everyone" is `message_type = 15` + a `message_revoked` row.

`whatsapp_modern.py` (routed from `messaging.py` when `message`+`jid`+`chat_row_id`
are present; legacy probe stays as fallback):

* conversations with JID, phone, type (contact / group / broadcast / channel / LID);
* messages with resolved sender, `message_type_label` (text, image, …, revoked,
  view-once, poll, edited), `message_media` join (path, mime, size, hash, caption),
  `message_edit_info`, server receipt time;
* **deleted recovery, AXIOM-style:** revoked rows flagged `database_deleted` with
  `revoked_by_jid`; the original text is recovered from `message_quoted` (a reply
  keeps a copy) and from the FTS shadow table `message_ftsv2_content.c0` keyed by
  `docid = message._id`; messages whose chat no longer exists are flagged
  `chat_deleted_orphan_message`; `deleted_chat_job` rows become deleted conversations;
* "Delete for me" leaves only freelist/WAL remnants, and the deleted pipeline carved
  the *stored* artifact bytes — ciphertext for a `.crypt14`. Patch 03 runs
  `recover_sqlite_residuals` on the **decrypted** bytes.

### 3.3 Acquisition reality (no code can fix this part)

Without root, `adb` cannot read `/data/data/com.whatsapp/` — neither `msgstore.db` nor
`files/key`. Only `/sdcard/Android/media/com.whatsapp/Databases/msgstore.db.crypt14/15`
is reachable, which `android_adb.py` already pulls. Supported routes, in order of
evidentiary cleanliness:

1. **crypt15 + the 64-digit end-to-end backup key** — the examiner reads it from the
   handset (Settings → Chats → Chat backup → End-to-end encrypted backup) and enters it
   in the existing `whatsapp_key_hex` intake field. Zero device modification. This is
   now the primary path and works with the rewritten decrypter.
2. **Rooted device** → `privileged_app_pull` already collects `msgstore.db`, `wa.db`
   and `files/key` (crypt12/14 then also open).
3. **Legacy-APK downgrade backup** (what UFED/Oxygen/AXIOM "Android downgrade" do):
   back up the current APK, `adb install -r -d` WhatsApp 2.11.431 (`allowBackup=true`),
   `adb backup -f wa.ab com.whatsapp`, unpack the `.ab`, read `databases/msgstore.db` +
   `files/key`, reinstall the original APK. It writes to the device and must be logged
   in the chain of custody with examiner approval; recommend implementing it as an
   explicit `CollectionMethod.ADVANCED_LOGICAL` sub-option with a consent gate, not as a
   default.

---

## 4. Vulnerability scanning — 7–8 min, 3 info findings per host

### 4.1 Root cause: the port scanner was being killed

`gmp_local.LocalOpenVAS.__init__` forced `plugins_timeout ≥ 60 s` and
`scanner_plugins_timeout ≥ 90 s` (comment: added to stop an SMB loop pinning a host at
94–97 %), and `configure-openvas` in the laptop compose hard-coded the same into
`openvas.conf`. Greenbone's defaults are **320 s and 36 000 s**; your own central
`docker-compose.gvm.yml` uses 30 days. `scanner_plugins_timeout` is the budget for the
*port-scanner* NVTs (Nmap / `find_service`); a `T:1-65535` sweep needs minutes, so
it was terminated at 90 s → no open ports → no service NVTs ran → exactly 3
informational results ("Host alive", OS/traceroute) and `plugin_errors: 1` on every
host in your log. The 7–8 min runtime is the time it takes to *not* scan.

Secondary: the laptop `.env` ran `PORT_PROFILE=fast`, `UDP_PROFILE=off`,
`GVM_OPTIMIZE_TEST=yes`, and the agent silently raised `GVM_MAX_CHECKS=8` to 16.

### 4.2 Nessus "Advanced Scan" parity (per your SOP)

| SOP setting | V45 OpenVAS equivalent |
|---|---|
| Discovery: UDP packets, fragile devices | `UDP_PROFILE=priority` (U:53,67-69,123,137-138,161-162,500,…), `GVM_ALIVE_TEST=Consider Alive`, `safe_checks=yes` |
| Verify open TCP ports found by local enumerators; all TCP | `PORT_PROFILE=full` → `T:1-65535`, `optimize_test=no` |
| Service discovery incl. DTLS / all UDP ports | priority UDP list above; full `U:1-65535` is ~hours/host on Nessus too — opt in per job via `GVM_TARGET_PORT_RANGE` |
| Web application tests enabled | "Full and fast" includes the *Web application abuses* / *Web Servers* families; ZAP remains the deep DAST layer |
| DoS disabled | `safe_checks=yes` (Denial of Service family stays off) |
| Malware / file-system scanning | credentialed SMB/SSH local checks via central `scanner_credentials` (Notus LSC enabled: `table_driven_lsc = yes`) |
| Network timeout 10 s | `checks_read_timeout=10`, `timeout_retry=3`, `open_sock_max_attempts=5` |
| Audit trail verbosity | `report_host_details=yes` |

Timeouts restored to 320 / 36 000 s (env-overridable). The SMB-hang concern is handled
where it belongs: the agent watchdog (`MAX_SCAN_RUNTIME_SEC=5400`, `STALL_SEC=1500`)
cancels a stuck task and keeps partial results, rather than degrading coverage for
every host.

Concurrency: `SCAN_IP_MAX_PARALLELISM=8` (eight OpenVAS tasks in flight, one host each)
with `GVM_MAX_CHECKS=8` honoured → ≤ 64 NVT processes on the laptop. SLO reset to
~12 hosts/h at ~35 min/host for a full-port, UDP-priority scan — that is what a
Nessus Advanced Scan costs too. The Fundfox findings (SSLv2/v3, SWEET32, OpenSSH < 7.2,
Dropbear < 2016.72, SMB unprivileged shares, IP forwarding) are all remote,
unauthenticated NVTs in the Greenbone feed; with services actually discovered they
will reappear, and `aetheris_severity.py` already floors SSLv2/v3 to Critical and
SWEET32 to High to match the Nessus-based report style.

---

## 5. Rollout

1. `git apply patches/*.patch`; copy the 5 NEW/REPLACEMENT modules; copy
   `tests/test_whatsapp_crypt_v45.py` to `backend/tests/`.
2. Create the scratch folder on NVMe and set `EXTRACT_SCRATCH_HOST_DIR` in `.env`
   (defaults to `AETHERIS_BACKUP_DIR/forensic-data/scratch`).
3. `docker compose up -d --build api worker-disk worker-parse worker-ocr-gpu worker-rag-gpu`.
4. Laptop: replace `.env` with `.env.v45` (re-add `GVM_PASSWORD`/tokens), `docker compose
   up -d --force-recreate configure-openvas openvas ospd-openvas scanner-agent`. Confirm
   `cat /etc/openvas/openvas.conf` shows `plugins_timeout = 320` and
   `scanner_plugins_timeout = 36000`.
5. Re-run the Reception-laptop job with `EXTRACT_REPLAN_ON_RESUME=true` once so the
   plan is rebuilt with the vendor filter; watch the disk log for the
   `Extract I/O plan … +v45[...]` line and per-shard `MiB/s`.

## 6. Still open (not in this bundle)

* Multi-partition images: `_open_filesystem` keeps one FS. Needs `VirtualDisk` to hold a
  list of `(offset, FS_Info)` and `enumerate_all_files` to prefix paths with the volume.
* NSRL/RDS known-good index: `extract_known_good.py` is complete and unused — build the
  `.hgi` once and set `FORENSIC_KNOWN_GOOD_INDEX`; hash exclusion is stronger than paths.
* Downgrade-backup acquisition method (§3.3 item 3) behind a consent gate.
* Central `greenbone_gmp.py` server-side scans already use 30-day timeouts; align
  `GVM_MAX_CHECKS=20 / GVM_MAX_HOSTS=8` with the central host's cores.

## 7. Verification record

* `tests/test_whatsapp_crypt_v45.py`: 9 passed (crypt12/14/15 round-trip; key file
  offset; hex/raw/garbage inputs; HKDF determinism; wrong-key fail-closed with
  diagnostics; plaintext pass-through).
* Synthetic modern `msgstore.db`: 2 chats, 4 messages (1 image with `message_media`,
  1 revoked with text recovered from `message_quoted`, 1 orphan of a deleted chat),
  1 deleted-chat job, 1 call — all resolved with JIDs; deleted count 2.
* `extract_shard_v45` end-to-end in folder mode: 4 shards, 301 files incl. a 70 MB
  spool-to-disk file and one unreadable path; every part is a valid `.tar.zst`, every
  index SHA-256 matches the tar member, 13 events through the bus, 0 DB calls.
* Vendor filter: 20 representative Windows paths — 7 vendor trees skipped, all 13
  AXIOM artifacts kept.
* EMLX: plist flags/date-received/remote-id/gmail-labels decoded; sidecar
  `Attachments/13/2/report.pdf` linked, `…/14/…` correctly excluded.
* Existing suites on the patched tree: `test_whatsapp_crypt`, `test_whatsapp_modern_extract`,
  `test_mobile_architecture_v2`, `test_email_mime_inventory`, `test_extract_parallel_plan`,
  `test_extract_then_process_barrier_v43`, `test_os_aware_extract`,
  `test_mobile_extraction_os`, `test_whatsapp_protocol_noise`,
  `test_emlx_evidence_reconciliation_v44`, `test_carved_email_mime_v36`: 86 passed,
  9 failed — the same 9 fail identically on the untouched tree (frontend assets /
  environment), plus `test_extract_stream_reader.py` which errors at collection on
  both because `_IterFileReader` was never merged.
* Not exercised in this sandbox: pyewf/pytsk3 reads and MinIO (no E01 or object store
  here); the EWF path uses the same `iter_file_from_disk` generator the folder path
  does.
