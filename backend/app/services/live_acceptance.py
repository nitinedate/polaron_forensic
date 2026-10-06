"""Real host acceptance checks; never substitute mocks or CPU for a GPU pass."""
from __future__ import annotations

from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from uuid import uuid4

KEY_NAMES = {'key', 'encrypted_backup.key', 'whatsapp.key', 'whatsapp_key.hex'}
BACKUP_SUFFIXES = ('.crypt12', '.crypt14', '.crypt15')
SQLITE_LIMIT = 768_000_000
MARKER = 'VERIFY7392'


def new_report(scope):
    return {'scope': scope, 'started_at': datetime.now(timezone.utc).isoformat(),
            'checks': [], 'live_execution_claimed': False}


def check(report, name, status, detail, *, required=True, **evidence):
    report['checks'].append({'name': name, 'status': status, 'detail': detail,
                             'required': required, 'evidence': evidence})


def finish(report):
    required = [c for c in report['checks'] if c['required']]
    report['status'] = ('failed' if any(c['status'] == 'fail' for c in required)
                        else 'passed' if required and all(c['status'] == 'pass' for c in required)
                        else 'blocked')
    report['finished_at'] = datetime.now(timezone.utc).isoformat()
    report['live_execution_claimed'] = report['status'] == 'passed'
    return report


def write_report(path, report):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(finish(report), indent=2, default=str) + '\n', encoding='utf-8')
    path.chmod(0o600)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def is_input(path):
    name = Path(path).name.lower()
    return (name in KEY_NAMES or name.startswith('msgstore') and
            name.endswith((*BACKUP_SUFFIXES, '.db', '.db-wal', '.db-shm', '.db-journal')))


def stage_inputs(source, keys, destination):
    """Stage selected acquired WhatsApp files, preserving and checking originals."""
    destination = Path(destination).resolve()
    copied = []
    if source:
        source = Path(source).resolve()
        if not source.exists():
            raise FileNotFoundError('Acquired evidence path does not exist')
        if destination.is_relative_to(source if source.is_dir() else source.parent):
            raise ValueError('Verification output must be outside the acquired source directory')
        candidates = source.rglob('*') if source.is_dir() else [source]
        base = source if source.is_dir() else source.parent
        for path in candidates:
            if not path.is_file() or path.is_symlink() or not is_input(path):
                continue
            rel = path.relative_to(base)
            target = destination / 'external' / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            target.chmod(0o600)
            digest = sha256(path)
            if digest != sha256(target):
                raise ValueError('Acquired evidence changed during verification staging')
            copied.append({'path': str(target.relative_to(destination)), 'sha256': digest,
                           'origin': 'supplied_acquisition', 'size_bytes': target.stat().st_size})
    from app.services.mobile_forensic.whatsapp_crypt import parse_key_material
    for index, key in enumerate(keys):
        key = Path(key)
        if key.stat().st_size > 512 or not parse_key_material(key.read_bytes()):
            raise ValueError('Supplied key is invalid; an ADB error file is not a key')
        target = destination / 'supplied-keys' / str(index) / 'key'
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(key, target)
        target.chmod(0o600)
        copied.append({'path': str(target.relative_to(destination)), 'sha256': sha256(target),
                       'origin': 'supplied_key', 'size_bytes': target.stat().st_size})
    return copied


def connected_device(adb, serial=''):
    result = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError('ADB device listing failed')
    rows = [line.split()[:2] for line in result.stdout.splitlines()
            if line.strip() and not line.startswith(('List of devices', '*'))]
    rows = [row for row in rows if len(row) == 2]
    if serial:
        rows = [row for row in rows if row[0] == serial]
    devices = [row[0] for row in rows if row[1] == 'device']
    if len(devices) != 1:
        if any(row[1] == 'unauthorized' for row in rows):
            raise RuntimeError('Unlock the connected phone and authorize its USB debugging prompt')
        raise RuntimeError('Exactly one authorized Android device is required; supply its serial when several are connected')
    return devices[0]


def capture_phone(*, adb, serial, output, source=None, keys=()):
    from app.services.mobile_acquire import privileged_app_pull as pull
    output = Path(output)
    raw = output / 'raw'
    report = new_report('live_android_and_selected_whatsapp_acquisition')
    if raw.exists() and any(raw.iterdir()):
        raise ValueError('Use a new verification output directory; acquired files are never overwritten')
    raw.mkdir(parents=True, exist_ok=True)
    raw.chmod(0o700)
    manifest = []
    try:
        serial = connected_device(adb, serial)
        check(report, 'phone_connection', 'pass', 'One authorized Android device responded',
              serial_sha256=hashlib.sha256(serial.encode()).hexdigest())
        mode = pull._root_mode(adb, serial)
        users = pull._android_users(adb, serial)
        modes = {}
        for package in ('com.whatsapp', 'com.whatsapp.w4b'):
            if mode:
                modes[package] = mode
            else:
                cp = pull._run(pull._adb_prefix(adb, serial) + ['shell', f'run-as {package} pwd'], timeout=12)
                if cp.returncode == 0 and re.fullmatch(rf'/data/(?:user/\d+|data)/{re.escape(package)}', cp.stdout.strip()):
                    modes[package] = 'run_as:' + package
        check(report, 'private_access', 'pass' if modes else 'blocked',
              'Existing private-file permission is available' if modes else 'Private app data is inaccessible through current ADB permissions',
              required=False, mode=mode or ('run_as' if modes else 'unavailable'))
        candidates = []
        for package, access in modes.items():
            roots = [f'/data/data/{package}', *[f'/data/user/{user}/{package}' for user in users]]
            for root in roots:
                for relative in ('files/key', 'files/encrypted_backup.key', 'databases/msgstore.db',
                                 'databases/msgstore.db-wal', 'databases/msgstore.db-shm', 'databases/msgstore.db-journal'):
                    remote = root + '/' + relative
                    if pull._remote_exists(adb, serial, access, remote):
                        candidates.append((remote, access))
        for root in ('/sdcard/Android/media/com.whatsapp/WhatsApp/Databases',
                     '/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business/Databases',
                     '/sdcard/WhatsApp/Databases', '/sdcard/WhatsApp Business/Databases'):
            for remote in pull._list_files(adb, serial, mode or 'shell', root):
                if is_input(Path(remote)):
                    candidates.append((remote, mode or 'shell'))
        rejected = 0
        for remote, access in dict.fromkeys(candidates):
            target = raw / 'phone' / pull._safe_rel(remote)
            ok, _error = pull._cat_file(adb, serial, access, remote, target)
            if ok:
                target.chmod(0o600)
                manifest.append({'path': str(target.relative_to(raw)), 'origin': 'live_adb',
                                 'sha256': sha256(target), 'size_bytes': target.stat().st_size})
            else:
                rejected += 1
        check(report, 'live_whatsapp_acquisition', 'pass' if manifest else 'blocked',
              'Selected WhatsApp bytes were collected read-only from the phone' if manifest else
              'No readable WhatsApp database, backup or key was available through the current phone permissions',
              captured_files=len(manifest), rejected_files=rejected)
    except Exception as exc:
        detail = str(exc) if isinstance(exc, RuntimeError) else 'Phone collection could not execute; check ADB and local access'
        check(report, 'live_phone_collection', 'blocked', detail, error_type=type(exc).__name__)
    try:
        staged = stage_inputs(source, keys, raw)
        manifest.extend(staged)
        check(report, 'supplied_evidence_staging', 'pass', 'Selected supplied inputs were copied with matching SHA256',
              required=bool(source or keys), staged_files=len(staged))
    except Exception as exc:
        check(report, 'supplied_evidence_staging', 'blocked',
              'Supplied path/key could not be staged or validated; input evidence was retained', error_type=type(exc).__name__)
    (output / 'acquired-files.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    (output / 'acquired-files.json').chmod(0o600)
    return finish(report)


def verify_whatsapp(source, derived):
    from app.services.mobile_acquire.android_readable import _materialize_whatsapp_decrypted
    from app.services.mobile_forensic.parsers._sqlite_util import SqliteEvidenceBytes, open_sqlite_bytes
    from app.services.mobile_forensic.parsers.messaging import WhatsAppParser
    from app.services.mobile_forensic.models import InventoryItem
    from app.services.mobile_forensic.plugins import ParseContext
    from app.services.mobile_forensic.whatsapp_crypt import parse_key_material
    source, derived = Path(source).resolve(), Path(derived).resolve()
    if derived.is_relative_to(source):
        raise ValueError('Derived output must be outside the acquired source tree')
    report = new_report('authenticated_whatsapp_and_actual_message_parsing')
    files = [p for p in source.rglob('*') if p.is_file() and not p.is_symlink()]
    inputs = [p for p in files if is_input(p)]
    hashes = {str(p): sha256(p) for p in inputs}
    crypts = [p for p in inputs if p.name.lower().startswith('msgstore') and p.name.lower().endswith(BACKUP_SUFFIXES)]
    eligible_crypts = [p for p in crypts if p.stat().st_size <= SQLITE_LIMIT]
    if len(eligible_crypts) != len(crypts):
        check(report, 'backup_size', 'blocked', 'A selected backup exceeds the supported input ceiling',
              oversize_backups=len(crypts)-len(eligible_crypts))
    keys = [p for p in inputs if p.name.lower() in KEY_NAMES]
    valid = [p for p in keys if p.stat().st_size <= 512 and parse_key_material(p.read_bytes())]
    check(report, 'key_validation', 'pass' if valid or not crypts else 'blocked',
          'Supported key material validated' if valid else 'No valid matching-key candidate was acquired' if crypts else 'Plaintext sources do not require a backup key',
          valid_candidates=len(valid), invalid_candidates=len(keys)-len(valid), encrypted_backups=len(crypts))
    result = {'copied': [], 'errors': [], 'limitations': [], 'whatsapp_decryption_state': 'not_applicable'}
    # Acceptance must examine every selected backup, regardless of production caps.
    previous = os.environ.pop('MOBILE_WHATSAPP_DECRYPT_MAX', None)
    try:
        _materialize_whatsapp_decrypted(eligible_crypts, valid, derived / 'whatsapp_decrypted', result)
    finally:
        if previous is not None:
            os.environ['MOBILE_WHATSAPP_DECRYPT_MAX'] = previous
    state = result['whatsapp_decryption_state']
    backups = result.get('whatsapp_backup_results') or []
    authenticated = sum(r.get('state') == 'decrypted' and r.get('diagnostics', {}).get('authenticated') is True for r in backups)
    crypto_ok = not crypts or state == 'decrypted' and authenticated == len(crypts)
    check(report, 'backup_authentication', 'pass' if crypto_ok else 'blocked',
          'Every selected encrypted backup authenticated' if crypts and crypto_ok else
          'No encrypted backup selected' if not crypts else 'One or more backups remain unreadable with the supplied key candidates',
          encrypted_backups=len(crypts), authenticated_backups=authenticated, state=state,
          failures=result.get('whatsapp_decrypt_failed', 0))
    databases = [p for p in inputs if p.name.lower().startswith('msgstore') and p.name.lower().endswith('.db')]
    databases.extend(Path(r['dest']) for r in result['copied'])
    counts = Counter()
    checked = []
    snapshots = set()
    for path in databases:
        try:
            if path.stat().st_size > SQLITE_LIMIT:
                raise ValueError('Database exceeds the supported SQLite input ceiling')
            raw = path.read_bytes()
            paths = {suffix: Path(str(path)+suffix) for suffix in ('-wal', '-journal') if Path(str(path)+suffix).is_file()}
            if any(p.stat().st_size > SQLITE_LIMIT for p in paths.values()):
                raise ValueError('SQLite companion exceeds the supported input ceiling')
            companions = {suffix: p.read_bytes() for suffix, p in paths.items()}
            signature=(hashlib.sha256(raw).hexdigest(),tuple((suffix,hashlib.sha256(blob).hexdigest()) for suffix,blob in companions.items()))
            if signature in snapshots:
                continue
            snapshots.add(signature)
            raw = SqliteEvidenceBytes(raw, companions)
            with open_sqlite_bytes(raw) as connection:
                if connection is None or connection.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                    raise ValueError('SQLite integrity check failed')
            context = ParseContext(job_id=str(uuid4()), platform='Android', read_bytes=lambda *_a, **_kw: raw)
            item = InventoryItem(path=str(path), size=len(raw), sha256=sha256(path))
            messages = 0
            try:
                for record in WhatsAppParser().parse(item, context):
                    if record.artifact_type == 'app_message':
                        messages += 1
                        counts[record.forensic.get('state', 'unverified')] += 1
            finally:
                context.clear_byte_cache()
            checked.append({'sha256': item.sha256, 'messages': messages, 'integrity': 'ok'})
        except Exception as exc:
            check(report, 'database_validation', 'fail', 'A database failed integrity, size or message parsing checks', error_type=type(exc).__name__)
    check(report, 'readable_messages', 'pass' if sum(counts.values()) else 'blocked',
          'The production WhatsApp parser read actual message records' if counts else 'No readable WhatsApp message records were recovered from these selected inputs',
          messages=sum(counts.values()), states=dict(counts), databases=checked,
          deleted_recovery_guaranteed=False)
    unchanged = all(p.exists() and sha256(p) == hashes[str(p)] for p in inputs)
    check(report, 'input_integrity', 'pass' if unchanged else 'fail', 'Acquired input hashes compared after parsing', files_checked=len(inputs))
    return finish(report)


def test_pattern():
    from PIL import Image, ImageDraw, ImageFont
    image = Image.new('RGB', (1100, 420), 'white')
    try:
        font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 60)
    except OSError:
        font = ImageFont.load_default(size=60)
    draw = ImageDraw.Draw(image)
    draw.text((55, 65), 'POLARON LIVE GPU TEST', fill='black', font=font)
    draw.text((55, 200), MARKER, fill='black', font=font)
    output = io.BytesIO()
    image.save(output, format='PNG')
    return image, output.getvalue()


def marker_present(text):
    return MARKER in re.sub(r'[^A-Z0-9]', '', str(text).upper())


def loaded_vision_gpu(models, model):
    names = {model, model + ':latest'}
    return next((row for row in models if (row.get('name') in names or row.get('model') in names)
                 and int(row.get('size_vram') or 0) > 0), None)


def verify_gpu():
    report = new_report('real_cuda_ocr_and_ollama_vision')
    started = time.monotonic()
    try:
        from app.services.job_locks import gpu_heavy_slot
        from app.services.gpu_thermal import get_gpu_stats
        from app.services import ocr_gpu
        from app.services.forensic_media_review import check_model, describe_frame, visual_model
        from app.services.model_router import _ollama_get, _ollama_post, ollama_unload_all_models
        import torch
        if not torch.cuda.is_available() or not torch.version.cuda:
            check(report, 'cuda_execution', 'blocked', 'This worker has no usable CUDA device; CPU fallback cannot pass')
            return finish(report)
        with gpu_heavy_slot('live_acceptance', wait_sec=15, fail_closed=True), ExitStack() as cleanup:
            stats = get_gpu_stats()
            if stats.hot or stats.temperature_c is not None and stats.temperature_c >= stats.pause_threshold_c:
                check(report, 'gpu_temperature', 'blocked', 'GPU is above the existing pipeline pause threshold')
                return finish(report)
            check(report, 'gpu_lease', 'pass', 'The production local and host-wide GPU permits were acquired')
            device = torch.cuda.current_device()
            matrix = torch.ones((128, 128), device='cuda', dtype=torch.float32)
            result = matrix @ matrix
            torch.cuda.synchronize()
            correct = bool(torch.allclose(result, torch.full_like(result, 128)))
            check(report, 'cuda_execution', 'pass' if correct else 'fail', 'A real CUDA matrix calculation was checked',
                  gpu_name=torch.cuda.get_device_name(device), torch_version=torch.__version__, cuda_version=torch.version.cuda)
            del result, matrix
            torch.cuda.empty_cache()
            image, picture = test_pattern()
            cleanup.callback(ocr_gpu.unload_glm_ocr)
            ollama_unload_all_models()
            try:
                text, _confidence = ocr_gpu._glm_ocr_image(image, prompt='Text Recognition:')
                cuda_model = str(getattr(ocr_gpu._glm_model, 'device', '')).startswith('cuda')
                correct = cuda_model and marker_present(text)
                check(report, 'cuda_ocr', 'pass' if correct else 'fail',
                      'The production OCR model read a known marker on CUDA' if correct else 'OCR did not verify the marker on a CUDA model',
                      expected_marker=MARKER, marker_matched=marker_present(text), model_on_cuda=cuda_model)
            finally:
                ocr_gpu.unload_glm_ocr()
                torch.cuda.empty_cache()
            model = visual_model()
            check_model()
            cleanup.callback(lambda: _ollama_post('/api/generate', {'model': model, 'prompt': '', 'keep_alive': 0}, timeout=30))
            description = describe_frame(picture)
            models = _ollama_get('/api/ps', timeout=15).get('models') or []
            resident = loaded_vision_gpu(models, model)
            correct = resident is not None and marker_present(description['description'])
            check(report, 'gpu_vision', 'pass' if correct else 'fail',
                  'The configured vision model described the known marker with GPU residency' if correct else
                  'Vision did not verify both the marker and GPU residency; a CPU response cannot pass',
                  model=model, marker_matched=marker_present(description['description']),
                  size_vram=int((resident or {}).get('size_vram') or 0),
                  test_picture_sha256=hashlib.sha256(picture).hexdigest(), synthetic_test_only=True)
            # Check before releasing admission, so another job cannot reload the
            # same model and make this owner's release appear to have failed.
            cleanup.close()
            loaded = _ollama_get('/api/ps', timeout=15).get('models') or []
            unloaded = not any(row.get('name') in {model, model+':latest'} or row.get('model') in {model, model+':latest'} for row in loaded)
            check(report, 'model_release', 'pass' if unloaded else 'fail', 'Vision model residency checked after cleanup')
    except Exception as exc:
        check(report, 'gpu_runtime', 'blocked',
              'Live GPU/Redis/model verification could not finish; inspect the local worker/model logs', error_type=type(exc).__name__)
    report['elapsed_seconds'] = round(time.monotonic()-started, 2)
    return finish(report)
