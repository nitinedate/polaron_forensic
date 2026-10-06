#!/usr/bin/env python3
"""Host/container entry point for live acceptance; summaries contain no key/chat bytes."""
from __future__ import annotations
import argparse
import json
import os
import signal
import subprocess
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
if Path('/app/app').is_dir():
    sys.path.insert(0, '/app')

from app.services.live_acceptance import capture_phone, finish, verify_gpu, verify_whatsapp, write_report  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description='Actual Android, authenticated WhatsApp and CUDA/vision checks')
    parser.add_argument('--mode', choices=['phone', 'whatsapp', 'gpu'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--adb', default='adb')
    parser.add_argument('--serial', default='')
    parser.add_argument('--source', type=Path)
    parser.add_argument('--key', type=Path, action='append', default=[])
    parser.add_argument('--derived', type=Path)
    parser.add_argument('--timeout', type=int, default=600, help='GPU check process deadline in seconds')
    parser.add_argument('--check-child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.check_child:
        def interrupted(_signal, _frame):
            raise TimeoutError('Acceptance check deadline or owner cancellation')
        signal.signal(signal.SIGTERM, interrupted)
    try:
        if args.mode == 'phone':
            result = capture_phone(adb=args.adb, serial=args.serial, output=args.output.parent,
                                   source=args.source, keys=args.key)
        elif args.check_child and args.mode == 'whatsapp':
            from app.services.forensic_stage_worker import _guard_owner
            _guard_owner()
            if not args.source or not args.derived:
                parser.error('whatsapp mode requires --source and --derived')
            result = verify_whatsapp(args.source, args.derived)
        elif args.check_child:
            from app.services.forensic_stage_worker import _guard_owner
            _guard_owner()
            result = verify_gpu()
        else:
            from app.services.forensic_stage_worker import _stop_owned_process
            with tempfile.TemporaryDirectory(prefix='aetheris-live-gpu-') as temporary:
                child_output=Path(temporary)/'result.json'
                child_args=[sys.executable,str(Path(__file__).resolve()),'--mode',args.mode,'--check-child','--output',str(child_output)]
                if args.mode=='whatsapp':
                    if not args.source or not args.derived:
                        parser.error('whatsapp mode requires --source and --derived')
                    child_args.extend(['--source',str(args.source),'--derived',str(args.derived)])
                process=subprocess.Popen(child_args,start_new_session=os.name=='posix',
                    env={**os.environ,'AETHERIS_STAGE_OWNER_PID':str(os.getpid())},stdout=subprocess.DEVNULL)
                try:
                    process.wait(timeout=max(30,min(args.timeout,7200)))
                    if not child_output.is_file():
                        raise RuntimeError('Check process exited without an acceptance result')
                    result=json.loads(child_output.read_text(encoding='utf-8'))
                finally:
                    _stop_owned_process(process)
    except Exception as exc:
        result = {'scope': args.mode, 'checks': [{'name': 'execution', 'required': True,
                   'status': 'blocked', 'detail': 'Verification could not execute; source evidence is retained',
                   'evidence': {'error_type': type(exc).__name__}}]}
        finish(result)
    write_report(args.output, result)
    print(json.dumps({'mode': args.mode, 'status': result['status'], 'report': str(args.output)}))
    return 0 if result['status'] == 'passed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
