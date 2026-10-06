"""Offline native-command migration tests; runnable without a Docker daemon."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

MOCK = r'''import json, os, pathlib, sys
args=sys.argv[1:]; case=os.environ['MIGRATION_CASE']; root=pathlib.Path(os.environ['MIGRATION_ROOT'])
with (root/'docker-calls.jsonl').open('a') as f:f.write(json.dumps(args)+'\n')
def fail(text,code=1):
 print(text,file=sys.stderr);sys.exit(code)
if args[0]=='ps':sys.exit(0)
if args[:2]==['volume','inspect']:
 if case=='daemon-fail':fail('Cannot connect to the Docker daemon')
 if case in ['legacy','copy-fail','cleanup-busy','images-fail'] and args[-1]=='aetheris-forensic_minio_data':
  print('{}');sys.exit(0)
 fail('Error response from daemon: get '+args[-1]+': no such volume')
if args[0]=='images':
 if case=='images-fail':fail('permission denied listing images')
 print('pgvector/pgvector:pg16');sys.exit(0)
if args[0]=='run':
 target=next(a[:-4] for a in args if a.endswith(':/to'))
 shutil=__import__('shutil'); shutil.copyfile(root/'legacy-evidence.bin',pathlib.Path(target)/'evidence.bin')
 if case=='copy-fail':fail('simulated copy failure',13)
 print('copy progress on stderr',file=sys.stderr);sys.exit(0)
if args[:2]==['volume','rm'] and case=='cleanup-busy':fail('volume is in use')
sys.exit(0)
'''


def run_checks(project: Path, powershell: str, output: Path):
    results=[]
    for case in ['fresh','daemon-fail','legacy','copy-fail','cleanup-busy','populated','images-fail']:
        root=output/case; (root/'scripts').mkdir(parents=True)
        for name in ['move-processing-data-to-backup.ps1','docker-engine-recovery.ps1']:
            shutil.copyfile(project/'scripts'/name,root/'scripts'/name)
        executable=root/'fake-bin';executable.mkdir()
        source=root/'legacy-evidence.bin';source.write_bytes(b'unchanged synthetic evidence\x00\xff')
        source_hash=hashlib.sha256(source.read_bytes()).hexdigest()
        if os.name=='nt':
            mock=executable/'mock-docker.py';mock.write_text(MOCK)
            (executable/'docker.cmd').write_text('@echo off\n"'+sys.executable+'" "'+str(mock)+'" %*\nexit /b %ERRORLEVEL%\n')
        else:
            mock=executable/'docker';mock.write_text('#!'+sys.executable+'\n'+MOCK);mock.chmod(0o700)
        backup=root/'backup'; (root/'.env').write_text('AETHERIS_BACKUP_DIR='+str(backup).replace('\\','/')+'\n')
        if case=='populated':
            (backup/'minio').mkdir(parents=True);(backup/'minio/user.bin').write_bytes(b'keep existing case data')
        env=os.environ.copy();env.update(PATH=str(executable)+os.pathsep+env.get('PATH',''),MIGRATION_CASE=case,MIGRATION_ROOT=str(root))
        call=subprocess.run([powershell,'-NoProfile','-File',str(root/'scripts/move-processing-data-to-backup.ps1')],env=env,capture_output=True,text=True,timeout=60)
        (root/'result.log').write_text(call.stdout+call.stderr)
        calls=[json.loads(s) for s in (root/'docker-calls.jsonl').read_text().splitlines()]
        ready=backup/'minio/.ready'
        failed=case in {'daemon-fail','copy-fail','images-fail'}
        assert (call.returncode!=0)==failed,(case,call.stdout,call.stderr)
        assert ready.exists()!=failed,(case,'ready marker')
        assert hashlib.sha256(source.read_bytes()).hexdigest()==source_hash
        if failed:
            assert not any(c[:2]==['volume','rm'] for c in calls)
            if case=='copy-fail':
                assert not (backup/'minio/evidence.bin').exists()
                assert list(backup.glob('minio.migrating-*'))
                # A retry must copy again rather than trust partial files.
                retry_env={**env,'MIGRATION_CASE':'legacy'}
                retry=subprocess.run([powershell,'-NoProfile','-File',str(root/'scripts/move-processing-data-to-backup.ps1')],env=retry_env,capture_output=True,text=True,timeout=60)
                assert retry.returncode==0,(retry.stdout,retry.stderr)
                assert ready.exists() and (backup/'minio/evidence.bin').read_bytes()==source.read_bytes()
                results.append({'case':'retry_after_failed_copy','status':'passed','expected_failure':False})
        if case=='fresh':
            assert not any(c[0] in {'run','images'} for c in calls)
            old_calls=len(calls)
            repeat=subprocess.run([powershell,'-NoProfile','-File',str(root/'scripts/move-processing-data-to-backup.ps1')],env=env,capture_output=True,text=True,timeout=60)
            assert repeat.returncode==0
            assert len((root/'docker-calls.jsonl').read_text().splitlines())==old_calls
        if case in {'legacy','cleanup-busy'}:
            assert (backup/'minio/evidence.bin').read_bytes()==source.read_bytes()
            assert not list(backup.glob('minio.migrating-*'))
        if case=='populated':
            assert (backup/'minio/user.bin').read_bytes()==b'keep existing case data'
            assert not any(c[:2]==['volume','inspect'] and c[-1]=='aetheris-forensic_minio_data' for c in calls)
        results.append({'case':case,'status':'passed','expected_failure':failed})
    report={'status':'passed','migration_scenarios':len(results),'cases':results,'docker':'offline native executable mock','native_windows_desktop':'not exercised'}
    (output/'migration-test-results.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--powershell',default=shutil.which('powershell.exe') or shutil.which('pwsh'))
    parser.add_argument('--out',type=Path)
    args=parser.parse_args()
    if not args.powershell:parser.error('Specify a PowerShell executable with --powershell')
    project=Path(__file__).resolve().parents[1]
    if args.out:
        assert not args.out.exists(),'Use a new output directory'
        args.out.mkdir(parents=True)
        report=run_checks(project,args.powershell,args.out.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix='aetheris-migration-test-') as work:
            report=run_checks(project,args.powershell,Path(work))
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
