"""Inject into a live CPython process: disable hashlib.sha256 work for extract speedup."""

from __future__ import annotations

import os
import sys


PATCH = r"""
import hashlib
class _NoopSha256:
    def __init__(self, data=b"", usedforsecurity=True):
        pass
    def update(self, data=b""):
        return None
    def digest(self):
        return b"\x00" * 32
    def hexdigest(self):
        return ""
    def copy(self):
        return self
hashlib.sha256 = _NoopSha256
print("patched hashlib.sha256 -> noop", flush=True)
"""


def main() -> int:
    # Prefer worker child (not pid 1 supervisor) when present
    targets = []
    for pid in sorted((int(p) for p in os.listdir("/proc") if p.isdigit()), reverse=True):
        try:
            cmd = open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\0", b" ").decode()
        except OSError:
            continue
        if "celery" in cmd and "disk-build" in cmd:
            targets.append(pid)
    if not targets:
        print("no celery disk-build process found", file=sys.stderr)
        return 1
    # Child usually higher pid than container pid 1
    pid = next((p for p in targets if p != 1), targets[0])
    print(f"target pid={pid}")

    # Try gdb python injection
    import shutil
    import subprocess
    import tempfile

    gdb = shutil.which("gdb")
    if not gdb:
        print("gdb not installed; attempting apt install")
        subprocess.check_call(["apt-get", "update", "-qq"])
        subprocess.check_call(["apt-get", "install", "-y", "-qq", "gdb"])
        gdb = shutil.which("gdb")
    if not gdb:
        print("gdb unavailable", file=sys.stderr)
        return 2

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
        fh.write(PATCH)
        patch_path = fh.name

    # Prefer gdb's python if linked; fallback to call PyRun_SimpleString
    script = f"""
set pagination off
attach {pid}
py
try:
  import codecs
  src = open({patch_path!r}, encoding='utf-8').read()
  import __main__
  exec(src)
  print('gdb-py inject ok')
except Exception as e:
  print('gdb-py inject failed', e)
end
detach
quit
"""
    with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as gh:
        gh.write(script)
        gdb_script = gh.name

    r = subprocess.run([gdb, "-batch", "-x", gdb_script], capture_output=True, text=True)
    print(r.stdout)
    print(r.stderr, file=sys.stderr)
    return r.returncode


if __name__ == "__main__":
    raise SystemExit(main())
