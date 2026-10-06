"""Lint: Windows PowerShell 5.1 turns redirected native stderr (2>&1) into terminating
errors when $ErrorActionPreference = "Stop". In scripts that set Stop, every 2>&1 on a
native command must sit inside a block that lowers the preference (Invoke-NativeCapture
or an explicit save/restore). Also flags non-ASCII characters inside .ps1 files, which
mis-decode under CP-1252 (an em dash's 0x94 byte becomes a closing quote).
Usage: python diagnostics/lint_ps1_native_stderr.py scripts/*.ps1 script_docker/*.ps1
"""
import re, sys

bad = 0
for path in sys.argv[1:]:
    text = open(path, encoding="utf-8", errors="replace").read()
    lines = text.splitlines()
    sets_stop = re.search(r'\$ErrorActionPreference\s*=\s*"Stop"', text) is not None
    for i, line in enumerate(lines, 1):
        if line.strip().startswith("#"):
            continue  # comments never reach the parser as code
        if re.search(r"[^\x00-\x7f]", line):
            print(f"{path}:{i}: non-ASCII character in .ps1 (CP-1252 decode hazard): {line.strip()[:80]}")
            bad += 1
        if "2>&1" in line and sets_stop:
            # allowed only when the surrounding 12 lines lower the preference
            window = "\n".join(lines[max(0, i - 12):i])
            if 'ErrorActionPreference = "Continue"' not in window and 'ErrorActionPreference = "SilentlyContinue"' not in window:
                print(f"{path}:{i}: 2>&1 on a native command under ErrorActionPreference=Stop: {line.strip()[:90]}")
                bad += 1
print("lint:", "FAIL" if bad else "OK", f"({len(sys.argv)-1} files)")
sys.exit(1 if bad else 0)
