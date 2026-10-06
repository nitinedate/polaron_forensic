# Aetheris Laptop Scanner v1.3.8 - PowerShell parser fix

## Fixed symptom

`Test-Windows-TLS-v1.3.7.ps1` could stop before making the HTTPS request with:

```
Variable reference is not valid. ':' was not followed by a valid variable name character.
```

The cause was PowerShell parsing `$Base:` inside a double-quoted error string as a scoped variable reference.

## Code fix

The two affected strings in `scripts/sync-agent-token.ps1` now delimit the variable explicitly:

```
CENTRAL_API_URL=${Base}: $detail
```

This is a parser-only fix. It does not change tokens, TLS validation, Greenbone volumes, scanner identity, or scan data.

## Apply to an existing installation

Copy the corrected `scripts/sync-agent-token.ps1` over the old file, or use the v1.3.8 hotfix package.

Then run:

```powershell
cd D:\laptop-scanner
powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-Windows-TLS-v1.3.8.ps1
```

If that succeeds, run:

```powershell
.\Start-Laptop.cmd
```
