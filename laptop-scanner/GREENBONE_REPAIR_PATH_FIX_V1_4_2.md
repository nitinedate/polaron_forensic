# Aetheris Laptop Scanner v1.4.2 - Greenbone repair path quoting fix

## Fixed failure

`Repair-Greenbone-Feed.cmd` previously passed `%~dp0` directly as a quoted `-Root` value. `%~dp0` ends with `\`, so Windows native argument parsing could deliver a malformed value such as:

`D:\laptop-scanner"`

PowerShell then failed at `Resolve-Path` with `Illegal characters in path`.

## Changes

1. `Repair-Greenbone-Feed.cmd` canonicalizes `%~dp0` with `for %%I in ("%ROOT%.") do set "ROOT=%%~fI"`, removing the trailing slash before the native PowerShell call.
2. `scripts/Repair-Greenbone-Feed-v1.4.1.ps1` defensively strips accidental surrounding quotes and trailing `\` or `/`, validates the directory with `Test-Path -LiteralPath`, then uses `Resolve-Path -LiteralPath`.
3. Added `Test-Greenbone-Repair-Install-v1.4.2.ps1` to validate the installation before the repair runs.
4. No Docker volumes, Greenbone feed data, `.env`, token, or scan results are deleted.
