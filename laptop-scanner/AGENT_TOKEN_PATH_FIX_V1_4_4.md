# Aetheris Laptop Scanner v1.4.4 - AGENT token host-path fix

## Symptom

`Start-Laptop.cmd` reaches the central server and binds the scanner, then fails with:

`Access to the path '...\scanner-agent\.agent-token' is denied.`

## Root cause

Older Docker Compose runs can create `scanner-agent/.agent-token` as a **directory** when the host file does not exist before a short-syntax bind mount is created. PowerShell then cannot write the returned agent token because the path is a directory.

## Fix

- Detect and repair a directory at `scanner-agent/.agent-token`.
- Remove only the `scanner-agent` container before changing that bind source; no volumes are deleted.
- Preserve the old directory as a timestamped backup instead of deleting it.
- Create/probe a writable token file before writing the returned secret.
- Use Compose long bind syntax with `create_host_path: false` so Docker cannot silently create a directory again.
- Ship a zero-byte `.agent-token` placeholder in the full package.

The fix does not delete Greenbone feeds, gvmd data, scan results, `.env`, or LAN fingerprint data.
