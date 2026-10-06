# Aetheris Laptop Scanner v1.4.6 - Agent token runtime directory fix

## Problem fixed
Older scanner-agent containers can retain `/app/.agent-token` as a directory in the container writable layer. Even after the Windows host path is repaired into a file, Docker/OCI then fails with `not a directory` while mounting the file.

## v1.4.6 design
The scanner no longer bind-mounts an individual Windows token file. It bind-mounts the directory `scanner-agent/runtime` to `/run/aetheris-agent` and reads `/run/aetheris-agent/agent-token`.

This is a directory-to-directory bind and avoids Windows Docker Desktop / WSL file-vs-directory ambiguity.

Startup automatically detects a legacy scanner-agent container whose mounts include `/app/.agent-token`, removes only that scanner-agent container, and lets Compose recreate it with the new runtime directory mount. Greenbone containers and named volumes are not removed.

The bootstrap still stores `AGENT_TOKEN` in `.env` as before, and writes the same bound token to `scanner-agent/runtime/agent-token` for live reload/recovery.
