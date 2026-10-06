#!/usr/bin/env sh
# Fallback only — prefer Persistent Edge (HTTPS agent) or Managed Remote / VPN
# (tls://site-vpn-host:9390). Use this when the site cannot expose GMP on the VPN.
#
# Run on the SITE host after OpenVAS GMP is listening on 127.0.0.1:9390.
# Forwards site GMP to a premise jump host so worker-nessus can use:
#   tls://<jump-host>:9390
#
# Usage:
#   ./scripts/onsite_openvas_reverse_tunnel.sh user@premise-jump.example.com
set -eu
JUMP="${1:?usage: $0 user@premise-jump-host}"
LOCAL_GMP_PORT="${LOCAL_GMP_PORT:-9390}"
REMOTE_LISTEN_PORT="${REMOTE_LISTEN_PORT:-9390}"

echo "Fallback reverse-tunnel: premise ${REMOTE_LISTEN_PORT} -> site 127.0.0.1:${LOCAL_GMP_PORT}"
echo "Register scanner as Managed Remote / VPN with URL tls://<jump-or-docker-host>:${REMOTE_LISTEN_PORT}"
exec ssh -N -R "0.0.0.0:${REMOTE_LISTEN_PORT}:127.0.0.1:${LOCAL_GMP_PORT}" "$JUMP"
