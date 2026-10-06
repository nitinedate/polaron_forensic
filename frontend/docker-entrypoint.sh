#!/bin/sh
set -e

# Do not block nginx on API health — uvicorn --reload can hang during shutdown and
# wget would wait forever, leaving :3000 with ERR_EMPTY_RESPONSE.
echo "[frontend] starting nginx (api readiness checked in background)..."

# When the api container is recreated it gets a new IP. Reload nginx so the
# static upstream re-resolves `api` (no per-request Docker DNS lookups).
watch_api_ip() {
    last_ip=""
    while true; do
        sleep 15
        if ! wget -q -T 5 -t 1 -O- http://api:8080/health >/dev/null 2>&1; then
            continue
        fi
        ip=$(getent ahostsv4 api 2>/dev/null | awk '{print $1; exit}')
        if [ -n "$ip" ] && [ "$ip" != "$last_ip" ]; then
            echo "[frontend] api resolved to $ip — reloading nginx"
            nginx -s reload 2>/dev/null || true
            last_ip="$ip"
        fi
    done
}

watch_api_ip &

exec "$@"
