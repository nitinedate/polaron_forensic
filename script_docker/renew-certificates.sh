#!/bin/sh
# Docker Compose joins this service to the gateway PID namespace, whose PID 1
# is the nginx master (docker-entrypoint.sh execs nginx).
# Existing ACME lineages and webroot paths are persisted in the certificate volume.
child_pid=""
trap 'if [ -n "$child_pid" ]; then kill -TERM "$child_pid" 2>/dev/null || true; wait "$child_pid" 2>/dev/null || true; fi; exit 0' TERM INT
while :; do
    certbot renew --non-interactive --quiet --no-random-sleep-on-renew \
        --deploy-hook 'kill -HUP 1' &
    child_pid=$!
    if wait "$child_pid"; then
        echo "Certificate renewal check completed. Nginx reloads only after a renewal."
    else
        echo "Certificate renewal failed; existing certificates remain in use. Check public TCP 80 and certbot-renewer logs." >&2
    fi
    child_pid=""
    sleep 21600 &
    child_pid=$!
    wait "$child_pid"
    child_pid=""
done
