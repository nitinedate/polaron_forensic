#!/usr/bin/env bash
set -euo pipefail
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
docker compose -f "$COMPOSE_FILE" exec -T worker-disk \
  pytest -q \
    tests/test_source_media.py \
    tests/test_disk_performance_v41.py \
    tests/test_extract_parallel_plan.py \
    tests/test_extract_stream_reader.py
