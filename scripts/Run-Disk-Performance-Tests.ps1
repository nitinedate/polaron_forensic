param([string]$ComposeFile = "docker-compose.yml")
docker compose -f $ComposeFile exec -T worker-disk pytest -q `
  tests/test_source_media.py `
  tests/test_disk_performance_v41.py `
  tests/test_extract_parallel_plan.py `
  tests/test_extract_stream_reader.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
