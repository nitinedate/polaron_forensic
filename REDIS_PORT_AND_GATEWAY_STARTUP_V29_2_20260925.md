# Redis port + Enterprise Console startup fix V29.2 — 2026-09-25

## Root cause
`docker compose up -d frontend` targets the legacy root frontend. Because that service depends on the root API, Compose also starts its Redis/Postgres/MinIO/Ollama/etc. If another Aetheris stack already owns host Redis port 6380, Docker fails with `Bind for 0.0.0.0:6380 failed: port is already allocated`.

The main unified Enterprise Console is the `gateway` service in `services/gateway/docker-compose.yml` and does not depend on Redis/Postgres.

## Correct UI rebuild
Run:

```powershell
.\scripts\rebuild-ui.ps1 -NoCache
```

Equivalent Docker commands:

```powershell
docker compose --project-directory . --project-name aetheris-gateway -f services/gateway/docker-compose.yml build --no-cache gateway
docker compose --project-directory . --project-name aetheris-gateway -f services/gateway/docker-compose.yml up -d --no-deps gateway
```

## Redis host port
The main/Forensic Redis publication is now configurable:

```env
REDIS_HOST_PORT=6380
```

Compose uses:

```yaml
127.0.0.1:${REDIS_HOST_PORT:-6380}:6379
```

Container-to-container Redis always remains `redis://redis:6379/0`.

If 6380 is occupied, run:

```powershell
.\scripts\select-free-redis-port.ps1
```

The script performs a real TCP bind test and writes the first available port into `.env`. It excludes Aetheris-reserved Redis ports 6381, 6382, 6389, 6391, and 6392.

## Diagnose the owner of 6380

```powershell
Get-NetTCPConnection -LocalPort 6380 -State Listen -ErrorAction SilentlyContinue |
  Select-Object LocalAddress,LocalPort,OwningProcess

docker ps --format "table {{.Names}}\t{{.Ports}}" | Select-String "6380"
```

Do not stop an existing Aetheris Redis just to rebuild the UI. Rebuild `gateway` instead.
