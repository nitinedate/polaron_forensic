# OpenVAS target port-selection fix

## Symptom

`gvmd` rejected target creation with:

`Response Error 400. One of PORT_LIST and PORT_RANGE are required`

## Root cause

`backend/app/services/greenbone_gmp.py` called `gmp.create_target()` with only
`name` and `hosts`. GMP requires every target to include either a `port_list_id`
or an explicit `port_range`.

## Fix

The Greenbone adapter now:

1. Resolves the requested scan configuration before creating the target.
2. Looks for a feed-provided `All IANA assigned TCP` port list first.
3. Falls back to `All TCP and Nmap top 100 UDP` if that is the available preferred list.
4. If no preferred feed port list is available yet, supplies the explicit fallback `T:1-65535`.
5. Never sends `create_target()` without a port selection.
6. Extends scanner preflight with a Greenbone scan-readiness check showing the selected port policy.

## Rebuild

From the project directory:

```powershell
docker compose build worker-nessus
docker compose up -d worker-nessus
docker compose exec worker-nessus python /scripts/scanner_preflight.py
```

The preflight should now include `PASS Greenbone scan readiness` and either a
`port_list_id` or `port_range: T:1-65535`.
