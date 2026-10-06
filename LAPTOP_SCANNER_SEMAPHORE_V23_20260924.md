# LaptopScanner adaptive IP semaphore - V23 (2026-09-24)

## Required behavior

- One scan job may contain 50+ IP addresses.
- One OpenVAS task is created per IP.
- Normal scan admission has a minimum of 5 concurrent IP permits.
- Auto mode scales to 10 concurrent IP tasks by default when the laptop is cool and has headroom.
- Warm/hot state falls back to 5 concurrent IPs.
- Critical thermal/RAM pressure pauses new admissions; already-running IP scans finish and release their permits.
- An unavailable IP or an error for one IP never fails or blocks the remaining IPs.
- When an IP finishes/errors, its permit is released immediately and the next pending IP starts.
- Port connection failures in the quick reachability stage are logged and the next probe port is tried. If every configured quick-probe port is unavailable, the IP is skipped before OpenVAS.

## Per-IP logs

Durable JSONL files are written to:

`laptop-scanner/logs/ip/<job-id>/<ip>.jsonl`

A combined job stream is written to:

`laptop-scanner/logs/ip/<job-id>/all-ips.jsonl`

The same `IP_EVENT` messages pass through the existing central scanner log shipper. Events include queued, port_unavailable, reachable/unreachable, start_attempt, started, resumed, progress, poll_error, scan_failed, completed, task/report ids, duration, result counts and plugin-error counts.

## Defaults

```env
MAX_CONCURRENT_SCAN_JOBS=1
SCAN_IP_PARALLELISM=auto
SCAN_IP_MAX_PARALLELISM=10
SKIP_UNREACHABLE_TARGETS=true
REACHABILITY_TIMEOUT_SEC=0.5
REACHABILITY_WORKERS=10
IP_SCAN_LOG_DIR=/app/logs/ip
GVM_MAX_HOSTS=10
SCAN_CPU_THROTTLE_C=84
SCAN_CPU_PAUSE_C=92
AGENT_VERSION=1.2.19
```

`MAX_CONCURRENT_SCAN_JOBS=1` is intentional: parallelism is inside a scan job, so a 50-IP case uses the shared 5-10 IP pool instead of running two independent jobs that compete for the same Greenbone/CPU resources.

## Forensic result completeness

The merge path no longer collapses Greenbone rows merely because plugin/host/port summaries match. Distinct rows inside a report are preserved. If resume/retry accidentally supplies the same Greenbone `report_id` twice, the duplicate report is skipped as a unit.
