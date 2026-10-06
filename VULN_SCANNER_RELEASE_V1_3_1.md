# Vulnerability Scanner Release v1.3.1

This release closes the four high-priority scanner integration gaps identified during the Polaron + laptop-scanner review.

## Release blockers resolved

### 1. Canonical packaging source

`laptop-scanner/scanner-agent` is the only source used by `scripts/pack-laptop-scanner-zip.ps1`.
The legacy repo-root `scanner-agent` is never copied over the laptop package. Packaging validates the scheduler, per-IP audit, port discovery, and target-progress files before ZIP creation.

### 2. Fast configuration is consistent

Default laptop settings are now:

```env
PORT_PROFILE=fast
GVM_OPTIMIZE_TEST=yes
PORT_DISCOVERY_ENABLED=true
GVM_MAX_HOSTS=10
GVM_MAX_CHECKS=6
SCAN_TARGET_PARALLELISM=30
```

The generated OpenVAS configuration uses the same `GVM_*` values. Explicit `PORT_PROFILE=full` remains available when a true TCP 1-65535 assessment is required.

### 3. Client open-port discovery

The new `laptop-scanner/scanner-agent/agent/port_discovery.py` mirrors the central scanner optimization:

1. take the authorized host chunk;
2. probe the Fast candidate TCP set concurrently;
3. record open ports per host;
4. create a union of open ports for the chunk;
5. pass only that union to the Greenbone target;
6. if no candidate port answers, use `T:22,80,443,445,3389,8080` instead of dropping the host.

This reduces unnecessary OpenVAS connection/plugin work while retaining a deterministic fallback.

### 4. Per-IP target progress persistence

The client sends delta updates such as:

```json
{
  "target_progress": {
    "192.168.1.10": {
      "status": "in_progress",
      "progress_pct": 42,
      "activity": "OpenVAS running"
    }
  }
}
```

The backend validates that the IP belongs to the scan job and persists it under `vuln_scan_jobs.orchestration_json.target_progress`. The scan-details API then emits the stored rows consumed by the existing React per-IP table.

Supported user-facing states are **Waiting**, **In Progress**, **Completed**, and **Fail**.

## Important performance behavior

The default scheduler targets about 30 effective host slots using a small bounded Greenbone task pool. It does not start 30 independent Greenbone services. For example, a typical plan is three tasks with up to ten hosts each.

The 165-host/hour objective remains an SLO that must be benchmarked on the real client network because runtime depends on services, credentials, VT set, latency, scanner CPU/RAM/SSD, and network controls.
