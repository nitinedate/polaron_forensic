"""Versioned guide policy and evidence-based service routing (no active probes)."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any
from uuid import UUID

CATALOG_PATH = Path(__file__).with_name("service_catalog.json")
MODES = {"full", "fast", "common", "vuln", "nessus", "nexus"}
UDP_MODES = {"priority", "full", "off"}
SNAPSHOT_FIELDS = {
    "ssh_credential_port",
    "policy_version",
    "port_profile",
    "udp_profile",
    "port_range",
    "requested_port_range",
    "tcp_port_count",
    "udp_port_count",
    "service_count",
    "udp_baseline",
    "udp_extensions",
    "custom_tcp_ports",
    "custom_udp_ports",
    "gmp_credential_refs",
    "credential_status",
    "targets",
    "task_id",
    "config_id",
    "scanner_id",
    "scan_config_name",
    "preferences",
    "preference_status",
    "nvt_count",
    "started_at",
    "snapshot_status",
    "reason",
    "feed_versions",
    "configuration_sha256",
    "network_scoped_methods",
    "rule_engine",
}
PREFERENCE_FIELDS = {
    "max_checks",
    "max_hosts",
    "checks_read_timeout",
    "timeout_retry",
    "open_sock_max_attempts",
    "optimize_test",
    "safe_checks",
    "plugins_timeout",
    "scanner_plugins_timeout",
    "expand_vhosts",
    "test_empty_vhost",
    "report_host_details",
}


def clip_policy_snapshots(raw: Any, targets: list[str]) -> dict[str, Any]:
    """Keep only small, source-task policies whose entire host list is assigned."""
    import ipaddress

    def canonical(host: Any) -> str:
        try:
            return str(ipaddress.ip_address(str(host).strip()))
        except ValueError:
            return str(host).strip().lower()

    allowed = {canonical(h) for h in targets}
    out = {}
    if not isinstance(raw, dict):
        return out
    for task_id, policy in list(raw.items())[:4096]:
        if not isinstance(policy, dict) or len(str(task_id)) > 128:
            continue
        hosts = policy.get("targets")
        if (
            not isinstance(hosts, list)
            or not hosts
            or not {canonical(h) for h in hosts} <= allowed
        ):
            continue
        item = {k: v for k, v in policy.items() if k in SNAPSHOT_FIELDS}
        item["task_id"] = str(task_id)
        for key in ("gmp_credential_refs", "credential_status"):
            item[key] = (
                {
                    k: str(v)[:200]
                    for k, v in (item.get(key) or {}).items()
                    if k in {"ssh", "smb", "snmp", "esxi"}
                }
                if isinstance(item.get(key), dict)
                else {}
            )
        item["preferences"] = (
            {
                k: str(v)[:100]
                for k, v in (item.get("preferences") or {}).items()
                if k in PREFERENCE_FIELDS
            }
            if isinstance(item.get("preferences"), dict)
            else {}
        )
        item["feed_versions"] = (
            {
                str(k)[:40]: str(v)[:100]
                for k, v in list((item.get("feed_versions") or {}).items())[:12]
            }
            if isinstance(item.get("feed_versions"), dict)
            else {}
        )
        try:
            encoded = json.dumps(item, allow_nan=False)
        except (TypeError, ValueError):
            continue
        if len(encoded) <= 32000:
            out[str(task_id)] = item
    return out


@lru_cache(maxsize=1)
def service_catalog() -> dict[str, Any]:
    doc = json.loads(CATALOG_PATH.read_text())
    if len(doc["services"]) != 52 or [s["id"] for s in doc["services"]] != list(
        range(1, 53)
    ):
        raise ValueError("Invalid 52-service catalog")
    return doc


def port_numbers(value: Any) -> list[int]:
    if value is None or value == "":
        return []
    tokens = value if isinstance(value, list) else str(value).split(",")
    ports: set[int] = set()
    for raw in tokens:
        if isinstance(raw, bool):
            raise ValueError("Boolean is not a port")
        token = str(raw).strip()
        if not re.fullmatch(r"\d{1,5}(?:-\d{1,5})?", token):
            raise ValueError("Port must be a number or ascending range")
        parts = token.split("-")
        lo = int(parts[0])
        hi = int(parts[-1])
        if not 1 <= lo <= hi <= 65535:
            raise ValueError("Port outside 1-65535 or reversed range")
        ports.update(range(lo, hi + 1))
    return sorted(ports)


def validate_request(settings: dict[str, Any] | None) -> dict[str, Any]:
    raw = settings or {}
    if not isinstance(raw, dict):
        raise ValueError("Scan settings must be an object")
    out: dict[str, Any] = {}
    for key, allowed in (("port_profile", MODES), ("udp_profile", UDP_MODES)):
        value = raw.get(key, raw.get("mode") if key == "port_profile" else None)
        if value is not None:
            value = str(value).strip().lower()
            if value not in allowed:
                raise ValueError(f"Invalid {key}")
            out[key] = value
    for key in ("custom_tcp_ports", "custom_udp_ports"):
        if raw.get(key) is not None:
            out[key] = port_numbers(raw[key])
            if len(out[key]) > 4096:
                raise ValueError(
                    "Custom scope exceeds 4096 ports; use the Full profile for an exhaustive scan"
                )
    if raw.get("ssh_credential_port") is not None:
        ports = port_numbers(raw["ssh_credential_port"])
        if len(ports) != 1:
            raise ValueError("SSH credential port must be a single port")
        out["ssh_credential_port"] = ports[0]
    refs = raw.get("gmp_credential_refs")
    if refs is not None:
        if not isinstance(refs, dict):
            raise ValueError("GMP credential references must be an object")
        out["gmp_credential_refs"] = {}
        for kind, value in refs.items():
            if kind not in {"ssh", "smb", "snmp", "esxi"}:
                raise ValueError("Unsupported GMP credential kind")
            out["gmp_credential_refs"][kind] = str(UUID(str(value)))
    # No passwords, account tokens, URLs or arbitrary scanner preferences cross this contract.
    return out


def format_ports(ports: list[int], transport: str) -> str:
    values = sorted(set(ports))
    groups = []
    for port in values:
        if groups and port == groups[-1][1] + 1:
            groups[-1][1] = port
        else:
            groups.append([port, port])
    return ",".join(
        f"{transport}:{a}" if a == b else f"{transport}:{a}-{b}" for a, b in groups
    )


def effective_policy(
    request: dict[str, Any] | None = None,
    *,
    port_profile: str | None = None,
    udp_profile: str | None = None,
    catalog_tcp: list[int] | None = None,
    catalog_udp: list[int] | None = None,
) -> dict[str, Any]:
    doc = service_catalog()
    req = validate_request(request)
    mode = req.get(
        "port_profile", port_profile or os.environ.get("PORT_PROFILE") or "full"
    )
    mode = str(mode).strip().lower()
    if mode not in MODES:
        raise ValueError("Invalid effective PORT_PROFILE")
    udp = req.get(
        "udp_profile", udp_profile or os.environ.get("UDP_PROFILE") or "priority"
    )
    udp = str(udp).strip().lower()
    udp = (
        "off"
        if udp in {"none", "disabled", "false", "0"}
        else "full"
        if udp in {"all", "1-65535"}
        else udp
    )
    if udp not in UDP_MODES:
        raise ValueError("Invalid effective UDP_PROFILE")
    baseline_tcp = sorted({p for s in doc["services"] for p in s["tcp_hints"]})
    extra_tcp = (
        req["custom_tcp_ports"]
        if "custom_tcp_ports" in req
        else port_numbers(os.environ.get("SCAN_TCP_CUSTOM_PORTS"))
    )
    extra_udp = (
        req["custom_udp_ports"]
        if "custom_udp_ports" in req
        else port_numbers(os.environ.get("SCAN_UDP_CUSTOM_PORTS"))
    )
    # Legacy UDP_PORT_RANGE adds ports; it must not erase the agreed baseline.
    legacy_udp = (
        str(os.environ.get("UDP_PORT_RANGE") or "").replace("U:", "").replace("u:", "")
    )
    extra_udp = sorted(set(extra_udp + port_numbers(legacy_udp)))
    tcp = (
        list(range(1, 65536))
        if mode == "full"
        else sorted(set(baseline_tcp + (catalog_tcp or []) + extra_tcp))
    )
    udp_ports = (
        list(range(1, 65536))
        if udp == "full"
        else []
        if udp == "off"
        else sorted(
            set(
                doc["udp_baseline"]
                + doc["udp_extensions"]
                + (catalog_udp or [])
                + extra_udp
            )
        )
    )
    spec = ",".join(
        s for s in (format_ports(tcp, "T"), format_ports(udp_ports, "U")) if s
    )
    policy = {
        "policy_version": doc["policy_version"],
        "port_profile": mode,
        "udp_profile": udp,
        "port_range": spec,
        "tcp_port_count": len(tcp),
        "udp_port_count": len(udp_ports),
        "service_count": 52,
        "udp_baseline": doc["udp_baseline"],
        "udp_extensions": doc["udp_extensions"],
        "custom_tcp_ports": extra_tcp,
        "custom_udp_ports": extra_udp,
        "gmp_credential_refs": req.get("gmp_credential_refs", {}),
        "ssh_credential_port": req.get("ssh_credential_port", 22),
        "network_scoped_methods": "DHCP/SSDP/mDNS are not implemented as a standalone network collector",
        "rule_engine": "OpenVAS native feed; per-rule success requires report evidence",
    }
    policy["configuration_sha256"] = hashlib.sha256(
        json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return policy


def matches_service(service: dict[str, Any], endpoint: dict[str, Any]) -> bool:
    """Match explicit protocol/product context; a port number alone never routes a product."""
    protocol = (
        str(endpoint.get("service") or endpoint.get("detected_protocol") or "")
        .strip()
        .lower()
    )
    product = " ".join(str(endpoint.get(k) or "") for k in ("product", "cpe")).lower()
    return protocol in service["protocols"] or any(
        p in product for p in service["product_patterns"]
    )


def evaluate_ip_forwarding(
    evidence: dict[str, Any] | None, *, expected_forwarding: bool | None = None
) -> dict[str, Any]:
    """Evaluate supplied/native authenticated configuration; this function does not collect it."""
    base = {"rule_id": "CFG-IP-FORWARDING", "rule_version": "1", "status": "not-tested"}
    if not evidence or not evidence.get("source_ref"):
        return {**base, "reason": "No source-backed IPv4/IPv6 configuration evidence"}
    values = [evidence.get("ipv4"), evidence.get("ipv6")]
    if any(type(v) not in (int, bool) or v not in (0, 1) for v in values):
        return {**base, "reason": "Both IPv4 and IPv6 forwarding states are required"}
    if not evidence.get("authenticated"):
        return {**base, "reason": "Authenticated host configuration is not established"}
    if not isinstance(expected_forwarding, bool):
        return {
            **base,
            "reason": "Device-role forwarding policy is unknown",
            "source_ref": evidence["source_ref"],
        }
    enabled = any(bool(v) for v in values)
    unexpected = enabled and expected_forwarding is False
    return {
        **base,
        "status": "finding" if unexpected else "passed",
        "forwarding_enabled": enabled,
        "expected_forwarding": expected_forwarding,
        "source_ref": evidence["source_ref"],
        "reason": "Unexpected forwarding against supplied device-role policy"
        if unexpected
        else "Observed forwarding is permitted by supplied role policy",
    }


def analyze_services(
    vulnerabilities: list[dict[str, Any]],
    *,
    host: str,
    coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Describe actual native engine evidence; lack of a finding is never a per-rule pass."""
    doc = service_catalog()
    import ipaddress

    def canonical(value: Any) -> str:
        raw = str(value or "").strip().casefold()
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            return raw

    rows = [r for r in vulnerabilities if canonical(r.get("host")) == canonical(host)]
    endpoints: dict[tuple[int, str], dict[str, Any]] = {}
    for row in rows:
        port = row.get("port")
        transport = str(row.get("protocol") or "").lower()
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
            or transport not in {"tcp", "udp"}
        ):
            continue
        key = (port, transport)
        item = endpoints.setdefault(
            key,
            {
                "ip": host,
                "port": port,
                "transport": transport,
                "source_result_ids": [],
                "service": None,
                "product": None,
                "cpe": None,
                "version": None,
                "confidence": "port_hint_only",
            },
        )
        for field in ("service", "product", "cpe", "version"):
            if row.get(field):
                item[field] = str(row[field])[:1000]
        rid = row.get("source_result_id") or row.get("result_id")
        if rid and str(rid) not in item["source_result_ids"]:
            item["source_result_ids"].append(str(rid))
        if item["service"] or item["product"] or item["cpe"]:
            item["confidence"] = "native_engine_context"
    for transport, keyname in (("tcp", "open_tcp_ports"), ("udp", "open_udp_ports")):
        for raw in (coverage or {}).get(keyname) or []:
            try:
                port = int(raw)
            except (ValueError, TypeError):
                continue
            if 1 <= port <= 65535:
                endpoints.setdefault(
                    (port, transport),
                    {
                        "ip": host,
                        "port": port,
                        "transport": transport,
                        "source_result_ids": [],
                        "service": None,
                        "product": None,
                        "cpe": None,
                        "version": None,
                        "confidence": "port_hint_only",
                    },
                )
    services = []
    for svc in doc["services"]:
        observed = [r for r in endpoints.values() if matches_service(svc, r)]
        referenced = []
        findings = []
        for row in rows:
            title = str(row.get("plugin_name") or "").lower()
            if matches_service(svc, row) or any(
                pattern in title for pattern in svc["product_patterns"]
            ):
                rid = str(
                    row.get("source_result_id")
                    or row.get("result_id")
                    or row.get("plugin_id")
                    or ""
                )
                if rid:
                    referenced.append(rid)
                try:
                    score = float(row.get("cvss", row.get("score", 0)) or 0)
                except (ValueError, TypeError):
                    score = 0
                if math.isfinite(score) and score > 0 and rid:
                    findings.append(rid)
        status = (
            "finding"
            if findings
            else "observation"
            if observed or referenced
            else "not-tested"
        )
        reason = (
            "Native report references; no independent per-check pass inferred"
            if status != "not-tested"
            else "No verified protocol/product or matching native check evidence in this report"
        )
        if svc["scope"] == "network" and not referenced and not observed:
            status = "unsupported"
            reason = (
                "No DHCP network-scoped collector is implemented by the per-IP agent"
            )
        services.append(
            {
                "service_id": svc["key"],
                "name": svc["name"],
                "engine_family": svc["engine_family"],
                "status": status,
                "reason": reason,
                "endpoint_count": len(observed),
                "source_result_ids": sorted(set(referenced)),
                "finding_result_ids": sorted(set(findings)),
                "credentialed_checks": "not-tested; authentication/privilege evidence is required",
            }
        )
    totals = {
        state: sum(s["status"] == state for s in services)
        for state in ("finding", "observation", "not-tested", "unsupported")
    }
    return {
        "policy_version": doc["policy_version"],
        "host": host,
        "services": services,
        "counts": totals,
        "endpoints": sorted(
            endpoints.values(), key=lambda x: (x["transport"], x["port"])
        ),
        "ip_forwarding": evaluate_ip_forwarding(None),
        "coverage_complete": False,
        "limitation": "Per-service rule pass/credential/network coverage is not proven by an OpenVAS Done state",
    }
