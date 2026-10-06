"""Stub scan findings for unconfigured scanner engines (dev / acceptance tests)."""

from __future__ import annotations

from typing import Any


def stub_scan_vulnerabilities(*, credentialed: bool = False, custom_checks: list[dict] | None = None) -> list[dict[str, Any]]:
    vulns: list[dict[str, Any]] = [
        {
            "plugin_id": "GVM-LOG4SHELL",
            "plugin_family": "General",
            "cve": "CVE-2021-44228",
            "score": 10.0,
            "severity": "critical",
            "plugin_name": "Apache Log4j Remote Code Execution (Log4Shell)",
            "solution": "Upgrade Log4j to 2.17.1 or later; apply vendor mitigations.",
            "port": 443,
            "protocol": "tcp",
            "service": "https",
        },
        {
            "plugin_id": "GVM-SSH-001",
            "plugin_family": "General",
            "cve": "CVE-2020-15778",
            "score": 7.8,
            "severity": "high",
            "plugin_name": "OpenSSH scp Command Injection",
            "solution": "Upgrade OpenSSH to a patched release.",
            "port": 22,
            "protocol": "tcp",
            "service": "ssh",
        },
    ]
    if credentialed:
        vulns.append(
            {
                "plugin_id": "GVM-PKG-001",
                "plugin_family": "Policy",
                "cve": None,
                "score": 5.5,
                "severity": "medium",
                "plugin_name": "Outdated package: openssl (credentialed)",
                "solution": "Apply security updates via package manager.",
            }
        )
    for chk in custom_checks or []:
        vulns.append(
            {
                "plugin_id": f"CUSTOM-{str(chk.get('id', 'check'))[:8]}",
                "plugin_family": "Custom",
                "cve": chk.get("cve_hint"),
                "score": 6.0,
                "severity": chk.get("severity_hint") or "medium",
                "plugin_name": chk.get("name") or "Custom check",
                "solution": "Review custom detection content.",
                "pci_requirement_tag": chk.get("pci_requirement_tag"),
            }
        )
    return vulns
