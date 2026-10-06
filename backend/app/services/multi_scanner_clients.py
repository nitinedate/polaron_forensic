"""Auxiliary vulnerability scanner clients.

Real scanner results are returned with ``stub=False``.  Stub data remains
available for unit/demo paths, but production orchestration rejects it unless
VULN_ALLOW_STUB_FINDINGS=true is explicitly set.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urlencode, urlparse
from urllib.request import urlopen

from app.config import get_settings

log = logging.getLogger("multi_scanner")


def _severity_label(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _web_candidates(target: str) -> list[str]:
    target = (target or "").strip()
    if not target:
        return []
    if target.startswith(("http://", "https://")):
        return [target]
    # HTTP first for local/internal assets, then HTTPS. ZAP will reject an
    # unreachable candidate and we continue with the other scheme.
    return [f"http://{target}", f"https://{target}"]


def _split_targets(targets: str) -> list[str]:
    return [t.strip() for t in (targets or "").split(",") if t.strip()]


def _first_target(targets: str) -> str:
    parts = _split_targets(targets)
    return parts[0] if parts else ""


def _is_container_image(target: str) -> bool:
    """True for image refs; false for IPs, host:port, and bare hostnames."""
    t = (target or "").strip()
    if not t:
        return False
    if t.startswith("sha256:") or "/" in t:
        return True
    if t.count(":") == 1:
        host, rest = t.rsplit(":", 1)
        if rest.isdigit():
            return False
        try:
            ipaddress.ip_address(host)
            return False
        except ValueError:
            return True
    try:
        ipaddress.ip_address(t)
        return False
    except ValueError:
        return False


class BaseAuxScanner:
    engine: str = "unknown"

    @property
    def configured(self) -> bool:
        return False

    def run_scan(self, *, targets: str, name: str) -> dict[str, Any]:
        return {
            "stub": True,
            "info": {"status": "completed", "engine": self.engine},
            "vulnerabilities": self._stub_vulnerabilities(targets),
            "message": f"{self.engine} live scanner is unavailable; returned test/stub data",
        }

    def _stub_vulnerabilities(self, targets: str) -> list[dict[str, Any]]:
        return []

    def server_status(self) -> dict[str, Any]:
        return {"status": "stub", "engine": self.engine, "message": f"{self.engine} stub mode"}


class NmapScanner(BaseAuxScanner):
    engine = "nmap"

    @property
    def configured(self) -> bool:
        return bool(shutil.which("nmap"))

    def run_scan(self, *, targets: str, name: str) -> dict[str, Any]:
        if not self.configured:
            return super().run_scan(targets=targets, name=name)
        hosts = _split_targets(targets)
        if not hosts:
            return super().run_scan(targets=targets, name=name)
        timeout = min(240, 40 + 25 * len(hosts))
        try:
            proc = subprocess.run(
                [
                    "nmap",
                    "-sV",
                    "-T4",
                    "--top-ports",
                    "200",
                    "--open",
                    "--max-retries",
                    "1",
                    "-oX",
                    "-",
                    *hosts,
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if proc.returncode != 0:
                log.warning("nmap exit %s: %s", proc.returncode, proc.stderr[:500])
                return super().run_scan(targets=targets, name=name)
            vulns = self._parse_nmap_xml(proc.stdout, hosts[0])
            return {"stub": False, "info": {"status": "completed", "engine": self.engine}, "vulnerabilities": vulns}
        except Exception as exc:
            log.warning("nmap scan failed: %s", exc)
            return super().run_scan(targets=targets, name=name)

    def _parse_nmap_xml(self, xml_text: str, fallback_host: str) -> list[dict[str, Any]]:
        import xml.etree.ElementTree as ET

        vulns: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return vulns
        host_nodes = root.findall("host")
        if not host_nodes:
            host_nodes = root.findall(".//host")
        if not host_nodes:
            for port in root.findall(".//port"):
                self._append_nmap_port(vulns, port, fallback_host)
            return vulns
        for host_el in host_nodes:
            addr_el = host_el.find("address")
            host_ip = (addr_el.get("addr") if addr_el is not None else None) or fallback_host
            for port in host_el.findall(".//port"):
                self._append_nmap_port(vulns, port, host_ip)
        return vulns

    @staticmethod
    def _append_nmap_port(vulns: list[dict[str, Any]], port: Any, host: str) -> None:
        state = port.find("state")
        if state is not None and state.get("state") != "open":
            return
        portid = port.get("portid")
        proto = port.get("protocol") or "tcp"
        svc = port.find("service")
        svc_name = svc.get("name") if svc is not None else ""
        product = svc.get("product") if svc is not None else ""
        version = svc.get("version") if svc is not None else ""
        banner = " ".join(x for x in (product, version) if x).strip()
        vulns.append(
            {
                "plugin_id": f"NMAP-{portid}-{proto}",
                "plugin_family": "Discovery",
                "plugin_name": f"Open port {portid}/{proto} — {svc_name or 'service'}",
                "description": f"Nmap discovered open {proto}/{portid}" + (f" ({banner})" if banner else ""),
                "synopsis": banner or f"{svc_name} on {portid}/{proto}",
                "solution": "Review exposed service; restrict access if not required.",
                "score": 3.0,
                "severity": "low",
                "port": int(portid) if portid and portid.isdigit() else None,
                "protocol": proto,
                "service": svc_name,
                "host": host,
            }
        )

    def _stub_vulnerabilities(self, targets: str) -> list[dict[str, Any]]:
        host = _first_target(targets) or "127.0.0.1"
        return [
            {
                "plugin_id": "NMAP-DISC-001",
                "plugin_family": "Discovery",
                "plugin_name": f"Host discovery — {host}",
                "description": f"Nmap stub: host {host} is reachable with common ports open.",
                "synopsis": "Discovery and service fingerprint",
                "solution": "Validate asset inventory.",
                "score": 2.0,
                "severity": "info",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "host": host,
            }
        ]


class NucleiScanner(BaseAuxScanner):
    engine = "nuclei"

    @property
    def configured(self) -> bool:
        return bool(shutil.which("nuclei"))

    def run_scan(self, *, targets: str, name: str) -> dict[str, Any]:
        if not self.configured:
            return super().run_scan(targets=targets, name=name)
        hosts = _split_targets(targets)
        if not hosts:
            return super().run_scan(targets=targets, name=name)

        def _scan_host(host: str) -> tuple[list[dict[str, Any]], str]:
            last_error = ""
            for url in _web_candidates(host):
                try:
                    proc = subprocess.run(
                        ["nuclei", "-u", url, "-jsonl", "-silent", "-timeout", "8", "-c", "25"],
                        capture_output=True,
                        text=True,
                        timeout=180,
                        check=False,
                    )
                    if proc.returncode != 0:
                        last_error = (proc.stderr or "")[:500]
                        continue
                    vulns: list[dict[str, Any]] = []
                    for line in proc.stdout.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        sev = str(item.get("info", {}).get("severity") or "medium").lower()
                        score_map = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.0, "info": 0.0}
                        classification = item.get("info", {}).get("classification") or {}
                        cves = classification.get("cve-id")
                        if isinstance(cves, list):
                            cve = cves[0] if cves else None
                        else:
                            cve = cves
                        matched = item.get("matched-at") or url
                        vulns.append(
                            {
                                "plugin_id": item.get("template-id") or item.get("templateID") or "NUCLEI",
                                "plugin_family": "Nuclei",
                                "plugin_name": item.get("info", {}).get("name") or item.get("matcher-name") or "Nuclei finding",
                                "description": item.get("info", {}).get("description") or matched,
                                "synopsis": item.get("type") or "misconfiguration",
                                "solution": item.get("info", {}).get("remediation") or "Apply vendor guidance.",
                                "score": score_map.get(sev, 5.0),
                                "severity": sev,
                                "cve": cve,
                                "host": urlparse(matched).hostname or host,
                            }
                        )
                    return vulns, ""
                except Exception as exc:
                    last_error = str(exc)
            return [], last_error

        workers = min(4, max(1, len(hosts)))
        try:
            from app.services.vuln_capacity import vuln_target_workers

            workers = min(vuln_target_workers(), max(1, len(hosts)))
        except Exception:
            pass
        all_vulns: list[dict[str, Any]] = []
        errors: list[str] = []
        if workers <= 1:
            results = [_scan_host(h) for h in hosts]
        else:
            results = []
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futs = [pool.submit(_scan_host, h) for h in hosts]
                for fut in as_completed(futs):
                    results.append(fut.result())
        for vulns, err in results:
            all_vulns.extend(vulns)
            if err:
                errors.append(err)
        if errors:
            log.warning("nuclei scan failed: %s", "; ".join(errors)[:500])
        if all_vulns or not errors:
            return {"stub": False, "info": {"status": "completed", "engine": self.engine}, "vulnerabilities": all_vulns}
        return super().run_scan(targets=targets, name=name)

    def _stub_vulnerabilities(self, targets: str) -> list[dict[str, Any]]:
        host = _first_target(targets) or "127.0.0.1"
        return [
            {
                "plugin_id": "NUCLEI-CVE-CHECK",
                "plugin_family": "Nuclei",
                "plugin_name": "SSL/TLS weak protocol (stub)",
                "description": "Nuclei stub: rapid CVE/misconfiguration template match.",
                "synopsis": "Misconfiguration detected",
                "solution": "Disable weak TLS; enforce TLS 1.2+.",
                "score": 9.0,
                "severity": "critical",
                "cve": "CVE-2014-3566",
                "port": 443,
                "protocol": "tcp",
                "host": host,
            }
        ]


class ZapScanner(BaseAuxScanner):
    engine = "zap"

    @property
    def configured(self) -> bool:
        return bool(get_settings().zap_api_url)

    @staticmethod
    def _api_json(base: str, path: str, params: dict[str, Any], timeout: int = 30) -> dict[str, Any]:
        query = urlencode({k: v for k, v in params.items() if v is not None})
        url = f"{base.rstrip('/')}{path}?{query}"
        with urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def server_status(self) -> dict[str, Any]:
        settings = get_settings()
        if not settings.zap_api_url:
            return super().server_status()
        try:
            data = self._api_json(
                settings.zap_api_url,
                "/JSON/core/view/version/",
                {"apikey": settings.zap_api_key or ""},
                timeout=10,
            )
            return {"status": "ok", "engine": self.engine, "version": data.get("version")}
        except Exception as exc:
            return {"status": "error", "engine": self.engine, "error": str(exc)}

    def _scan_one_url(self, *, base: str, key: str, target: str, target_url: str, timeout_sec: int) -> list[dict[str, Any]]:
        start = self._api_json(
            base,
            "/JSON/spider/action/scan/",
            {"apikey": key, "url": target_url, "recurse": "true", "subtreeOnly": "true"},
            timeout=30,
        )
        scan_id = str(start.get("scan") or "")
        if not scan_id:
            raise RuntimeError(f"ZAP spider did not return scan id: {start}")

        deadline = time.monotonic() + timeout_sec
        while True:
            status_data = self._api_json(
                base,
                "/JSON/spider/view/status/",
                {"apikey": key, "scanId": scan_id},
                timeout=30,
            )
            try:
                progress = int(status_data.get("status") or 0)
            except (TypeError, ValueError):
                progress = 0
            if progress >= 100:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError(f"ZAP spider timed out after {timeout_sec}s for {target_url}")
            time.sleep(2)

        while True:
            pending = self._api_json(
                base,
                "/JSON/pscan/view/recordsToScan/",
                {"apikey": key},
                timeout=30,
            )
            try:
                remaining = int(pending.get("recordsToScan") or 0)
            except (TypeError, ValueError):
                remaining = 0
            if remaining <= 0 or time.monotonic() >= deadline:
                break
            time.sleep(2)

        alerts_data = self._api_json(
            base,
            "/JSON/core/view/alerts/",
            {"apikey": key, "baseurl": target_url, "start": 0, "count": 500},
            timeout=60,
        )
        vulns: list[dict[str, Any]] = []
        risk_to_score = {"High": 8.0, "Medium": 5.0, "Low": 2.5, "Informational": 0.0}
        for alert in alerts_data.get("alerts") or []:
            risk = str(alert.get("risk") or "Informational")
            score = risk_to_score.get(risk, 0.0)
            alert_url = str(alert.get("url") or target_url)
            parsed = urlparse(alert_url)
            port = parsed.port
            if port is None:
                port = 443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None
            vulns.append(
                {
                    "plugin_id": str(alert.get("pluginId") or alert.get("alertRef") or "ZAP"),
                    "plugin_family": "OWASP ZAP",
                    "plugin_name": alert.get("alert") or alert.get("name") or "ZAP alert",
                    "description": alert.get("description") or "",
                    "synopsis": alert.get("param") or alert.get("evidence") or "Web application finding",
                    "solution": alert.get("solution") or "Review OWASP ZAP guidance.",
                    "score": score,
                    "severity": _severity_label(score),
                    "port": port,
                    "protocol": "tcp",
                    "service": parsed.scheme or "http",
                    "host": parsed.hostname or target,
                    "cwe": alert.get("cweid"),
                    "reference": alert.get("reference"),
                }
            )
        return vulns

    def run_scan(self, *, targets: str, name: str) -> dict[str, Any]:
        settings = get_settings()
        if not settings.zap_api_url:
            return super().run_scan(targets=targets, name=name)

        base = settings.zap_api_url.rstrip("/")
        key = settings.zap_api_key or ""
        timeout_sec = max(0, int(getattr(settings, "zap_scan_timeout_sec", 180) or 0))
        if timeout_sec <= 0:
            timeout_sec = 180
        hosts = _split_targets(targets)
        errors: list[str] = []
        all_vulns: list[dict[str, Any]] = []

        for target in hosts:
            scanned = False
            for target_url in _web_candidates(target):
                try:
                    all_vulns.extend(
                        self._scan_one_url(
                            base=base,
                            key=key,
                            target=target,
                            target_url=target_url,
                            timeout_sec=timeout_sec,
                        )
                    )
                    scanned = True
                    break
                except Exception as exc:
                    errors.append(f"{target_url}: {exc}")
            if not scanned and not hosts:
                break

        if all_vulns or (hosts and not errors):
            return {
                "stub": False,
                "info": {"status": "completed", "engine": self.engine},
                "vulnerabilities": all_vulns,
                "message": "; ".join(errors)[:1000] if errors else None,
            }
        if errors:
            log.warning("zap scan failed: %s", "; ".join(errors)[:1000])
        result = super().run_scan(targets=targets, name=name)
        result["message"] = "; ".join(errors)[:1000] or result.get("message")
        return result

    def _stub_vulnerabilities(self, targets: str) -> list[dict[str, Any]]:
        host = _first_target(targets) or "127.0.0.1"
        return [
            {
                "plugin_id": "ZAP-10021",
                "plugin_family": "OWASP ZAP",
                "plugin_name": "X-Content-Type-Options Header Missing",
                "description": "ZAP stub: web application passive scan finding.",
                "synopsis": "Missing security header",
                "solution": "Set X-Content-Type-Options: nosniff.",
                "score": 4.0,
                "severity": "medium",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "host": host,
            }
        ]


class WazuhScanner(BaseAuxScanner):
    engine = "wazuh"

    @property
    def configured(self) -> bool:
        return bool(get_settings().wazuh_api_url)

    def run_scan(self, *, targets: str, name: str) -> dict[str, Any]:
        # Wazuh does not perform an on-demand network scan. Findings must be
        # queried for a known enrolled agent. The project currently has no
        # target->agent mapping, so do not pretend a live scan succeeded.
        result = super().run_scan(targets=targets, name=name)
        result["message"] = (
            "Wazuh requires an enrolled agent and target-to-agent mapping; "
            "live Wazuh vulnerability inventory is not configured for this target"
        )
        return result

    def _stub_vulnerabilities(self, targets: str) -> list[dict[str, Any]]:
        host = _first_target(targets) or "127.0.0.1"
        return [
            {
                "plugin_id": "WAZUH-VULN-001",
                "plugin_family": "Wazuh",
                "plugin_name": "Outdated package detected on endpoint",
                "description": "Wazuh stub: continuous endpoint visibility finding.",
                "synopsis": "Endpoint package vulnerability",
                "solution": "Patch via endpoint management.",
                "score": 6.5,
                "severity": "medium",
                "host": host,
            }
        ]


class TrivyScanner(BaseAuxScanner):
    engine = "trivy"

    @property
    def configured(self) -> bool:
        return bool(shutil.which("trivy"))

    def run_scan(self, *, targets: str, name: str) -> dict[str, Any]:
        settings = get_settings()
        image = _first_target(targets)
        if not _is_container_image(image):
            return {
                "stub": False,
                "info": {"status": "skipped", "engine": self.engine},
                "vulnerabilities": [],
                "message": f"trivy skipped host/IP target {image}",
            }
        if not shutil.which("trivy"):
            return super().run_scan(targets=targets, name=name)
        try:
            cmd = ["trivy", "image"]
            if settings.trivy_server_url:
                cmd += ["--server", settings.trivy_server_url.rstrip("/")]
            cmd += ["--format", "json", "--quiet", image]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=900,
                check=False,
            )
            if proc.returncode != 0:
                result = super().run_scan(targets=targets, name=name)
                result["message"] = f"trivy exited {proc.returncode}: {proc.stderr[:500]}"
                return result
            data = json.loads(proc.stdout or "{}")
            vulns: list[dict[str, Any]] = []
            for result_item in data.get("Results") or []:
                for v in result_item.get("Vulnerabilities") or []:
                    score = 0.0
                    cvss = v.get("CVSS") or {}
                    for source in ("nvd", "redhat", "ghsa"):
                        try:
                            score = float((cvss.get(source) or {}).get("V3Score") or 0)
                        except (TypeError, ValueError):
                            score = 0.0
                        if score:
                            break
                    severity = str(v.get("Severity") or "UNKNOWN").lower()
                    if severity == "unknown":
                        severity = _severity_label(score)
                    vulns.append(
                        {
                            "plugin_id": v.get("VulnerabilityID") or "TRIVY",
                            "plugin_family": "Trivy",
                            "plugin_name": v.get("Title") or v.get("VulnerabilityID") or "Trivy vulnerability",
                            "description": v.get("Description") or "",
                            "synopsis": v.get("PkgName") or "container vulnerability",
                            "solution": v.get("FixedVersion") or "Upgrade container image.",
                            "score": score,
                            "severity": severity,
                            "cve": v.get("VulnerabilityID"),
                            "host": image,
                        }
                    )
            return {"stub": False, "info": {"status": "completed", "engine": self.engine}, "vulnerabilities": vulns}
        except Exception as exc:
            log.warning("trivy scan failed: %s", exc)
            result = super().run_scan(targets=targets, name=name)
            result["message"] = str(exc)
            return result

    def _stub_vulnerabilities(self, targets: str) -> list[dict[str, Any]]:
        return [
            {
                "plugin_id": "TRIVY-CVE-2024",
                "plugin_family": "Trivy",
                "plugin_name": "Container image CVE (stub)",
                "description": "Trivy stub: container/Kubernetes image vulnerability.",
                "synopsis": "Outdated base image package",
                "solution": "Rebuild image with patched base.",
                "score": 7.0,
                "severity": "high",
                "cve": "CVE-2024-0001",
            }
        ]


AUX_SCANNERS: dict[str, type[BaseAuxScanner]] = {
    "nmap": NmapScanner,
    "nuclei": NucleiScanner,
    "zap": ZapScanner,
    "owasp_zap": ZapScanner,
    "wazuh": WazuhScanner,
    "trivy": TrivyScanner,
}


def get_aux_scanner(engine: str) -> BaseAuxScanner:
    cls = AUX_SCANNERS.get(engine.strip().lower())
    if not cls:
        raise ValueError(f"Unknown auxiliary engine: {engine}")
    return cls()
