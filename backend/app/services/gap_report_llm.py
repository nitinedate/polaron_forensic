"""Ollama enrichment for Gap Assessment findings — Lilavati-style plain language."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from app.config import get_settings
from app.services.model_router import generate_text

log = logging.getLogger("gap_report_llm")

_CHUNK_SIZE = 8

_SYSTEM_PROMPT = """You write Gap Assessment report content for Aetheris Technologies clients
(hospitals, enterprises). Use simple English a non-technical client can understand.
Write like a professional security assessment report — never paste scanner labels or stub text.

Observation: 2-3 sentences on what was found during testing (like a Lilavati gap report).
Impact: 2-3 sentences on business/security consequences if exploited (see example Impact lines).
Description: 3-4 sentences explaining the technical gap for the detailed finding section.
Mitigation: 2-4 sentences in simple, non-technical English for a business reader. Explain what the client should do in clear steps. Do NOT use jargon such as TLS, SSL, CVE, cipher, port numbers, header names, or vendor product codes.
Recommendation: 2-3 sentences of clear, actionable guidance in plain language (combine the main fix steps; suitable for section 8 of the report).

Do not mention "stub", Nuclei, Trivy, Wazuh, ZAP, Nmap, or internal tooling.
Return ONLY valid JSON — no markdown fences, no commentary."""

_EXAMPLE_BLOCK = """
Example style (follow tone and length, not necessarily the same vulnerabilities):

Finding: Microsoft RDP RCE (CVE-2019-0708) (BlueKeep)
Observation: The system is vulnerable to BlueKeep (CVE-2019-0708), a serious flaw in Microsoft Remote Desktop (RDP). An attacker can exploit this weakness without login credentials to gain control of the system.
Impact: Successful exploitation can lead to complete system takeover, malware or ransomware spread, or use of the system to attack other systems on the network.
Description: BlueKeep is a critical weakness in Remote Desktop on certain Windows systems. It lets an attacker run harmful code without a password by sending specially crafted requests.
Mitigation: Arrange for your IT team to install the official security update on all affected computers as soon as possible. If remote access is not needed for daily work, turn it off or limit it to approved staff only. After the fix, confirm with a follow-up review that the weakness is no longer present.
Recommendation: Apply the official Microsoft security patch for BlueKeep on all affected systems immediately. Disable Remote Desktop where it is not required, enable Network Level Authentication, and restrict RDP (TCP 3389) to trusted networks only. Re-scan after patching to confirm the gap is closed.
"""


def _clean_scanner_text(text: str) -> str:
    t = (text or "").strip()
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"\(stub\)", "", t, flags=re.I)
    t = re.sub(r"\b(?:Nuclei|Trivy|Wazuh|ZAP|Nmap)\s+stub:\s*", "", t, flags=re.I)
    t = re.sub(r"\bstub:\s*", "", t, flags=re.I)
    t = re.sub(
        r"\b(?:rapid CVE/misconfiguration template match|container/Kubernetes image vulnerability|"
        r"continuous endpoint visibility finding|web application passive scan finding)\b",
        "",
        t,
        flags=re.I,
    )
    t = re.sub(r"\bNmap discovered open tcp/\d+\s*\([^)]+\)", "", t, flags=re.I)
    return t.strip(" .")


def _is_scanner_stub(text: str) -> bool:
    t = (text or "").strip().lower()
    if not t or len(t) < 20:
        return True
    stub_markers = (
        "stub",
        "nuclei",
        "trivy",
        "wazuh",
        "zap stub",
        "template match",
        "passive scan finding",
        "endpoint visibility finding",
        "nmap discovered open tcp/",
    )
    if any(m in t for m in stub_markers):
        return True
    if t.startswith("the system is affected by") and len(t) < 120:
        return True
    return False


def _split_bullets(text: str) -> list[str]:
    if not text:
        return []
    parts = re.split(r"[\n\r]+|(?<=[.!?])\s+(?=[A-Z])|;\s+", text.strip())
    items = [p.strip(" •\t-") for p in parts if p.strip()]
    return items[:8]


def _display_finding_name(name: str) -> str:
    return re.sub(r"\s*\(stub\)\s*", " ", name or "", flags=re.I).strip()


def _mitigation_is_detailed(text: str) -> bool:
    t = (text or "").strip()
    if len(t) < 100 or _is_scanner_stub(t):
        return False
    lower = t.lower()
    terse_markers = (
        "disable weak",
        "enforce tls",
        "tls 1.2",
        "tls 1.3",
        "set x-content",
        "nosniff",
        "tcp/",
        "cve-",
    )
    if len(t) < 140 and any(m in lower for m in terse_markers):
        return False
    return True


def _build_mitigation_text(name: str, risk: str, mitigation: list[str] | None = None) -> str:
    """Plain-language mitigation paragraph for the vulnerability observation table."""
    name = _display_finding_name(name)
    lower = name.lower()
    risk_label = (risk or "Medium").lower()

    if "ssl" in lower or "tls" in lower:
        return (
            f"Work with your IT team or service provider to update the affected system so it no longer "
            f"accepts outdated or unsafe ways of sending information over the network. Enable only modern, "
            f"trusted security settings supported by your vendor, and remove older options that attackers "
            f"can abuse. Because this issue is rated {risk_label} severity, complete the change promptly and "
            f"ask for a follow-up review to confirm the weakness has been fully resolved."
        )
    if "container" in lower or ("cve" in lower and "image" in lower):
        return (
            f"Ask your IT or cloud team to rebuild and redeploy the affected application using an updated, "
            f"supported version that includes the latest security fixes. Replace any outdated components "
            f"before putting the service back into regular use. After deployment, verify that the updated "
            f"version is running on all affected systems."
        )
    if "header" in lower or "content-type" in lower:
        return (
            f"Request your website or application administrator to adjust the site settings so browsers "
            f"handle content in a safer way, following standard security guidance from your hosting or "
            f"development vendor. Test the site after the change to confirm the protection is active on "
            f"all relevant pages."
        )
    if "open port" in lower or "tcpwrapped" in lower or "tcp/" in lower:
        return (
            f"Review whether the identified network service needs to remain open to the internet or to "
            f"other untrusted networks. If it is not required for business use, restrict access using your "
            f"firewall or network controls. If the service is required, ensure it is properly secured, "
            f"monitored, and kept up to date."
        )
    if "outdated package" in lower or "package" in lower:
        return (
            f"Plan with your IT team to update the outdated software on the affected systems using your "
            f"normal patch or maintenance process. Apply the required updates during an approved maintenance "
            f"window and confirm that the new version is installed successfully."
        )
    if "snmp" in lower:
        return (
            f"Change default or weak community settings on the affected devices and limit management access "
            f"to trusted administrators only. Review device configuration with your network team and confirm "
            f"that sensitive system information is no longer exposed."
        )

    steps = [str(s).strip().rstrip(".") for s in (mitigation or []) if str(s).strip()][:3]
    if steps:
        actions = ", ".join(steps[:-1]) + (f", and {steps[-1]}" if len(steps) > 1 else steps[0])
        return (
            f"Assign an owner to review {name} on the affected systems and plan corrective action because "
            f"it is rated {risk_label} severity. Work with your IT or vendor support team to {actions.lower() if actions[0].isupper() else actions}. "
            f"After the fix is applied, perform a follow-up check to confirm the issue is no longer present."
        )

    return (
        f"Assign an owner to review this finding on the affected systems and plan corrective action based "
        f"on its {risk_label} severity. Work with your IT or vendor support team to apply the recommended "
        f"security fixes or configuration changes. After remediation, perform a follow-up check to confirm "
        f"the issue is no longer present."
    )


def _build_recommendation_text(name: str, risk: str, mitigation: list[str]) -> str:
    """Plain-language recommendation paragraph for section 8 and finding details."""
    name = _display_finding_name(name)
    steps = [str(s).strip().rstrip(".") for s in mitigation if str(s).strip()][:4]
    if len(steps) >= 2:
        actions = ", ".join(steps[:-1]) + f", and {steps[-1]}"
    elif steps:
        actions = steps[0]
    else:
        actions = "review affected systems, apply the required security fixes, and verify closure with a follow-up scan"

    lower = name.lower()
    if "ssl" in lower or "tls" in lower:
        return (
            f"To address {name}, disable weak protocols and enforce TLS 1.2 or higher on all affected services. "
            f"{actions.capitalize() if actions[0].islower() else actions}. "
            f"Prioritise this work because the finding is rated {risk} severity."
        )
    if "header" in lower or "content-type" in lower:
        return (
            f"Configure the application or web server to send the recommended security response headers for {name}. "
            f"{actions.capitalize() if actions and actions[0].islower() else actions}. "
            "Test the change and confirm the header is present on all relevant pages."
        )
    if "container" in lower or "cve" in lower:
        return (
            f"Rebuild and redeploy affected container images with an updated, patched base image to resolve {name}. "
            f"{actions.capitalize() if actions and actions[0].islower() else actions}. "
            "Scan images again before production deployment."
        )
    if "outdated" in lower or "package" in lower:
        return (
            f"Update outdated software packages on the affected endpoints to remediate {name}. "
            f"{actions.capitalize() if actions and actions[0].islower() else actions}. "
            "Use your endpoint or patch management process and confirm updates are applied successfully."
        )

    return (
        f"To reduce risk from {name}, {actions}. "
        f"Complete remediation based on its {risk} severity rating and verify the gap is closed with a follow-up scan."
    )


def _recommendation_is_detailed(text: str) -> bool:
    t = (text or "").strip()
    return len(t) >= 80 and not _is_scanner_stub(t)


def _fallback_enrich(finding: dict[str, Any]) -> dict[str, Any]:
    name = _display_finding_name(finding.get("name") or "Finding")
    risk = finding.get("risk") or "Medium"
    raw_desc = _clean_scanner_text(finding.get("description") or finding.get("observation") or "")
    raw_rem = _clean_scanner_text(finding.get("remediation") or "")

    observation = raw_desc
    if _is_scanner_stub(observation):
        observation = (
            f"During the assessment, {name} was identified on the in-scope systems. "
            f"This issue is rated {risk} severity and should be reviewed and corrected promptly."
        )
    elif not observation.lower().startswith(("the ", "a ", "an ", "this ", "during ")):
        observation = f"The system is affected by {name}. {observation}"

    nvt_impact = _clean_scanner_text(str(finding.get("nvt_impact") or ""))
    impact = nvt_impact if len(nvt_impact) >= 40 and not _is_scanner_stub(nvt_impact) else (
        f"The presence of {name} ({risk} severity) increases the risk of unauthorized access, "
        f"data exposure, or service disruption if exploited by a malicious actor."
    )
    if not nvt_impact:
        if risk.lower() == "critical":
            impact = (
                f"If exploited, {name} could allow an attacker to take control of affected systems, "
                "spread malware, or move deeper into the network."
            )
        elif "openssl" in name.lower() or "ssl" in name.lower() or "tls" in name.lower():
            impact = (
                f"Use of weak or outdated SSL/TLS settings related to {name} may allow attackers to "
                "intercept encrypted communications or decrypt sensitive data over time."
            )
        elif "snmp" in name.lower():
            impact = (
                f"The default or weak SNMP configuration described by {name} can expose system and "
                "network details to unauthorized users, aiding further attacks."
            )
        elif "header" in name.lower() or "content-type" in name.lower():
            impact = (
                f"Missing security headers such as those noted in {name} increase the risk of "
                "browser-based attacks, content sniffing, and unauthorized data exposure."
            )

    description = raw_desc if not _is_scanner_stub(raw_desc) else ""
    if not description:
        description = (
            f"{name} is a {risk.lower()}-severity security gap identified during the assessment. "
            "It should be remediated to protect systems, applications, and sensitive data from exploitation."
        )
    if len(description) < 80:
        description = (
            f"{description} This weakness was confirmed on in-scope hosts and requires corrective "
            "action as part of the organization's security improvement plan."
        )

    mitigation = _split_bullets(raw_rem)
    if not mitigation:
        mitigation = [
            "Review affected systems and confirm the issue.",
            "Apply vendor patches or configuration changes as recommended.",
            "Re-scan after remediation to verify the gap is closed.",
        ]
    if len(raw_rem) >= 60 and not _is_scanner_stub(raw_rem):
        mitigation_paragraph = raw_rem
    else:
        mitigation_paragraph = _build_mitigation_text(name, risk, mitigation)

    rec_core = mitigation[0] if mitigation else "Review and remediate this gap as a priority."
    recommendation = _build_recommendation_text(name, risk, mitigation if mitigation else [rec_core])

    return {
        **finding,
        "client_observation": observation,
        "client_impact": impact,
        "client_description": description,
        "client_mitigation": mitigation[:6],
        "client_mitigation_paragraph": mitigation_paragraph,
        "client_recommendation": recommendation,
    }


def _extract_json_array(text: str) -> list[dict[str, Any]] | None:
    raw = (text or "").strip()
    if not raw:
        return None
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", raw)
    if fence:
        raw = fence.group(1).strip()
    start = raw.find("[")
    end = raw.rfind("]")
    if start >= 0 and end > start:
        raw = raw[start : end + 1]
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else None
    except json.JSONDecodeError:
        return None


def _build_prompt(findings: list[dict[str, Any]], *, client: str) -> str:
    payload = []
    for f in findings:
        payload.append(
            {
                "name": f.get("name"),
                "risk": f.get("risk"),
                "hosts": f.get("hosts") or [],
                "raw_description": _clean_scanner_text(f.get("description") or ""),
                "raw_remediation": _clean_scanner_text(f.get("remediation") or ""),
            }
        )
    return (
        f"Client: {client}\n"
        f"{_EXAMPLE_BLOCK}\n"
        "Rewrite each finding below for sections Observation, Impact, Description, Mitigation (2-4 plain-language sentences as one string), "
        "and Recommendation (2-3 plain-language sentences with actionable steps).\n"
        "Return a JSON array with one object per finding. Each object MUST include the exact 'name' field "
        "from the input.\n\n"
        f"Findings:\n{json.dumps(payload, indent=2)}"
    )


def _merge_llm_row(finding: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    mit = row.get("mitigation")
    mit_para = ""
    mit_list: list[str] = []
    if isinstance(mit, str):
        mit_para = _clean_scanner_text(mit)
        mit_list = _split_bullets(mit_para)
    elif isinstance(mit, list):
        mit_list = [str(m).strip() for m in mit if str(m).strip()]
        mit_para = " ".join(mit_list)

    obs = _clean_scanner_text(str(row.get("observation") or ""))
    impact = _clean_scanner_text(str(row.get("impact") or ""))
    desc = _clean_scanner_text(str(row.get("description") or ""))
    rec = _clean_scanner_text(str(row.get("recommendation") or ""))

    out = dict(finding)
    if obs:
        out["client_observation"] = obs
    if impact:
        out["client_impact"] = impact
    if desc:
        out["client_description"] = desc
    if mit_list:
        out["client_mitigation"] = mit_list[:8]
    if mit_para and _mitigation_is_detailed(mit_para):
        out["client_mitigation_paragraph"] = mit_para
    if rec:
        out["client_recommendation"] = rec

    fallback = _fallback_enrich(out)
    for key in (
        "client_observation",
        "client_impact",
        "client_description",
        "client_mitigation",
    ):
        if not out.get(key):
            out[key] = fallback[key]
    if not _mitigation_is_detailed(str(out.get("client_mitigation_paragraph") or "")):
        out["client_mitigation_paragraph"] = fallback["client_mitigation_paragraph"]
    mit = out.get("client_mitigation") or fallback.get("client_mitigation") or []
    if not _recommendation_is_detailed(str(out.get("client_recommendation") or "")):
        out["client_recommendation"] = _build_recommendation_text(
            _display_finding_name(out.get("name") or finding.get("name") or "Finding"),
            out.get("risk") or finding.get("risk") or "Medium",
            mit if isinstance(mit, list) else [],
        )
    elif not out.get("client_recommendation"):
        out["client_recommendation"] = fallback["client_recommendation"]
    return out


def _enrich_chunk(findings: list[dict[str, Any]], *, client: str, model: str) -> list[dict[str, Any]]:
    if not findings:
        return []
    prompt = _build_prompt(findings, client=client)
    try:
        raw = generate_text(prompt, model=model, system=_SYSTEM_PROMPT, temperature=0.15)
    except Exception as exc:
        log.warning("Gap report LLM chunk failed: %s", exc)
        return [_fallback_enrich(f) for f in findings]

    if raw.startswith("[Model ") and "unavailable" in raw:
        return [_fallback_enrich(f) for f in findings]

    rows = _extract_json_array(raw)
    if not rows:
        log.warning("Gap report LLM returned unparseable JSON; using fallback text")
        return [_fallback_enrich(f) for f in findings]

    by_name = {str(r.get("name", "")).strip().lower(): r for r in rows if r.get("name")}
    out: list[dict[str, Any]] = []
    for f in findings:
        key = (f.get("name") or "").strip().lower()
        row = by_name.get(key)
        out.append(_merge_llm_row(f, row) if row else _fallback_enrich(f))
    return out


def enrich_gap_findings(
    findings: list[dict[str, Any]],
    *,
    client: str = "Client",
    enabled: bool | None = None,
) -> list[dict[str, Any]]:
    """Rewrite scanner findings into client-friendly Lilavati-style prose via Ollama."""
    if not findings:
        return []

    settings = get_settings()
    use_llm = settings.gap_report_llm_enabled if enabled is None else enabled
    if not use_llm:
        return [_fallback_enrich(f) for f in findings]

    model = settings.gap_report_llm_model or settings.llm_fast_model
    enriched: list[dict[str, Any]] = []
    for i in range(0, len(findings), _CHUNK_SIZE):
        chunk = findings[i : i + _CHUNK_SIZE]
        enriched.extend(_enrich_chunk(chunk, client=client, model=model))
    return enriched
