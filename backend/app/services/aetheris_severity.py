"""CVSS severity with an explicit version basis and retained source signals."""
from __future__ import annotations

import math
import os
from typing import Any

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_basis(value: str | None = None) -> str:
    raw = str(value or os.environ.get("VULN_SEVERITY_BASIS") or "cvss_v3").strip().lower()
    raw = raw.replace(".", "").replace(" ", "").replace("_", "")
    return "cvss_v2" if raw in {"cvssv2", "cvss2", "2", "cvssv20"} else "cvss_v4" if raw in {"cvssv4", "cvss4", "4", "cvssv40"} else "cvss_v3"


def valid_score(value: Any, maximum: float = 10.0) -> float | None:
    if value is None or isinstance(value, bool) or str(value).strip() == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) and 0 <= number <= maximum else None


def choose_cvss_score(row: dict[str, Any], basis: str | None = None) -> tuple[float, str, dict[str, float | None]]:
    aliases = {
        "cvss_v2": ("cvss_v2", "cvss2", "cvss_v2_base", "cvss2_base", "cvss2_base_score"),
        "cvss_v3": ("cvss_v3", "cvss3", "cvss_v3_base", "cvss3_base", "cvss3_base_score"),
        "cvss_v4": ("cvss_v4", "cvss4", "cvss_v4_base", "cvss4_base", "cvss4_base_score"),
    }
    candidates: dict[str, float | None] = {}
    for name, keys in aliases.items():
        values = [score for key in keys if (score := valid_score(row.get(key))) is not None]
        candidates[name] = max(values) if values else None
    for name in ("score", "cvss", "cvss_base", "greenbone_result_severity", "greenbone_nvt_cvss_base", "severity"):
        value = valid_score(row.get(name))
        if value is not None:
            candidates[name] = value
    signals = row.get("greenbone_score_signals")
    if isinstance(signals, dict):
        for name, raw in signals.items():
            value = valid_score(raw)
            if value is not None:
                candidates["greenbone." + str(name)] = value
    preferred = severity_basis(basis)
    for name in dict.fromkeys((preferred, "cvss_v3", "cvss_v2", "cvss_v4")):
        if candidates[name] is not None:
            return float(candidates[name]), name, candidates
    generic = {name: value for name, value in candidates.items() if value is not None}
    if generic:
        source = max(generic, key=lambda name: float(generic[name]))
        return float(generic[source]), source, candidates
    return 0.0, "unavailable", candidates


def severity_from_cvss(cvss: float, basis: str | None = None) -> str:
    score = valid_score(cvss) or 0.0
    if score >= (10.0 if severity_basis(basis) == "cvss_v2" else 9.0):
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "info"


def apply_policy_floors(synopsis: str, severity: str) -> tuple[str, None]:
    """Compatibility API: descriptions never override technical severity."""
    return severity, None


def classify_severity(*, cvss: float = 0.0, synopsis: str = "", raw_severity: Any = None,
                      basis: str | None = None) -> tuple[str, None]:
    return severity_from_cvss(cvss, basis), None


def aetheris_severity_sql(alias: str = "f") -> str:
    prefix = f"{alias}." if alias else ""
    basis = severity_basis()
    source = f"COALESCE({prefix}risk_factors_json->>'severity_basis', '{basis}')"
    return f"""CASE
  WHEN COALESCE({prefix}cvss, 0) >= CASE WHEN {source}='cvss_v2' THEN 10 ELSE 9 END THEN 'critical'
  WHEN COALESCE({prefix}cvss, 0) >= 7 THEN 'high'
  WHEN COALESCE({prefix}cvss, 0) >= 4 THEN 'medium'
  WHEN COALESCE({prefix}cvss, 0) > 0 THEN 'low'
  ELSE 'info'
END"""
