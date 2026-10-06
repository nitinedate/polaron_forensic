"""Documented Aetheris contextual Risk Number; native Tenable VPR is separate."""
from __future__ import annotations
from typing import Any
from app.services.aetheris_severity import valid_score

MODEL_VERSION = "nessus-aligned-weighted-1"


def risk_band_from_number(number: float) -> str:
    score = valid_score(number, 100.0) or 0.0
    return "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low" if score > 0 else "info"


def score_finding(*, cvss: float | None, is_kev: bool = False,
                  external_exposure: str | None = None, asset_criticality: str | None = None,
                  days_open: int = 0, credentialed: bool = True, qod: float | None = None,
                  vpr_score: float | None = None, epss_score: float | None = None) -> dict[str, Any]:
    numeric = valid_score(cvss) or 0.0
    technical = numeric * 2.5
    vpr = valid_score(vpr_score)
    epss = valid_score(epss_score, 1.0)
    if vpr is not None:
        threat, threat_source = vpr * 2.0, "vpr"
    elif epss is not None:
        threat, threat_source = epss * 20.0, "epss"
    else:
        threat, threat_source = 0.0, "unavailable"
    known = 15.0 if is_kev else 0.0
    exposure = {"internet-facing": 15.0, "partner": 10.0, "internal": 5.0, "isolated": 1.0}.get(str(external_exposure or "internal").lower(), 5.0)
    impact = {"tier0": 15.0, "tier1": 12.0, "tier2": 8.0, "tier3": 4.0, "0": 15.0, "1": 12.0, "2": 8.0, "3": 4.0}.get(str(asset_criticality or "tier2").lower().replace(" ", ""), 8.0)
    age = min((valid_score(days_open, 1e12) or 0.0) / 30.0 * 5.0, 5.0)
    quality = valid_score(qod, 100.0)
    confidence = quality / 20.0 if quality is not None else 2.0 if credentialed else 0.0
    risk_scored = numeric > 0 or known > 0 or threat > 0
    total = max(0.0, min(technical + threat + known + exposure + impact + age + confidence, 100.0)) if risk_scored else 0.0
    return {"enterprise_risk_score": round(total, 2), "risk_band": risk_band_from_number(total),
            "risk_factors_json": {"model_version": MODEL_VERSION, "risk_model_kind": "aetheris_contextual_not_tenable_vpr",
                "risk_scored": risk_scored, "technical": round(technical, 2), "threat": round(threat, 2),
                "threat_source": threat_source, "vpr_score": vpr, "epss_score": epss,
                "known_exploitation": known, "exposure": exposure, "impact": impact,
                "age": round(age, 2), "confidence": round(confidence, 2)}}
