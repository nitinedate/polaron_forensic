"""Plain-language rewrite for mobile forensic report findings (client-friendly).

Turns examiner/technical evidence into simple, detailed wording with:
- no file paths, database names, or tool jargon
- full sentences a non-technical reader can understand
- optional multi-model fallback (primary → rewrite pool → fast)
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.config import get_settings
from app.services.model_router import generate_text, list_models

log = logging.getLogger("mobile_report_llm")

_PATH_RE = re.compile(
    r"(?i)(?:[A-Za-z]:\\|\\\\|/)"
    r"(?:Users|home|data|private|var|AppDomain|Documents|Library|DCIM|"
    r"whatsapp|msgstore|databases|Trash|Recycle)[^\s\]\)\"']*"
)
_TECH_TOKEN_RE = re.compile(
    r"(?i)\b(?:msgstore\.db|wa\.db|chatstorage|sqlite|freelist|WAL|IndexedDB|"
    r"LevelDB|protobuf|SHA-?256|MD5|IMEI|JID|@s\.whatsapp\.net|"
    r"AXIOM|Magnet|UFED|Cellebrite|/data/data/|com\.whatsapp|"
    r"artifact_id|minio|parser|offset|hex)\b"
)
_EXT_PATHISH_RE = re.compile(
    r"(?i)(?:\bpath:\s*[^\n]+|\[[^\]]*(?:/|\\)[^\]]*\]|"
    r"`[^`]+`|"
    r"(?:file_path|source_path|storage_uri)\s*[:=]\s*\S+)"
)

MOBILE_PLAIN_LANGUAGE_SYSTEM = """You write mobile phone examination findings for everyday readers
(clients, managers, court readers who are not technical).

Rules you MUST follow:
1. Use simple, clear English in full sentences. Be detailed but easy to understand.
2. NEVER mention file paths, folder names, database names, app package names, hashes,
   IMEI, technical tool names, or internal system labels.
3. NEVER invent people, amounts, dates, or events that are not in the evidence summary.
4. Explain what was checked, what was found, and what it means in ordinary words.
5. Prefer phrases like "photos on the phone", "chat messages", "payment app screenshots",
   "voice notes", "deleted items that were recovered".
6. If something was not found, say so carefully (do not claim absolute certainty).
7. Return ONLY a markdown section starting with:
### 3. Observations
followed by hyphen bullets (- ...). No other headings."""

MOBILE_PLAIN_LANGUAGE_GUIDE = """
Write Observations for a mobile phone examination report.

REQUIRED STYLE:
- Short bullets a non-technical person can understand.
- Observations must follow the case Objective and the Procedure that was carried out.
- First 4–6 bullets: device integrity / safety style findings (rooting, unusual changes,
  malware/phishing in browsing, unusual background activity) — only when supported.
- Then detailed bullets about communications, photos, payment-related pictures,
  voice notes, deleted/recovered items, and other case-relevant evidence that answer the Objective.
- Use everyday words. Example: say "WhatsApp chats" not "msgstore.db rows".
- Say "payment app screenshots" not ".jpg under /WhatsApp/Media".
- Include approximate counts when the evidence summary provides them.
- Add 1–2 bullets that explain, in plain terms, why the findings matter for the case.
- Do not include any path, filename with folders, database name, or technical code.

BAD:
- path: /data/data/com.whatsapp/databases/msgstore.db
- Freelist carve recovered WAL residuals
- IndexedDB LevelDB YouTube API headers

GOOD:
- The phone’s WhatsApp chats were reviewed for conversations about money transfers.
- About 120 photos were reviewed. Some appear to be payment receipts and UPI transfer screens.
- A few voice notes were found that discuss money. In plain terms, this supports that
  payment-related conversations and pictures were stored on the phone.
""".strip()


def strip_technical_noise(text: str) -> str:
    """Remove paths and common forensic/tool tokens from text before/after LLM."""
    t = text or ""
    t = _EXT_PATHISH_RE.sub("", t)
    t = _PATH_RE.sub("", t)
    t = _TECH_TOKEN_RE.sub("", t)
    t = re.sub(r"[ \t]{2,}", " ", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()


def evidence_summary_for_llm(
    *,
    inventory: dict[str, int] | None,
    payment_hits: list[dict[str, str]] | None,
    rag_snippets: list[str] | None,
) -> str:
    """Build a path-free evidence brief the rewrite model can safely use."""
    parts: list[str] = []
    inv = inventory or {}
    if inv:
        friendly = {
            "pictures": "photos/images",
            "whatsapp_media": "WhatsApp media (photos/videos/audio)",
            "audio": "voice notes / audio files",
            "documents": "documents",
            "whatsapp_messages": "WhatsApp messages",
            "whatsapp_chats": "WhatsApp chats",
            "call_logs": "call history",
            "sms": "SMS / text messages",
            "installed_apps": "installed apps",
            "contacts": "contacts",
            "deleted_files": "deleted / recovered files",
            "deleted_photos": "deleted photos",
            "deleted_videos": "deleted videos",
            "critical_files": "deleted or unusual files",
            "telegram": "Telegram messages",
            "signal": "Signal messages",
            "browser": "internet browsing history",
        }
        lines = []
        for key, label in friendly.items():
            n = int(inv.get(key) or 0)
            if n > 0:
                lines.append(f"- {label}: about {n:,}")
        if lines:
            parts.append("Counts found on the phone (approximate):\n" + "\n".join(lines))

    pay_bits: list[str] = []
    for h in payment_hits or []:
        snippet = strip_technical_noise(str(h.get("content") or ""))
        if len(snippet) < 20:
            continue
        # Keep only readable content — never the path.
        pay_bits.append(f"- {snippet[:220]}")
        if len(pay_bits) >= 8:
            break
    if pay_bits:
        parts.append("Payment-related text seen in reviewed items:\n" + "\n".join(pay_bits))

    rag_bits: list[str] = []
    for snip in rag_snippets or []:
        clean = strip_technical_noise(snip)
        if len(clean) < 30:
            continue
        rag_bits.append(f"- {clean[:280]}")
        if len(rag_bits) >= 8:
            break
    if rag_bits:
        parts.append("Other readable evidence notes:\n" + "\n".join(rag_bits))

    return "\n\n".join(parts).strip()


def _configured_model_pool() -> list[str]:
    settings = get_settings()
    pool: list[str] = []
    for name in (
        getattr(settings, "mobile_report_llm_model", None),
        settings.llm_primary_model,
        getattr(settings, "mobile_report_llm_fallback_model", None),
        settings.gap_report_llm_model,
        "llama3.1:8b",
        "qwen2.5:7b",
        settings.llm_fast_model,
        "qwen3.5:9b",
    ):
        n = (name or "").strip()
        if n and n not in pool:
            pool.append(n)
    # Extra models listed for mobile narrative (comma-separated).
    extra = (getattr(settings, "mobile_report_llm_models", "") or "").strip()
    for part in extra.split(","):
        n = part.strip()
        if n and n not in pool:
            pool.append(n)
    return pool


def resolve_mobile_report_model() -> str:
    """Pick the best available model for plain-language mobile findings."""
    settings = get_settings()
    preferred = (getattr(settings, "mobile_report_llm_model", None) or settings.llm_primary_model).strip()
    available = list_models()
    pool = _configured_model_pool()
    if not available:
        return preferred
    for name in pool:
        if any(name in m or m.startswith(name.split(":")[0]) for m in available):
            return name
    return preferred


def looks_like_llm_stub(text: str) -> bool:
    """True when model_router / Ollama returned an unusable stub or empty body."""
    t = (text or "").strip()
    if not t:
        return True
    low = t.lower()
    return (
        "unavailable" in low and "stub" in low
    ) or "stub output for development" in low or low.startswith("[model ")


def looks_too_technical(text: str) -> bool:
    if looks_like_llm_stub(text):
        return True
    if not text or len(text.strip()) < 40:
        return True
    if _PATH_RE.search(text) or _EXT_PATHISH_RE.search(text):
        return True
    if _TECH_TOKEN_RE.search(text):
        return True
    bad_markers = (
        "indexeddb",
        "leveldb",
        "protobuf",
        "freelist",
        "msgstore",
        "/data/data/",
        "artifact_id",
        "parser_version",
        "required style",
        "write observations for a mobile",
    )
    low = text.lower()
    return any(m in low for m in bad_markers)


def rewrite_mobile_observations_plain(
    draft: str,
    *,
    evidence_brief: str,
    objective_txt: str = "",
    procedure_txt: str = "",
    model: str | None = None,
) -> str:
    """Rewrite draft observations into simple detailed client language."""
    settings = get_settings()
    if not getattr(settings, "mobile_report_llm_enabled", True):
        return strip_technical_noise(draft)

    draft_clean = strip_technical_noise(draft)
    brief = strip_technical_noise(evidence_brief)
    model_name = (model or resolve_mobile_report_model()).strip()

    prompt = (
        f"{MOBILE_PLAIN_LANGUAGE_GUIDE}\n\n"
        "Rewrite the draft findings below into the required Observations section.\n"
        "Observations MUST answer the case Objective using what the Procedure checked.\n"
        "Keep only facts supported by the evidence brief. Remove every path and technical term.\n"
        "Make the wording detailed enough that a normal person understands what was found "
        "and why it matters, without sounding like a computer log.\n\n"
        f"Case objective (must guide every finding):\n{(objective_txt or '')[:900]}\n\n"
        f"Procedure / what was checked (must guide the wording):\n{(procedure_txt or '')[:900]}\n\n"
        f"Evidence brief (already cleaned — use only this):\n{brief[:7000]}\n\n"
        f"Draft findings to rewrite:\n{draft_clean[:5000]}\n"
    )

    errors: list[str] = []
    for candidate in [model_name, *([m for m in _configured_model_pool() if m != model_name])]:
        try:
            out = generate_text(
                prompt,
                model=candidate,
                system=MOBILE_PLAIN_LANGUAGE_SYSTEM,
                temperature=0.15,
            ).strip()
            out = strip_technical_noise(out)
            if looks_too_technical(out) or len(out) < 80:
                errors.append(f"{candidate}: still technical or too short")
                continue
            if "### 3." not in out and not out.lstrip().startswith("-"):
                out = "### 3. Observations\n\n" + out
            log.info("mobile plain-language findings via model=%s", candidate)
            return out
        except Exception as exc:
            errors.append(f"{candidate}: {exc}")
            log.warning("mobile plain rewrite failed model=%s: %s", candidate, exc)

    log.warning("mobile plain rewrite exhausted models: %s", "; ".join(errors[:6]))
    # Last resort: cleaned draft without paths.
    cleaned = draft_clean
    if not cleaned.startswith("###"):
        cleaned = "### 3. Observations\n\n" + cleaned
    return cleaned


def plain_fallback_observations(
    inventory: dict[str, int] | None,
    *,
    objective_txt: str = "",
    procedure_txt: str = "",
) -> str:
    """Report inventory facts without inventing a completed review or findings."""
    inv = inventory or {}
    obj = strip_technical_noise(objective_txt or "")
    bullets: list[str] = []
    if obj:
        short_obj = re.sub(r"\s+", " ", obj).strip()
        if len(short_obj) > 220:
            short_obj = short_obj[:217].rsplit(" ", 1)[0] + "…"
        bullets.append(f"- The stated case objective is: {short_obj}")
    bullets.append("- These observations describe the acquired inventory; totals alone do not establish what each item contains.")
    for key, label in (
        ("pictures", "pictures and images"),
        ("whatsapp_messages", "WhatsApp message records"),
        ("whatsapp_chats", "WhatsApp chat records"),
        ("whatsapp_media", "WhatsApp media records"),
        ("audio", "audio files"),
        ("videos", "video files"),
        ("documents", "documents"),
        ("sms", "text message records"),
        ("call_logs", "call records"),
        ("deleted_files", "items marked deleted or recovered"),
        ("critical_files", "items requiring examiner review"),
    ):
        count = int(inv.get(key) or 0)
        if count:
            bullets.append(f"- The acquired inventory contains {count:,} {label}.")
    bullets.append("- Rooting, malware, payment activity and the contents of images or audio cannot be determined from inventory counts. Source-linked observations require content review.")
    return "### 3. Observations\n\n" + "\n".join(bullets)
