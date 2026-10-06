#!/usr/bin/env python3
"""Learn a report model from the physical PDFs in document_report_model.

The PDFs teach two things only:
  * which queries retrieve the matching records from extracted case content
  * how an observation is written once those records are in hand

Names, accounts, hashes, URLs and counts from the exemplars are not stored.
Re-run after adding a PDF:

  python backend/scripts/build_document_report_model.py
"""
from __future__ import annotations

import json
import re
from pathlib import Path

def _model_dir() -> Path:
    candidates = [
        Path("/app/app/knowledge/document_report_model"),
        Path(__file__).resolve().parents[1] / "app" / "knowledge" / "document_report_model",
    ]
    for path in candidates:
        if path.is_dir():
            return path
    return candidates[-1]


ROOT = _model_dir()
OUT = ROOT / "report_model.json"

_PAGE_RE = re.compile(r"Page\s+\d+\s+of\s+\d+", re.I)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w.-]+\.\w+\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,}\b")
_OPO_RE = re.compile(r"OBJECTIVE,\s*PROCEDURE\s*(?:&|AND)\s*OBSERVATIONS?", re.I)
_END_RE = re.compile(r"\n\s*(?:[A-Z]\.\s*)?(?:ANNEXURE|ANALYSIS SUMMARY)\b", re.I)
_BLOCK_RE = re.compile(
    r"(?ms)^\s*(\d+)[.)]\s+(.+?)\s*\n\s*Objective\s*:\s*(.*?)\n\s*Procedure\s*:\s*(.*?)\n\s*Observations?\s*:\s*(.*?)(?=^\s*\d+[.)]\s+\S|\Z)"
)
def _clean(text: str) -> str:
    text = _PAGE_RE.sub(" ", text)
    text = text.replace("\u00a0", " ").replace("\r", "\n")
    text = re.sub(r"[\ue000-\uf8ff]", " ", text)
    text = _EMAIL_RE.sub("[account]", text)
    text = _HASH_RE.sub("[hash]", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n[ \t]+", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _sentence(text: str) -> str:
    body = " ".join(str(text or "").split())
    body = re.sub(r"https?://\S+", "[url]", body)
    return body[:500].strip(" .:-")


def _queries_from_procedure(title: str, procedure: str) -> list[str]:
    """Turn the examiner's procedure into retrieval queries over extracted content."""
    body = _sentence(procedure)
    queries = [f"{title} extracted evidence for the current case"]
    first = re.split(r"(?<=[.])\s+", body)[0] if body else ""
    focus = re.sub(
        r"^(The\s+)?(system|browser|web browser history|available records).{0,40}?(examined|reviewed)\s+to\s+",
        "",
        first,
        flags=re.I,
    ).strip(" .")
    if focus and focus.lower() != title.lower():
        queries.append(focus)
    nouns = re.findall(
        r"\b(?:USB|pen drives?|external hard disks?|RDP|remote desktop|browser history|"
        r"WhatsApp|Facebook|Telegram|Zoom|cloud storage|Google Drive|OneDrive|Box|"
        r"email accounts?|Outlook|Gmail|Google Takeout|calendar|social media|"
        r"LinkedIn|installed applications|connection times|downloads|login records|"
        r"synchronization folders|saved sessions)\b",
        body,
        flags=re.I,
    )
    seen: set[str] = set()
    for noun in nouns:
        key = noun.lower()
        if key in seen:
            continue
        seen.add(key)
        queries.append(f"{noun} in extracted content for this case")
    out: list[str] = []
    used: set[str] = set()
    for query in queries:
        text = " ".join(query.split())
        key = text.lower()
        if text and key not in used:
            used.add(key)
            out.append(text)
    return out[:6]


def _writing_moves(title: str, observation: str) -> list[str]:
    body = _sentence(observation).lower()
    absent = bool(re.search(r"\b(not identified|no evidence|did not reveal|were not)\b", body))
    moves = [
        f"Answer only the question in '{title}' from records retrieved for this case.",
        "Open by stating whether the examined records identified the activity or did not identify it.",
    ]
    if absent:
        moves.append(
            "When the retrieved records do not contain the activity, say the examination did not identify it. Do not turn a missing record into proof the activity never occurred if the source was not fully available."
        )
    else:
        moves.append(
            "When the retrieved records contain the activity, name the evidence family and what it indicates. Access or a connection is not file transfer, use, or unauthorized intent unless a separate record supports that stronger claim."
        )
    moves.append("Do not copy accounts, names, URLs, hashes, dates or counts from the physical training reports.")
    return moves


def _pdf_text(path: Path) -> str:
    import pymupdf

    doc = pymupdf.open(path)
    try:
        return _clean("\n".join(page.get_text() for page in doc))
    finally:
        doc.close()


def _opo_section(text: str) -> str:
    """The table of contents repeats the heading. Use the copy that contains Objective blocks."""
    for match in _OPO_RE.finditer(text):
        rest = text[match.end():]
        if not re.search(r"Objective\s*:", rest[:2500], re.I):
            continue
        end = _END_RE.search(rest)
        if end and end.start() < 400:
            continue
        return rest[: end.start()] if end else rest
    return ""


def _summary_topics(text: str, source: str) -> list[dict]:
    """Master summaries have finding headings instead of Objective/Procedure blocks."""
    if "MASTER FORENSIC SUMMARY" not in text.upper() and "KEY FINDINGS" not in text.upper():
        return []
    topics: list[dict] = []
    for match in re.finditer(r"(?m)^\s*\d+\.\s+([A-Z][^\n]{12,140})$", text):
        title = " ".join(match.group(1).split()).strip(" .")
        if re.search(r"overview|google accounts|mobile devices", title, re.I):
            continue
        topics.append(
            {
                "title": title,
                "extraction_queries": _queries_from_procedure(title, title),
                "examination_method": f"Search extracted content for records that answer: {title}",
                "observation_shape": "identified",
                "writing_moves": _writing_moves(title, "traces were identified"),
                "source_documents": [source],
            }
        )
    return topics[:12]


def _objectives(text: str) -> list[dict]:
    section = _opo_section(text)
    if not section:
        return []
    found: list[dict] = []
    for block in _BLOCK_RE.finditer(section):
        title = " ".join(block.group(2).split()).strip(" .:-")
        if len(title) < 4 or len(title) > 160:
            continue
        procedure = _sentence(block.group(4))
        observation = _sentence(block.group(5))
        if not procedure:
            continue
        found.append(
            {
                "title": title,
                "extraction_queries": _queries_from_procedure(title, procedure),
                "examination_method": procedure,
                "observation_shape": (
                    "not_identified"
                    if re.search(r"\b(not identified|no evidence|did not reveal)\b", observation, re.I)
                    else "identified"
                ),
                "writing_moves": _writing_moves(title, observation),
            }
        )
    return found


def build() -> dict:
    documents = []
    by_title: dict[str, dict] = {}
    for path in sorted(ROOT.glob("*.pdf")):
        text = _pdf_text(path)
        objectives = _objectives(text) or _summary_topics(text, path.name)
        documents.append(
            {
                "file": path.name,
                "objectives_learned": len(objectives),
            }
        )
        for item in objectives:
            key = re.sub(r"[^a-z0-9]+", " ", item["title"].lower()).strip()
            current = by_title.get(key)
            if current is None:
                item = dict(item)
                item["source_documents"] = [path.name]
                by_title[key] = item
                continue
            if path.name not in current["source_documents"]:
                current["source_documents"].append(path.name)
            for query in item["extraction_queries"]:
                if query not in current["extraction_queries"]:
                    current["extraction_queries"].append(query)
            current["extraction_queries"] = current["extraction_queries"][:8]
    objectives = sorted(by_title.values(), key=lambda row: row["title"].lower())
    return {
        "version": "document-report-model-v1",
        "purpose": (
            "Trained from the physical reports in document_report_model. "
            "Agents use extraction_queries to retrieve the current case's extracted content, "
            "then writing_moves to draft the observation. Exemplar case facts are not stored."
        ),
        "query_method": [
            "Match the objective title to a trained pattern from the physical reports.",
            "Run each extraction_query against this job's extracted content only, scoped by job id.",
            "Use browser history, device connections, installed programs, email artifacts and cloud records as the procedure names them.",
            "Do not answer from a physical training report. If the query returns nothing, the observation says the activity was not identified in the available records.",
        ],
        "observation_writing": {
            "rules": [
                "Write the observation only after the extraction queries have been run on the current case.",
                "Use the same shape as the physical reports: what was examined, whether traces were identified or not identified, and what that does or does not establish.",
                "Keep access, connection and presence separate from transfer, use and unauthorized intent.",
                "End with one short sentence beginning 'This means' that restates the finding in plain language.",
                "Never copy a name, account, URL, hash, date or count from a file in document_report_model.",
            ]
        },
        "documents": documents,
        "objectives": objectives,
    }


def main() -> int:
    if not ROOT.is_dir():
        raise SystemExit(f"Missing {ROOT}")
    model = build()
    OUT.write_text(json.dumps(model, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OUT}")
    print(f"documents={len(model['documents'])} objectives={len(model['objectives'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
