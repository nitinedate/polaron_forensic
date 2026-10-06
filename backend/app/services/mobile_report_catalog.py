"""Mobile forensic report catalog — artifacts, objectives, AXIOM maps (Android + iOS)."""

from __future__ import annotations

# Default selected artifacts for mobile_forensic (exact public.axiom_artifacts names on Android).
MOBILE_FORENSIC_ARTIFACTS: list[tuple[str, str]] = [
    ("Communication", "WhatsApp Messages - Android"),
    ("Communication", "WhatsApp Calls"),
    ("Communication", "WhatsApp Chats - Android"),
    ("Communication", "WhatsApp Encrypted Backups - Android"),
    ("Media", "WhatsApp Media - Android"),
    ("Communication", "Android SMS"),
    ("Communication", "Android SMS/MMS"),
    ("Communication", "Android Call Logs"),
    ("Communication", "Telegram Messages - Android"),
    ("Communication", "Signal Messages - Android"),
    ("Communication", "Facebook Messenger Messages"),
    ("Communication", "Facebook Messenger Calls"),
    ("Social Networking", "Instagram Direct Messages"),
    ("Social Networking", "Instagram Media"),
    ("Social Networking", "LinkedIn Messages"),
    ("Social Networking", "LinkedIn Profile"),
    ("Email & Calendar", "Android Emails"),
    ("Email & Calendar", "Gmail Emails"),
    ("Email & Calendar", "Android Yahoo Mail Attachments"),
    ("Media", "Pictures"),
    ("Media", "Videos"),
    ("Media", "Audio"),
    ("Documents", "PDF Documents"),
    ("Application Usage", "Android Device Information"),
    ("Application Usage", "Installed Applications"),
    ("Application Usage", "Google Play Installed Applications"),
    ("Operating System", "Accounts Information"),
    ("Operating System", "Google Accounts"),
    ("Connected Devices", "SIM Card ICCID"),
    ("Connected Devices", "SIM Card IMSI"),
    ("Connected Devices", "SIM Card Phone Numbers"),
    ("Connected Devices", "SIM Card Service Providers"),
    ("Connected Devices", "SIM Card SMS Messages"),
]

# iOS twins — used when the job platform is iOS (must not reuse Android AX-* ids).
MOBILE_FORENSIC_ARTIFACTS_IOS: list[tuple[str, str]] = [
    ("Communication", "WhatsApp Messages - iOS"),
    ("Communication", "WhatsApp Calls"),
    ("Communication", "WhatsApp Chats - iOS"),
    ("Communication", "WhatsApp Encrypted Backups - iOS"),
    ("Media", "WhatsApp Media - iOS"),
    ("Communication", "WhatsApp Groups - iOS"),
    ("Communication", "iOS iMessage/SMS/MMS"),
    ("Communication", "iOS Call Logs"),
    ("Communication", "Telegram Messages - iOS"),
    ("Communication", "Signal Messages - iOS"),
    ("Communication", "Facebook Messenger Messages"),
    ("Communication", "Facebook Messenger Calls"),
    ("Communication", "Apple Contacts - iOS"),
    ("Social Networking", "Instagram Direct Messages"),
    ("Social Networking", "Instagram Media"),
    ("Social Networking", "LinkedIn Messages"),
    ("Social Networking", "LinkedIn Profile"),
    ("Email & Calendar", "Apple Mail"),
    ("Email & Calendar", "Gmail Emails"),
    ("Media", "Pictures"),
    ("Media", "Videos"),
    ("Media", "Audio"),
    ("Documents", "PDF Documents"),
    ("Application Usage", "iOS Device Information"),
    ("Application Usage", "Installed Applications"),
    ("Operating System", "Apple Accounts"),
    ("Connected Devices", "SIM Card ICCID"),
    ("Connected Devices", "SIM Card IMSI"),
    ("Connected Devices", "SIM Card Phone Numbers"),
    ("Connected Devices", "SIM Card Service Providers"),
    ("Connected Devices", "SIM Card SMS Messages"),
]

# Common Android artifact_name → iOS artifact_name when remapping a wrong-platform selection.
ANDROID_TO_IOS_ARTIFACT_NAME: dict[str, str] = {
    "WhatsApp Messages - Android": "WhatsApp Messages - iOS",
    "WhatsApp Encrypted Backups - Android": "WhatsApp Encrypted Backups - iOS",
    "WhatsApp Media - Android": "WhatsApp Media - iOS",
    "WhatsApp Chats - Android": "WhatsApp Chats - iOS",
    "WhatsApp Contacts - Android": "WhatsApp Contacts - iOS",
    "WhatsApp Groups - Android": "WhatsApp Groups - iOS",
    "Android SMS": "iOS iMessage/SMS/MMS",
    "Android SMS/MMS": "iOS iMessage/SMS/MMS",
    "Android Call Logs": "iOS Call Logs",
    "Telegram Messages - Android": "Telegram Messages - iOS",
    "Telegram Chats - Android": "Telegram Chats - iOS",
    "Signal Messages - Android": "Signal Messages - iOS",
    "Android Emails": "Apple Mail",
    "Android Yahoo Mail Attachments": "iOS Yahoo Mail Contacts",
    "Android Device Information": "iOS Device Information",
    "Google Play Installed Applications": "Installed Applications",
    "Accounts Information": "Apple Accounts",
    "Google Accounts": "Apple Accounts",
}

# Section C titles for mobile_forensic (also registered in REPORT_OBJECTIVES).
MOBILE_FORENSIC_OBJECTIVE_TITLES: list[str] = [
    "Device Identity & SIM Attribution",
    "Mobile Chat & Messaging Applications",
    "Mobile File Access & Media Handling",
    "Mobile User Accounts & App Logins",
    "Installed Mobile Applications",
    "Mobile Email & Attachments",
    "Social Media & LinkedIn Activity",
    "Mobile Cloud Storage & Sync",
    "Contacts & Address Book",
    "Mobile External Storage & USB/OTG",
]

# Title → Magnet AXIOM objective ID
MOBILE_TITLE_AXIOM_OBJECTIVE_ID: dict[str, str] = {
    "Device Identity & SIM Attribution": "O066",
    "Mobile Chat & Messaging Applications": "O043",
    "Mobile File Access & Media Handling": "O022",
    "Mobile User Accounts & App Logins": "O016",
    "Installed Mobile Applications": "O011",
    "Mobile Email & Attachments": "O045",
    "Social Media & LinkedIn Activity": "O043",
    "Mobile Cloud Storage & Sync": "O059",
    "Contacts & Address Book": "O041",
    "Mobile External Storage & USB/OTG": "O065",
}

# Report-agent knowledge is generated from the user-supplied AXIOM KB.  The mobile
# artifact lists and Android/iOS remapping above remain product ingestion metadata;
# they are not a second source of Objective/Procedure/Observation semantics.
from app.services.axiom_forensic_kb import (
    controlled_objective_text,
    controlled_procedure_text,
    evidence_questions_for_objective,
    objective_knowledge_plan,
    rag_terms_for_objective,
)


def _kb_mobile_narrative(title: str) -> dict:
    plan = objective_knowledge_plan(title)
    steps: list[str] = []
    for proc in plan.get("procedures") or []:
        for step in proc.get("steps") or []:
            text = str(step or "").strip()
            if text and text not in steps:
                steps.append(text)
    sources: list[str] = []
    for family in [
        *(plan.get("direct_primary_artifact_families") or []),
        *(plan.get("supporting_artifact_families") or []),
        *(plan.get("corroborating_artifact_families") or []),
    ]:
        if family and family not in sources:
            sources.append(str(family))
    return {
        "narrative": controlled_procedure_text(title, max_steps=0),
        "check_steps": steps[:8],
        "rag_queries": rag_terms_for_objective(title),
        "evidence_sources": sources[:16],
        "kb_report_ids": plan.get("report_ids") or [],
        "kb_procedure_ids": plan.get("procedure_ids") or [],
    }


MOBILE_OBJECTIVE_STATEMENTS: dict[str, str] = {
    title: controlled_objective_text(title) for title in MOBILE_FORENSIC_OBJECTIVE_TITLES
}
MOBILE_EXAMINATION_NARRATIVES: dict[str, dict] = {
    title: _kb_mobile_narrative(title) for title in MOBILE_FORENSIC_OBJECTIVE_TITLES
}
MOBILE_EVIDENCE_QUESTIONS: dict[str, list[str]] = {
    title: evidence_questions_for_objective(title) for title in MOBILE_FORENSIC_OBJECTIVE_TITLES
}
