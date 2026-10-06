from __future__ import annotations


def test_supplied_forensic_report_corpus_is_loaded_and_valid():
    from app.services.report_reference_kb import reference_corpus_summary, validate_reference_corpus

    assert validate_reference_corpus() == []
    summary = reference_corpus_summary()
    assert summary["source_reports"] == 13
    assert summary["objective_patterns"] == 18
    assert summary["artifact_categories"] == 13
    assert summary["writing_style_rules"] >= 8


def test_reference_patterns_map_the_report_objective_titles_to_controlled_kb_reports():
    from app.services.axiom_forensic_kb import objective_knowledge_plan

    cases = {
        "Verify Use of Unauthorized Remote Access Tools": {"INSTALLED_APPLICATIONS", "RDP_ACTIVITY"},
        "Cloud Storage Service Usage": {"BROWSER_HISTORY", "CLOUD_ACTIVITY"},
        "Analysis of Chat / Communication Apps": {"BROWSER_HISTORY", "INSTANT_MESSAGING"},
        "Analysis of Social Media Activity": {"BROWSER_HISTORY"},
        "Anti-Forensics Tools": {"INSTALLED_APPLICATIONS", "PROGRAM_EXECUTION"},
        "Torrent URLs": {"BROWSER_HISTORY", "BROWSER_DOWNLOADS"},
        "Malware / Phishing URL Verification": {"BROWSER_HISTORY", "SECURITY_DETECTIONS"},
    }
    for title, expected in cases.items():
        plan = objective_knowledge_plan(title)
        assert expected.issubset(set(plan["report_ids"])), (title, plan["report_ids"])
        assert plan["reference_exemplar_guidance"]["pattern_id"]


def test_reference_client_wording_is_simple_and_not_internal_kb_language():
    from app.services.report_examination_narratives import format_client_objective, format_client_procedure

    objective = format_client_objective("Cloud Storage Service Usage")
    procedure = format_client_procedure("Cloud Storage Service Usage")
    assert "cloud storage" in objective.lower()
    assert "upload" in objective.lower()
    assert "browser history" in procedure.lower()
    assert "controlled" not in procedure.lower()
    assert "primary evidence" not in procedure.lower()


def test_cloud_provider_taxonomy_learned_from_reports_but_rejects_id5_adtech_false_positive():
    from app.services.report_objective_case_facts import _cloud_provider

    assert _cloud_provider("https://drive.google.com/drive/folders/abc") == "Google Drive"
    assert _cloud_provider("https://www.dropbox.com/") == "Dropbox"
    assert _cloud_provider("https://mega.com/") == "Mega"
    assert _cloud_provider("https://skydrive.live.com/?id=x") == "SkyDrive / OneDrive"
    assert _cloud_provider("https://tenant.egnyte.com/app") == "Egnyte"
    assert _cloud_provider("https://www.sync.com/files/") == "Sync.com"
    # id5-sync.com is advertising ID-sync infrastructure, not Sync.com cloud storage.
    assert _cloud_provider("https://id5-sync.com/api/config/prebid") is None


def test_torrent_classifier_does_not_learn_archive_org_misclassification_from_reference_report():
    from app.services.report_objective_case_facts import _is_torrent_url

    assert _is_torrent_url("magnet:?xt=urn:btih:abc")
    assert _is_torrent_url("https://1337x.to/torrent/123/test")
    assert not _is_torrent_url("https://archive.org/details/aircraftdesign/page/n5/mode/2up")


def test_remote_access_fact_separates_tool_presence_from_unauthorized_use(monkeypatch):
    from app.services import forensic_inventory
    from app.services.report_objective_case_facts import _remote_access_fact

    monkeypatch.setattr(
        forensic_inventory,
        "collect_installed_programs",
        lambda *_a, **_k: {"non_microsoft": [], "microsoft": [], "samples_non_ms": ["AnyDesk"], "samples_ms": []},
    )
    monkeypatch.setattr(
        forensic_inventory,
        "collect_rdp_connections",
        lambda *_a, **_k: {"count": 0, "connections": [], "samples": []},
    )
    fact = _remote_access_fact(None, "job", "Verify Use of Unauthorized Remote Access Tools")
    assert fact["status"] == "CONFIRMED"
    assert fact["key_entities"]["remote_tools"] == ["AnyDesk"]
    assert "does not by itself" in fact["observation"].lower()
    assert "unauthorized" in fact["observation"].lower()


def test_chat_and_social_facts_name_services_not_generic_web_totals(monkeypatch):
    from app.services import report_objective_case_facts as mod

    rows = [
        {"url": "https://web.whatsapp.com/", "record_origin": "browser_history"},
        {"url": "https://web.telegram.org/", "record_origin": "browser_history"},
        {"url": "https://www.instagram.com/example", "record_origin": "browser_history"},
        {"url": "https://www.linkedin.com/in/example", "record_origin": "browser_history"},
    ]
    monkeypatch.setattr(mod, "_browser_records_with_persisted_fallback", lambda *_a, **_k: (rows, []))
    chat = mod._chat_fact(None, "job", "Analysis of Chat / Communication Apps")
    social = mod._social_fact(None, "job", "Analysis of Social Media Activity")
    assert chat["key_entities"]["services"] == ["WhatsApp Web", "Telegram Web"]
    assert social["key_entities"]["services"] == ["Instagram", "LinkedIn"]


def test_agent_safe_brief_contains_reference_method_but_no_reference_case_values():
    from app.services.report_objectives_observation_service import _agent_safe_brief

    safe = _agent_safe_brief(
        {
            "objective": {"title": "Cloud Storage Service Usage"},
            "status": "INCONCLUSIVE",
            "knowledge_plan": {
                "report_ids": ["BROWSER_HISTORY"],
                "direct_report_ids": [],
                "supporting_report_ids": ["BROWSER_HISTORY"],
                "procedure_ids": [],
                "limitations": [],
                "knowledge_base_version": "test",
                "reference_exemplar_guidance": {
                    "pattern_id": "CLOUD_STORAGE",
                    "decision_rules": ["Cloud URL access proves access only."],
                },
            },
            "report_results": [],
            "allowed_counts": [],
        }
    )
    assert safe["knowledge_plan"]["reference_exemplar_guidance"]["pattern_id"] == "CLOUD_STORAGE"
    serialized = repr(safe)
    assert "418" not in serialized
    assert "Ex-1" not in serialized


def test_reference_guidance_includes_learned_forensic_writing_style():
    from app.services.report_reference_kb import reference_agent_guidance

    guidance = reference_agent_guidance("Cloud Storage Service Usage")
    rules = guidance["writing_style_rules"]
    assert any("objective" in rule.lower() and "conclusion" in rule.lower() for rule in rules)
    assert any("observation" in rule.lower() and "evidence" in rule.lower() for rule in rules)


def test_cloud_takeout_reference_patterns_are_controlled_and_query_safe():
    from app.services.axiom_forensic_kb import objective_knowledge_plan

    cases = {
        "Verification of Google Account Data": {"EVIDENCE_SOURCE_SUMMARY", "CLOUD_ACTIVITY"},
        "Review of Gmail Usage": {"EMAIL_COMMUNICATIONS"},
        "Review of Google Drive Files": {"CLOUD_FILES", "DOCUMENTS"},
        "Review of Google Account Activity Logs": {"CLOUD_ACTIVITY"},
        "Review of Google Calendar Events": {"CLOUD_ACTIVITY"},
        "Review of Connected Devices History": {"DEVICE_INFORMATION", "CLOUD_ACTIVITY"},
        "Review of Google Photos Albums": {"PICTURES", "CLOUD_FILES"},
        "Review of Google Drive Shared Files": {"CLOUD_FILES"},
        "Review of Google Drive Shared Permissions": {"CLOUD_FILES"},
    }
    for title, expected in cases.items():
        plan = objective_knowledge_plan(title)
        assert expected.issubset(set(plan["report_ids"])), (title, plan["report_ids"])
        guide = plan["reference_exemplar_guidance"]
        assert guide["pattern_id"]
        assert guide["query_strategy"]["primary_filters"]
        assert guide["query_strategy"]["dedupe_keys"]
        assert guide["query_strategy"]["coverage_requirements"]
        assert guide["query_strategy"]["index_hints"]
        assert guide["query_principles"]


def test_reference_query_principles_keep_llm_out_of_unbounded_sql():
    from app.services.report_reference_kb import reference_agent_guidance

    guidance = reference_agent_guidance("Review of Gmail Usage")
    principles = " ".join(guidance["query_principles"]).lower()
    assert "controlled" in principles
    assert "job" in principles or "case" in principles
    assert "dedup" in principles
    assert "unverified" in principles
    assert "index" in principles
