"""Plain-language observation humanization."""

from app.services.report_objective_evidence import friendly_artifact_label, humanize_observation_text


def test_humanize_observation_replaces_forensic_jargon():
    raw = (
        "Evidence confirms the presence of 32,575 web-related files on the system, "
        "as indicated by the artifact 'Web Related Files.' No NTUSER.DAT or related profile "
        "folders were found. The Security.evtx log shows logon type 3 for LIDWIN001732."
    )
    out = humanize_observation_text(raw)
    assert "Evidence confirms" not in out
    assert "NTUSER.DAT" not in out
    assert "Security.evtx" not in out
    assert "logon type 3" not in out.lower()
    assert "examination found" in out.lower() or "The examination found" in out


def test_friendly_artifact_label():
    assert friendly_artifact_label("Web Related Files") == "web-related files"
    assert friendly_artifact_label("") == "records"
