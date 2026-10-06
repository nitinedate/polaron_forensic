from app.services.evidence_contract import baseline_disk_evidence_contract


def test_external_disk_contract_deduplicates_physical_devices():
    contract = baseline_disk_evidence_contract("Connection of External Hard Disks")
    fields = set(contract["required_fields"])
    queries = " ".join(contract["rag_queries"]).lower()
    assert "distinct_physical_device_count" in fields
    assert "device_model_or_identity" in fields
    assert "physical device" in queries
    assert any("observation rule" in x.lower() for x in contract["prohibited_claims"])


def test_email_contract_separates_current_and_historical_account_state():
    contract = baseline_disk_evidence_contract("Email Accounts Used on the Laptop")
    fields = set(contract["required_fields"])
    questions = " ".join(contract["evidence_questions"]).lower()
    assert "account_state" in fields
    assert "historical" in questions
    assert "currently" in questions
