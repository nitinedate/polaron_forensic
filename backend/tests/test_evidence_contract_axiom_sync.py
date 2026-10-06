from app.services.evidence_contract_planner import _merge_axiom_requirements
from app.services.evidence_contract import baseline_disk_evidence_contract


def test_axiom_required_and_expected_fields_are_merged_into_contract():
    row = {
        "axiom_objective_id": "O022",
        "required_observation_fields": "file name; action; timestamp",
        "expected_output_fields": "user, path, corroboration",
        "minimum_corroboration": 2,
        "limitations": "Do not infer copy from open/access evidence alone.",
        "axiom_statement": "Determine which relevant files were opened, changed, renamed, copied, or deleted.",
        "axiom_procedure_text": "1. Review file access records.\n2. Corroborate with recent-document traces.",
    }
    contract = _merge_axiom_requirements(row, baseline_disk_evidence_contract("File Access and Handling"))
    fields = {x.lower() for x in contract["required_fields"]}
    assert "file name" in fields
    assert "action" in fields
    assert "timestamp" in fields
    assert "corroboration" in fields
    assert contract["corroboration_min"] >= 2
    assert any("file access records" in q.lower() for q in contract["rag_queries"])
    assert any("axiom limitations" in p.lower() for p in contract["prohibited_claims"])
