"""Count domain contract — no cross-domain label mixing."""

from app.services.axiom_count_result import COUNT_DOMAIN_LABELS, CountResult, count_result_from_int


def test_count_domain_labels_are_distinct() -> None:
    labels = list(COUNT_DOMAIN_LABELS.values())
    assert len(labels) == len(set(labels))


def test_answer_text_includes_domain_not_file_only_for_records() -> None:
    result = count_result_from_int(
        847,
        artifact_name="Web Chat URLs",
        count_domain="artifact_record",
        query_id="URL_VISIT_WEB_CHAT",
    )
    text = result.answer_text("Web Chat URLs")
    assert "847" in text
    assert "artifact record" in text
    assert "Web Chat URLs" in text


def test_file_occurrence_domain_label() -> None:
    result = CountResult(
        occurrence_count=12,
        count_domain="file_occurrence",
        query_id="DOCUMENT_EXTENSION",
    )
    assert "file occurrences" in result.answer_text("PDF")


def test_persist_fields_align_primary_count() -> None:
    result = CountResult(occurrence_count=5, unique_content_count=3, count_domain="artifact_record")
    fields = result.persist_fields()
    assert fields["artifact_count"] == 5
    assert fields["occurrence_count"] == 5
    assert fields["unique_count"] == 3
