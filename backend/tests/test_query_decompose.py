"""Tests for compound forensic query decomposition."""

from app.retrieval.query_decompose import decompose_query


def test_decompose_os_and_hardware() -> None:
    subs = decompose_query("provide operating system and hardware information")
    assert len(subs) == 2
    assert "operating system" in subs[0].lower()
    assert "hardware" in subs[1].lower()


def test_single_question_unchanged() -> None:
    q = "Which users logged into this laptop?"
    assert decompose_query(q) == [q]


def test_explicit_double_question() -> None:
    subs = decompose_query("Who are the users? What is the OS version?")
    assert len(subs) == 2
