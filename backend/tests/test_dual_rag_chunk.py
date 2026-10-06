"""CPU-side RAG chunk helper used while the GPU embeds the previous batch."""

from types import SimpleNamespace

from app.services.dual_rag_index import chunk_rows_for_embedding


def test_chunk_rows_skips_empty_and_chunks_ocr_text() -> None:
    settings = SimpleNamespace(rag_chunk_size=24, rag_chunk_overlap=0)
    rows = [
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "file_path": "Documents/note.txt",
            "normalized": None,
            "ocr_text": "hello world this is embeddable ocr text",
            "encyclopedia_artifact_id": None,
        },
        {
            "id": "22222222-2222-2222-2222-222222222222",
            "file_path": "Windows/System32/foo.dll",
            "normalized": None,
            "ocr_text": None,
            "encyclopedia_artifact_id": None,
        },
    ]
    texts, meta, skip_ids, fallback = chunk_rows_for_embedding(rows, settings)
    assert skip_ids == ["22222222-2222-2222-2222-222222222222"]
    assert fallback == 0
    assert texts
    assert all("Evidence file Documents/note.txt" in t for t in texts)
    assert meta[0]["job_artifact_id"] == "11111111-1111-1111-1111-111111111111"
    assert meta[0]["chunk_index"] == 0
