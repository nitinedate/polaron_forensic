"""Tests for GLM-OCR service and GPU log helpers."""

from __future__ import annotations

from types import SimpleNamespace

from app.services import ocr_gpu
from app.services.gpu_thermal import GpuStats, gpu_log_prefix, gpu_work_log_message


def test_gpu_log_prefix_when_gpu_available(monkeypatch) -> None:
    stats = GpuStats(
        available=True,
        temperature_c=62,
        name="NVIDIA GeForce RTX 4060 Laptop GPU",
    )
    monkeypatch.setattr("app.services.gpu_thermal.get_gpu_stats", lambda: stats)
    prefix = gpu_log_prefix()
    assert prefix.startswith("[GPU")
    assert "62°C" in prefix


def test_gpu_work_log_message_prefixes_when_gpu(monkeypatch) -> None:
    stats = GpuStats(available=True, temperature_c=58, name="RTX 4060")
    monkeypatch.setattr("app.services.gpu_thermal.get_gpu_stats", lambda: stats)
    msg = gpu_work_log_message("GLM-OCR processing 3 files")
    assert msg.startswith("[GPU")
    assert "GLM-OCR processing 3 files" in msg


def test_ocr_bytes_uses_pypdf_text_layer(monkeypatch) -> None:
    monkeypatch.setattr(
        ocr_gpu,
        "_extract_pdf_text_layer",
        lambda data: ("hello pdf", 0.9),
    )
    text, conf, engine = ocr_gpu.ocr_bytes(b"%PDF", path="doc.pdf")
    assert text == "hello pdf"
    assert engine == "pypdf"
    assert conf == 0.9


def test_os_vendor_ocr_path_skips_adobe_stamps_and_windows() -> None:
    assert ocr_gpu.is_os_vendor_ocr_path(
        "Program Files (x86)/Adobe/Reader 11.0/Reader/plug_ins/Annotations/Stamps/Words.pdf"
    )
    assert ocr_gpu.is_os_vendor_ocr_path("Windows/System32/drivers/etc/hosts")
    assert not ocr_gpu.is_os_vendor_ocr_path("/Users/a/Documents/contract.pdf")
    assert not ocr_gpu.is_os_vendor_ocr_path("/Downloads/invoice-scan.png")


def test_cpu_prepare_skips_os_vendor_pdfs() -> None:
    prep = ocr_gpu.cpu_prepare_ocr_item(
        b"%PDF-1.4",
        path="Program Files (x86)/Adobe/Reader 11.0/Reader/plug_ins/Annotations/Stamps/Words.pdf",
    )
    assert prep["status"] == "skip"
    assert prep["engine"] == "os_vendor"


def test_photo_like_path_skips_camera_and_screenshots() -> None:
    assert ocr_gpu.is_photo_like_path("/Users/a/DCIM/IMG_0123.jpg")
    assert ocr_gpu.is_photo_like_path("C:/Users/a/Downloads/Screenshot 2026.png")
    assert ocr_gpu.is_photo_like_path("/WhatsApp Images/IMG_0099.jpeg")
    assert not ocr_gpu.is_photo_like_path("/Documents/contract.pdf")
    assert not ocr_gpu.is_photo_like_path("/Downloads/invoice-scan.png")


def test_prepare_ocr_image_downscales_and_skips_icons() -> None:
    from PIL import Image

    huge = Image.new("RGB", (4000, 3000), "white")
    prepared = ocr_gpu.prepare_ocr_image(huge, max_edge=1280)
    assert prepared is not None
    assert max(prepared.size) == 1280
    tiny = Image.new("RGB", (32, 32), "white")
    assert ocr_gpu.prepare_ocr_image(tiny, max_edge=1280) is None


def test_resolve_ocr_device_stays_cpu_when_cuda_missing(monkeypatch) -> None:
    monkeypatch.setattr(ocr_gpu, "_cuda_usable", lambda: False)
    monkeypatch.setattr(
        ocr_gpu,
        "get_settings",
        lambda: SimpleNamespace(ocr_device="cpu", rag_embedding_enabled=False),
    )
    assert ocr_gpu.ocr_should_use_gpu() is True
    assert ocr_gpu._resolve_ocr_device() == ("cpu", False)


def test_ocr_agent_takes_gpu_when_embeddings_off(monkeypatch) -> None:
    monkeypatch.setattr(ocr_gpu, "_cuda_usable", lambda: True)
    monkeypatch.setattr(
        ocr_gpu,
        "get_settings",
        lambda: SimpleNamespace(ocr_device="cpu", rag_embedding_enabled=False),
    )
    assert ocr_gpu.ocr_should_use_gpu() is True
    assert ocr_gpu._resolve_ocr_device() == ("cuda:0", True)


def test_ocr_device_none_never_uses_gpu(monkeypatch) -> None:
    monkeypatch.setattr(ocr_gpu, "_cuda_usable", lambda: True)
    monkeypatch.setattr(
        ocr_gpu,
        "get_settings",
        lambda: SimpleNamespace(ocr_device="none", rag_embedding_enabled=False),
    )
    assert ocr_gpu.ocr_should_use_gpu() is False


def test_ocr_is_gpu_only_default(monkeypatch) -> None:
    monkeypatch.setattr(
        ocr_gpu,
        "get_settings",
        lambda: SimpleNamespace(ocr_gpu_only=True, ocr_parallel_buckets=4),
    )
    assert ocr_gpu.ocr_is_gpu_only() is True
    monkeypatch.setattr(
        ocr_gpu,
        "get_settings",
        lambda: SimpleNamespace(ocr_gpu_only=False, ocr_parallel_buckets=0),
    )
    assert ocr_gpu.ocr_is_gpu_only() is True
    monkeypatch.setattr(
        ocr_gpu,
        "get_settings",
        lambda: SimpleNamespace(ocr_gpu_only=False, ocr_parallel_buckets=4),
    )
    assert ocr_gpu.ocr_is_gpu_only() is False


def test_cpu_bucket_does_not_claim_cuda_unavailable() -> None:
    msg = ocr_gpu.glm_defer_log_message(5, cpu_bucket=True, cuda_ok=True)
    assert "CUDA is unavailable" not in msg
    assert "GLM on CUDA" in msg
    assert "5" in msg


def test_gpu_drain_orders_images_before_pdfs() -> None:
    order = ocr_gpu._ocr_pending_order_sql(glm_first=True)
    assert "<> '.pdf'" in order
    filt = ocr_gpu._ocr_pending_filter_sql(cpu_bucket=True)
    assert ".pdf" in filt
    assert ocr_gpu._ocr_pending_filter_sql(cpu_bucket=False) == ""


def test_ocr_cpu_process_one_uses_text_layer(monkeypatch) -> None:
    monkeypatch.setattr(
        ocr_gpu,
        "cpu_prepare_ocr_item",
        lambda data, path, max_pages=None, allow_photos=False: {
            "status": "cpu_done",
            "text": "hello",
            "conf": 0.9,
            "engine": "pypdf",
            "segments": [],
        },
    )
    result = ocr_gpu._ocr_cpu_process_one(
        {"row": {"id": "1"}, "data": b"%PDF", "path": "a.pdf", "max_pages": 2, "allow_photos": False}
    )
    assert result["status"] == "ok"
    assert result["text"] == "hello"
    assert result["engine"] == "pypdf"


def test_ocr_cpu_process_one_signals_needs_gpu(monkeypatch) -> None:
    monkeypatch.setattr(
        ocr_gpu,
        "cpu_prepare_ocr_item",
        lambda data, path, max_pages=None, allow_photos=False: {
            "status": "needs_gpu",
            "text": "",
            "conf": 0.0,
            "engine": "glm-ocr",
            "segments": [{"type": "image", "image": object()}],
        },
    )
    result = ocr_gpu._ocr_cpu_process_one(
        {"row": {"id": "2"}, "data": b"png", "path": "scan.png", "max_pages": 2, "allow_photos": True}
    )
    assert result["status"] == "needs_gpu"
    assert result["engine"] == "glm-ocr"


def test_ocr_bytes_image_uses_glm(monkeypatch) -> None:
    monkeypatch.setattr(
        ocr_gpu,
        "cpu_prepare_ocr_item",
        lambda data, path, max_pages=None, allow_photos=False: {
            "status": "needs_gpu",
            "path": path,
            "text": "",
            "conf": 0.0,
            "engine": "glm-ocr",
            "segments": [{"type": "image", "image": object(), "prompt": "x"}],
        },
    )
    monkeypatch.setattr(
        ocr_gpu,
        "_gpu_ocr_prepared",
        lambda prep: ("table data", 0.92, "glm-ocr"),
    )
    text, conf, engine = ocr_gpu.ocr_bytes(b"png", path="scan.png")
    assert engine == "glm-ocr"
    assert text == "table data"


def test_cpu_prepare_text_layer_pdf_skips_gpu(monkeypatch) -> None:
    monkeypatch.setattr(ocr_gpu, "_extract_pdf_text_layer", lambda data: ("native text", 0.9))
    prep = ocr_gpu.cpu_prepare_ocr_item(b"%PDF-1.4", path="contract.pdf")
    assert prep["status"] == "cpu_done"
    assert prep["engine"] == "pypdf"
    assert prep["text"] == "native text"
    assert prep["segments"] == []


def test_office_without_images_stays_off_gpu() -> None:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "word/document.xml",
            "<w:document><w:t>Invoice 12345 paid in full today</w:t></w:document>",
        )
    prep = ocr_gpu.cpu_prepare_ocr_item(buf.getvalue(), path="Users/a/Documents/invoice.docx")
    assert prep["status"] == "cpu_done"
    assert prep["engine"] == "office-text"
    assert prep["segments"] == []
    assert "Invoice 12345" in prep["text"]


def test_office_with_embedded_image_still_needs_gpu() -> None:
    import io
    import zipfile

    from PIL import Image, ImageDraw

    img = Image.new("RGB", (400, 520), "white")
    draw = ImageDraw.Draw(img)
    for y in range(36, 500, 16):
        draw.rectangle((28, y, 372, y + 7), fill=(20, 20, 20))
    raw = io.BytesIO()
    img.save(raw, format="PNG")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "word/document.xml",
            "<w:document><w:t>See the attached scan of the signed contract</w:t></w:document>",
        )
        zf.writestr("word/media/image1.png", raw.getvalue())
    prep = ocr_gpu.cpu_prepare_ocr_item(buf.getvalue(), path="Users/a/Documents/signed.docx")
    assert prep["status"] == "needs_gpu"
    assert any(seg.get("type") == "image" for seg in prep["segments"])


def test_office_with_no_text_and_no_images_is_skipped() -> None:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", "<w:document></w:document>")
    prep = ocr_gpu.cpu_prepare_ocr_item(buf.getvalue(), path="Users/a/Documents/empty.docx")
    assert prep["status"] == "skip"
    assert prep["engine"] == "office-no-image"


def test_text_pdf_without_images_skips_gpu() -> None:
    fitz = __import__("fitz")
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Invoice 12345 paid in full")
    data = doc.tobytes()
    doc.close()
    prep = ocr_gpu.cpu_prepare_ocr_item(data, path="Users/a/Documents/letter.pdf")
    assert prep["status"] == "cpu_done"
    assert prep["engine"] in ("pypdf", "pymupdf-text")
    assert not any(seg.get("type") == "image" for seg in prep["segments"])


def test_scan_pdf_page_still_needs_gpu() -> None:
    import io

    fitz = __import__("fitz")
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (400, 520), "white")
    draw = ImageDraw.Draw(img)
    for y in range(36, 500, 16):
        draw.rectangle((28, y, 372, y + 7), fill=(20, 20, 20))
    raw = io.BytesIO()
    img.save(raw, format="PNG")
    doc = fitz.open()
    page = doc.new_page()
    page.insert_image(fitz.Rect(72, 72, 400, 520), stream=raw.getvalue())
    data = doc.tobytes()
    doc.close()
    prep = ocr_gpu.cpu_prepare_ocr_item(data, path="Users/a/Documents/scan.pdf")
    assert prep["status"] == "needs_gpu"
    assert any(seg.get("type") == "image" for seg in prep["segments"])


def test_cpu_prepare_skips_blank_image() -> None:
    import io

    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (220, 220), "white").save(buf, format="PNG")
    prep = ocr_gpu.cpu_prepare_ocr_item(buf.getvalue(), path="blank.png", allow_photos=True)
    assert prep["status"] == "skip"
    assert prep["engine"] in ("blank", "tiny")


def test_cpu_prepare_skips_clear_color_photo() -> None:
    import io

    from PIL import Image

    img = Image.linear_gradient("L").convert("RGB").resize((320, 240))
    pixels = img.load()
    for y in range(240):
        for x in range(320):
            pixels[x, y] = ((x * 3) % 256, (y * 5) % 256, (x + y) % 256)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    prep = ocr_gpu.cpu_prepare_ocr_item(
        buf.getvalue(), path="Users/a/Documents/holiday.png", allow_photos=True
    )
    assert prep["status"] == "skip"
    assert prep["engine"] == "blank"


def test_cpu_prepare_scan_like_image_needs_glm() -> None:
    import io

    from PIL import Image, ImageDraw

    img = Image.new("RGB", (400, 520), "white")
    draw = ImageDraw.Draw(img)
    for y in range(36, 500, 16):
        draw.rectangle((28, y, 372, y + 7), fill=(20, 20, 20))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    prep = ocr_gpu.cpu_prepare_ocr_item(buf.getvalue(), path="invoice-scan.png", allow_photos=True)
    assert prep["status"] == "needs_gpu"
    assert prep["engine"] == "glm-ocr"


def test_digital_text_usable() -> None:
    assert ocr_gpu._digital_text_usable("Invoice 12345 paid in full")
    assert not ocr_gpu._digital_text_usable("   ")
    assert not ocr_gpu._digital_text_usable("iii")


def test_cpu_prepare_skips_camera_photos_only_when_disallowed() -> None:
    prep = ocr_gpu.cpu_prepare_ocr_item(
        b"\xff\xd8", path="/Users/a/DCIM/IMG_0123.jpg", allow_photos=False
    )
    assert prep["status"] == "skip"
    assert prep["engine"] == "photo"


def test_ocr_status_queues_pictures_and_skips_cache(monkeypatch) -> None:
    monkeypatch.setattr(
        ocr_gpu,
        "get_settings",
        lambda: SimpleNamespace(ocr_documents_only=False),
    )
    assert ocr_gpu.ocr_status_for_artifact(
        "Users/a/Pictures/Screenshots/shot.png", extension=".png", size_bytes=80_000
    ) == "pending"
    assert ocr_gpu.ocr_status_for_artifact(
        "Users/a/DCIM/IMG_0123.jpg", extension=".jpg", size_bytes=1_200_000
    ) == "pending"
    assert ocr_gpu.ocr_status_for_artifact(
        "Users/a/AppData/Local/cache/thumb.png", extension=".png", size_bytes=80_000
    ) == "skipped"
    assert ocr_gpu.ocr_status_for_artifact(
        "Windows/System32/drivers/etc/hosts", extension=".png", size_bytes=80_000
    ) == "skipped"
    assert ocr_gpu.is_ocr_noise_path("Users/a/Pictures/vacation.jpg", size_bytes=900_000, extension=".jpg") is False


def test_ocr_status_skips_camera_roll_when_documents_only(monkeypatch) -> None:
    monkeypatch.setattr(
        ocr_gpu,
        "get_settings",
        lambda: SimpleNamespace(ocr_documents_only=True),
    )
    assert ocr_gpu.ocr_status_for_artifact(
        "Users/a/Pictures/Screenshots/shot.png", extension=".png", size_bytes=80_000
    ) == "skipped"
    assert ocr_gpu.ocr_status_for_artifact(
        "Users/a/DCIM/IMG_0123.jpg", extension=".jpg", size_bytes=1_200_000
    ) == "skipped"
    assert ocr_gpu.ocr_status_for_artifact(
        "Users/a/Documents/scan.pdf", extension=".pdf", size_bytes=400_000
    ) == "pending"
    assert ocr_gpu.ocr_status_for_artifact(
        "Users/a/Downloads/invoice.png", extension=".png", size_bytes=80_000
    ) == "pending"


def test_enqueue_eligible_ocr_does_not_requeue_skipped(monkeypatch) -> None:
    captured: dict = {}

    class _Result:
        rowcount = 4

    def _execute(_db, sql, params):
        captured["sql"] = sql
        captured["params"] = params
        return _Result()

    monkeypatch.setattr(ocr_gpu, "execute", _execute)
    monkeypatch.setattr(
        ocr_gpu,
        "get_settings",
        lambda: SimpleNamespace(ocr_documents_only=True),
    )
    assert ocr_gpu.enqueue_eligible_ocr(object(), "job-1") == 4
    assert "ocr_status='pending'" in captured["sql"]
    assert "skipped" not in captured["sql"]
    assert "'na'" in captured["sql"]
    assert captured["params"]["jid"] == "job-1"


def test_reopen_skipped_forensic_ocr_requeues_policy_matches(monkeypatch) -> None:
    captured: dict = {}

    class _Result:
        rowcount = 24

    def _execute(_db, sql, params):
        captured["sql"] = sql
        captured["params"] = params
        return _Result()

    monkeypatch.setattr(ocr_gpu, "execute", _execute)
    monkeypatch.setattr(
        ocr_gpu,
        "get_settings",
        lambda: SimpleNamespace(ocr_documents_only=True),
    )
    assert ocr_gpu.reopen_skipped_forensic_ocr(object(), "job-1") == 24
    assert "skipped" in captured["sql"]
    assert "ocr_status='pending'" in captured["sql"]
    assert captured["params"]["jid"] == "job-1"


def test_cpu_worker_hands_glm_scans_to_cuda_queue(monkeypatch) -> None:
    delayed: list[tuple] = []

    class _Drain:
        @staticmethod
        def delay(*args):
            delayed.append(args)

    import sys
    import types

    fake_tasks = types.ModuleType("app.tasks")
    fake_tasks.ocr_drain_task = _Drain
    monkeypatch.setitem(sys.modules, "app.tasks", fake_tasks)
    monkeypatch.setattr(ocr_gpu, "this_is_glm_drain_task", lambda: False)
    monkeypatch.setattr(ocr_gpu, "ocr_should_use_gpu", lambda: True)
    monkeypatch.setattr(ocr_gpu, "_cuda_usable", lambda: False)

    msg, handed = ocr_gpu.handoff_glm_scans_to_cuda_worker(
        "firm_aetheris", "job-1", 24, cpu_bucket=False
    )
    assert handed is True
    assert "handed to CUDA GLM worker" in msg
    assert "CUDA is unavailable" not in msg
    assert delayed == [("firm_aetheris", "job-1")]

    parked, parked_off = ocr_gpu.handoff_glm_scans_to_cuda_worker(
        "firm_aetheris", "job-1", 24, cpu_bucket=True
    )
    assert parked_off is False
    assert "left for GLM on CUDA" in parked


def test_count_pending_ocr_does_not_skip(monkeypatch) -> None:
    called = {"skip": 0}

    def _skip(_db, _job_id):
        called["skip"] += 1
        return 99

    monkeypatch.setattr(ocr_gpu, "skip_ocr_noise_pending", _skip)

    class _Db:
        pass

    monkeypatch.setattr(ocr_gpu, "fetchone", lambda *_a, **_k: {"c": 12})
    assert ocr_gpu.count_pending_ocr(_Db(), "job") == 12
    assert called["skip"] == 0


def test_sequential_mode_off_for_throughput(monkeypatch) -> None:
    from app.tasks import _responsive_sequential_mode

    monkeypatch.setattr(
        "app.config.get_settings",
        lambda: SimpleNamespace(pipeline_sequential_agents=False, perf_policy_mode="throughput"),
    )
    assert _responsive_sequential_mode() is False


def test_ocr_agent_progress_never_fakes_complete() -> None:
    from app.services.pipeline_orchestrator import ocr_agent_progress

    skipped = ocr_agent_progress(
        ocr_done=0, ocr_pending=0, ocr_eligible=420, parse_pending=100, extract_incomplete=False
    )
    assert skipped["state"] != "done"
    assert skipped["pct"] == 0

    waiting = ocr_agent_progress(
        ocr_done=0, ocr_pending=80, ocr_eligible=420, parse_pending=50, extract_incomplete=False
    )
    assert waiting["state"] == "running"
    assert waiting["pct"] == 1
    assert "OCR" in waiting["detail"]

    real = ocr_agent_progress(
        ocr_done=12, ocr_pending=0, ocr_eligible=12, parse_pending=0, extract_incomplete=False
    )
    assert real == {"state": "done", "pct": 100, "detail": "12 OCR'd"}

    leftover_eligible = ocr_agent_progress(
        ocr_done=32, ocr_pending=0, ocr_eligible=56, parse_pending=0, extract_incomplete=False,
        artifacts_registered=100,
        ocr_unfinished=0,
    )
    assert leftover_eligible["state"] == "done"
    assert leftover_eligible["pct"] == 100

    unfinished = ocr_agent_progress(
        ocr_done=32, ocr_pending=0, ocr_eligible=56, parse_pending=0, extract_incomplete=False,
        artifacts_registered=100,
        ocr_unfinished=12,
    )
    assert unfinished["state"] == "running"
    assert unfinished["pct"] < 100

    flicker = ocr_agent_progress(
        ocr_done=255, ocr_pending=0, ocr_eligible=3000, parse_pending=50, extract_incomplete=False
    )
    assert flicker["state"] != "done"
    assert flicker["pct"] < 100

    during_extract = ocr_agent_progress(
        ocr_done=0, ocr_pending=0, ocr_eligible=0, parse_pending=0, extract_incomplete=True
    )
    assert during_extract["state"] == "pending"
    assert during_extract["pct"] == 0

    no_files_yet = ocr_agent_progress(
        ocr_done=0,
        ocr_pending=0,
        ocr_eligible=0,
        parse_pending=0,
        extract_incomplete=False,
        artifacts_registered=0,
    )
    assert no_files_yet["state"] == "pending"
    assert no_files_yet["pct"] == 0

    after_parse_empty = ocr_agent_progress(
        ocr_done=0,
        ocr_pending=0,
        ocr_eligible=0,
        parse_pending=0,
        extract_incomplete=False,
        artifacts_registered=1200,
    )
    assert after_parse_empty["state"] == "done"


def test_open_ocr_cpu_pool_uses_threads_when_daemon(monkeypatch) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from types import SimpleNamespace

    monkeypatch.setattr(
        ocr_gpu.multiprocessing,
        "current_process",
        lambda: SimpleNamespace(daemon=True),
    )
    pool = ocr_gpu.open_ocr_cpu_pool(3)
    assert isinstance(pool, ThreadPoolExecutor)
    pool.shutdown(wait=False)


def test_run_ocr_skipped_when_disabled(monkeypatch) -> None:
    monkeypatch.setattr(
        ocr_gpu,
        "get_settings",
        lambda: SimpleNamespace(ocr_enabled=False),
    )

    class _Db:
        def commit(self) -> None:
            return None

    result = ocr_gpu.run_ocr_for_job(_Db(), "job", schema_name="firm", read_file_fn=lambda p: b"")
    assert result["status"] == "skipped"


def test_cuda_oom_is_not_permanent_unavailable(monkeypatch) -> None:
    """VRAM contention must remain retryable after exclusive-slot unload."""
    ocr_gpu._glm_model = None
    ocr_gpu._glm_processor = None
    ocr_gpu._glm_device = None
    ocr_gpu._glm_unavailable = False
    ocr_gpu._glm_unavailable_reason = None

    class _Oom(RuntimeError):
        pass

    calls = {"n": 0}

    def _fake_prepare() -> None:
        return None

    def _boom(*_a, **_k):
        calls["n"] += 1
        raise _Oom("CUDA out of memory. Tried to allocate 20.00 MiB")

    monkeypatch.setattr(ocr_gpu, "_resolve_ocr_device", lambda: ("cuda:0", True))
    monkeypatch.setattr(ocr_gpu, "_prepare_cuda_for_ocr_load", _fake_prepare)
    monkeypatch.setattr(ocr_gpu, "get_settings", lambda: SimpleNamespace(ocr_model="zai-org/GLM-OCR"))

    import sys
    import types

    fake_torch = types.SimpleNamespace(
        cuda=types.SimpleNamespace(is_available=lambda: True, empty_cache=lambda: None, synchronize=lambda: None),
        bfloat16="bf16",
        float32="fp32",
        version=types.SimpleNamespace(cuda="12.8"),
        __version__="2.14.0+cu128",
    )
    monkeypatch.setitem(sys.modules, "torch", fake_torch)

    fake_tf = types.ModuleType("transformers")
    fake_tf.AutoProcessor = types.SimpleNamespace(from_pretrained=_boom)
    fake_tf.GlmOcrForConditionalGeneration = types.SimpleNamespace(from_pretrained=_boom)
    monkeypatch.setitem(sys.modules, "transformers", fake_tf)

    model, processor, device = ocr_gpu._get_glm_ocr()
    assert model is None and processor is None and device is None
    assert calls["n"] == 2  # one retry after OOM
    assert ocr_gpu._glm_unavailable is False
    assert ocr_gpu._glm_unavailable_reason
    ocr_gpu.clear_glm_ocr_load_failure()
    assert ocr_gpu._glm_unavailable_reason is None
