"""GPU text detection for scans, screens, and video frames — thermal guards included."""

from __future__ import annotations

import io
import logging
import multiprocessing
import os
import threading
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, ThreadPoolExecutor, wait

from app.config import get_settings
from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.disk_build_log import write_disk_log

log = logging.getLogger("ocr_gpu")

_glm_model = None
_glm_processor = None
_glm_device: str | None = None
_fast_reader = None
_fast_reader_failed = False
_glm_lock = threading.Lock()
_fitz_lock = threading.Lock()
_glm_unavailable = False
_glm_unavailable_reason: str | None = None


def clear_glm_ocr_load_failure() -> None:
    """Allow another load attempt after a transient CUDA OOM / VRAM contention."""
    global _glm_unavailable, _glm_unavailable_reason
    with _glm_lock:
        _glm_unavailable = False
        _glm_unavailable_reason = None


def _is_cuda_oom(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return (
        "out of memory" in msg
        or "cuda oom" in msg
        or type(exc).__name__ in ("OutOfMemoryError", "CUDAOutOfMemoryError")
    )


def _prepare_cuda_for_ocr_load() -> None:
    """Free competing GPU residents and raise the process VRAM cap for OCR."""
    try:
        from app.services.embedding_gpu import unload_embedder

        unload_embedder()
    except Exception as exc:
        log.debug("embedder unload before OCR load: %s", exc)
    # V45: on a single 12 GB card a resident 14B Ollama model (~9 GB) leaves no
    # room for GLM-OCR at OCR_CUDA_MEMORY_FRACTION. RAG already evicts Ollama
    # (GPU_THERMAL_UNLOAD_OLLAMA_BEFORE_RAG); OCR must do the same.
    try:
        import os as _os

        if (_os.environ.get("GPU_THERMAL_UNLOAD_OLLAMA_BEFORE_OCR") or "true").strip().lower() in {"1", "true", "yes", "on"}:
            from app.services.model_router import ollama_unload_all_models

            unloaded = ollama_unload_all_models()
            if unloaded:
                log.info("Unloaded Ollama models before GLM-OCR load: %s", unloaded)
    except Exception as exc:
        log.debug("ollama unload before OCR load skipped: %s", exc)
    try:
        import gc
        import os

        import torch

        gc.collect()
        if torch.cuda.is_available():
            # Exclusive OCR slot — allow more of the laptop GPU than RAG's tight cap.
            # (RAG sets ~0.40; GLM-OCR needs room after embedder unload.)
            frac = float(os.environ.get("OCR_CUDA_MEMORY_FRACTION", "0.70"))
            try:
                from app.config import get_settings

                frac = float(getattr(get_settings(), "ocr_cuda_memory_fraction", frac) or frac)
            except Exception:
                pass
            frac = max(0.40, min(frac, 0.90))
            try:
                torch.cuda.set_per_process_memory_fraction(frac, 0)
                # Allow reconfigure later when RAG reloads with its own cap.
                from app.services import embedding_gpu as _eg

                _eg._cuda_configured = False  # type: ignore[attr-defined]
            except Exception as exc:
                log.debug("OCR CUDA fraction set skipped: %s", exc)
            torch.cuda.empty_cache()
            try:
                torch.cuda.synchronize()
            except Exception:
                pass
            log.info("CUDA prepared for GLM-OCR load (memory fraction≈%.2f)", frac)
    except Exception as exc:
        log.debug("CUDA prepare for OCR skipped: %s", exc)


def unload_glm_ocr() -> bool:
    """Free the OCR reader so another GPU job can use the card.

    The name stays because RAG, thermal shutdown, and the OCR slot already
    call it when this process must drop its CUDA weights.
    """
    global _glm_model, _glm_processor, _glm_device, _fast_reader
    with _glm_lock:
        if _glm_model is None and _glm_processor is None and _fast_reader is None:
            return False
        _glm_model = None
        _glm_processor = None
        _glm_device = None
        _fast_reader = None
    try:
        import gc

        gc.collect()
        import torch

        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            torch.cuda.synchronize()
        log.info("Unloaded GPU OCR from memory")
        return True
    except Exception as exc:
        log.debug("GPU OCR unload cleanup: %s", exc)
        return True

IMAGE_EXT = frozenset({".jpg", ".jpeg", ".png", ".tif", ".tiff", ".bmp", ".gif", ".webp", ".heic"})
# Office files are not added to the OCR queue. Text-only Word/Excel/PowerPoint
# never reaches GLM. A file that does arrive is handled in cpu_prepare: pictures
# only, and a document with no pictures is finished from its own text.
OFFICE_EXT = frozenset({".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx"})
VIDEO_EXT = frozenset({
    ".mp4", ".mkv", ".mov", ".avi", ".m4v", ".webm", ".mpeg", ".mpg", ".3gp", ".3gpp",
})
DOCUMENT_EXT = frozenset({".pdf", *IMAGE_EXT, *VIDEO_EXT})

OCR_ELIGIBLE_EXT_SQL = """
lower(coalesce(extension, '')) IN (
  '.pdf', '.png', '.jpg', '.jpeg', '.tif', '.tiff', '.webp', '.bmp', '.gif', '.heic',
  '.mp4', '.mkv', '.mov', '.avi', '.m4v', '.webm', '.mpeg', '.mpg', '.3gp', '.3gpp'
)
"""
OCR_DOC_FOLDER_SQL = """
(
  lower(file_path) LIKE '%/documents/%'
  OR lower(file_path) LIKE '%whatsapp%/documents/%'
  OR lower(file_path) LIKE '%/download%'
  OR lower(file_path) LIKE '%/downloads/%'
  OR lower(file_path) LIKE '%/desktop/%'
)
"""
# Cache/thumbs/OS vendor / app chrome only — never Pictures, DCIM, screenshots, WhatsApp images.
OCR_NOISE_SQL = """
(
  lower(file_path) LIKE '%/cache/%'
  OR lower(file_path) LIKE '%/.cache/%'
  OR lower(file_path) LIKE '%/.thumbnails/%'
  OR lower(file_path) LIKE '%/thumbs/%'
  OR lower(file_path) LIKE '%thumbcache%'
  OR lower(file_path) LIKE '%thumbs.db'
  OR lower(file_path) LIKE '%glide_disk_cache%'
  OR lower(file_path) LIKE '%/emoji/%'
  OR lower(file_path) LIKE '%/stickers/%'
  OR lower(file_path) LIKE '%/sticker/%'
  OR lower(file_path) LIKE '%/appdata/%'
  OR lower(file_path) LIKE '%appdata/%'
  OR lower(file_path) LIKE '%accountpictures%'
  OR lower(file_path) LIKE '%/application data/%'
  OR lower(file_path) LIKE '%/service worker/%'
  OR lower(file_path) LIKE '%/code cache/%'
  OR lower(file_path) LIKE '%/gpucache/%'
  OR lower(file_path) LIKE '%/shadercache/%'
  OR lower(file_path) LIKE '%/inetcache/%'
  OR lower(file_path) LIKE '%/temporary internet%'
  OR lower(file_path) LIKE '%/teams/backgrounds/%'
  OR lower(file_path) LIKE '%/node_modules/%'
  OR lower(file_path) LIKE '%/temp/%'
  OR lower(file_path) LIKE '%/tmp/%'
  OR lower(file_path) LIKE '%program files%'
  OR lower(file_path) LIKE '%programdata/%'
  OR lower(file_path) LIKE '%windows/system32%'
  OR lower(file_path) LIKE '%windows/syswow64%'
  OR lower(file_path) LIKE '%windows/winsxs%'
  OR lower(file_path) LIKE '%windows/servicing%'
  OR lower(file_path) LIKE '%windows/systemapps%'
  OR lower(file_path) LIKE '%$recycle.bin%'
  OR lower(file_path) LIKE '%system volume information%'
  OR lower(file_path) LIKE '%/plug_ins/%'
  OR lower(file_path) LIKE '%/stamps/%'
  OR lower(file_path) LIKE '%adobe/reader%'
  OR lower(file_path) LIKE '%adobe/acrobat%'
  OR lower(file_path) LIKE '%/windows/fonts/%'
  OR lower(file_path) LIKE '%/windows/installer/%'
  OR lower(coalesce(extension, '')) = '.ico'
  OR (
    coalesce(size_bytes, 0) > 0 AND coalesce(size_bytes, 0) < 4096
    AND lower(coalesce(extension, '')) <> '.pdf'
  )
)
"""
_CACHE_OCR_MARKERS = (
    "/cache/",
    "/.cache/",
    "/.thumbnails/",
    "/thumbs/",
    "thumbcache",
    "thumbs.db",
    "glide_disk_cache",
    "/emoji/",
    "/stickers/",
    "/sticker/",
    "/appdata/",
    "/application data/",
    "/service worker/",
    "/code cache/",
    "/gpucache/",
    "/shadercache/",
    "/inetcache/",
    "/temporary internet",
    "/teams/backgrounds/",
    "/node_modules/",
    "/temp/",
    "/tmp/",
)

_PHOTO_PATH_MARKERS = (
    "/dcim/",
    "/camera/",
    "/camera roll/",
    "/pictures/",
    "/photos/",
    "/screenshots/",
    "whatsapp image",
    "whatsapp video",
    "/whatsapp%/media/",
)
_PHOTO_NAME_PREFIXES = ("img_", "dsc_", "pxl_", "dscn", "img-")
_OS_VENDOR_OCR_MARKERS = (
    "program files/",
    "program files (x86)/",
    "programdata/",
    "windows/system32",
    "windows/syswow64",
    "windows/winsxs",
    "windows/servicing",
    "windows/systemapps",
    "$recycle.bin",
    "system volume information",
    "/plug_ins/",
    "/stamps/",
    "adobe/reader",
    "adobe/acrobat",
)


class GlmOcrTimeout(Exception):
    """A single GLM page exceeded OCR_MAX_INFER_SEC — skip the rest of this document."""


def is_os_vendor_ocr_path(path: str) -> bool:
    """True for Windows/OS vendor trees that burn OCR with no case evidence."""
    lower = str(path or "").replace("\\", "/").lower()
    if not lower:
        return False
    return any(marker in lower for marker in _OS_VENDOR_OCR_MARKERS)


def is_photo_like_path(path: str) -> bool:
    """True for camera rolls / screenshots. Used only when OCR_DOCUMENTS_ONLY=true."""
    lower = str(path or "").replace("\\", "/").lower()
    if not lower or lower.endswith(".pdf"):
        return False
    name = lower.rsplit("/", 1)[-1]
    if any(marker in lower for marker in _PHOTO_PATH_MARKERS):
        return True
    if name.startswith(_PHOTO_NAME_PREFIXES):
        return True
    if "screenshot" in name or name.startswith("screen shot") or name.startswith("snip"):
        return True
    return False


def forensic_photos_allowed() -> bool:
    """Images and videos may be prepared for OCR unless documents-only mode is on.

    Clear photographs and clear video frames are skipped from the pixels.
    Scans, screens, and other text-like pictures still go to the GPU.
    Documents-only mode still limits pictures to document folders.
    """
    return not bool(getattr(get_settings(), "ocr_documents_only", True))


def is_document_folder_path(path: str) -> bool:
    lower = str(path or "").replace("\\", "/").lower()
    return (
        "/documents/" in lower
        or "/download" in lower
        or "/downloads/" in lower
        or "/desktop/" in lower
    )


def is_ocr_noise_path(path: str, *, size_bytes: int = 0, extension: str = "") -> bool:
    """True for cache, thumbs, icons, and OS vendor trees — not user pictures."""
    if is_os_vendor_ocr_path(path):
        return True
    lower = str(path or "").replace("\\", "/").lower()
    if any(marker in lower for marker in _CACHE_OCR_MARKERS):
        return True
    ext = (extension or "").lower()
    if not ext and "." in lower:
        ext = "." + lower.rsplit(".", 1)[-1]
    if ext == ".ico":
        return True
    if ext != ".pdf" and int(size_bytes or 0) > 0 and int(size_bytes or 0) < 4096:
        return True
    return False


def ocr_status_for_artifact(path: str, *, extension: str = "", size_bytes: int = 0) -> str:
    """pending / skipped / na for a newly parsed artifact."""
    ext = (extension or "").lower()
    if not ext.startswith(".") and ext:
        ext = f".{ext}"
    if not ext:
        name = str(path or "").replace("\\", "/").rsplit("/", 1)[-1]
        if "." in name:
            ext = "." + name.rsplit(".", 1)[-1].lower()
    if ext not in DOCUMENT_EXT:
        return "na"
    if is_ocr_noise_path(path, size_bytes=size_bytes, extension=ext):
        return "skipped"
    if ext != ".pdf" and not forensic_photos_allowed() and not is_document_folder_path(path):
        return "skipped"
    return "pending"


def ocr_status_sql_for_parse_skip() -> str:
    """CASE expression used when bulk-skipping media from parse (keep OCR pending)."""
    keep = _ocr_eligible_keep_sql()
    return (
        f"CASE WHEN {keep} THEN 'pending' "
        f"WHEN {OCR_ELIGIBLE_EXT_SQL} THEN 'skipped' ELSE 'na' END"
    )


def prepare_ocr_image(img, *, max_edge: int = 1280):
    """Downscale for GLM and drop icons too small to be documents.

    Full-resolution phone photos make token generation much slower without
    improving forensic OCR quality.
    """
    try:
        width, height = img.size
    except Exception:
        return img
    if width < 80 or height < 80:
        return None
    edge = max(width, height)
    limit = max(int(max_edge or 1280), 480)
    if edge <= limit:
        return img
    scale = limit / float(edge)
    new_size = (max(1, int(width * scale)), max(1, int(height * scale)))
    try:
        from PIL import Image

        resample = getattr(Image, "Resampling", Image).BILINEAR
        return img.resize(new_size, resample)
    except Exception:
        return img.resize(new_size)


def _ocr_prompt_for_path(path: str) -> str:
    lower = path.lower()
    if lower.endswith((".xls", ".xlsx", ".csv")):
        return "Table Recognition:"
    if "formula" in lower or lower.endswith((".tex",)):
        return "Formula Recognition:"
    return "Text Recognition:"


def _cuda_usable() -> bool:
    try:
        import torch

        return bool(torch.cuda.is_available() and getattr(torch.version, "cuda", None))
    except Exception:
        return False


def ocr_should_use_gpu() -> bool:
    """Whether the OCR agent should dispatch a GPU drain.

    GLM must not run on CPU (minutes per page). Text-layer PDFs stay on CPU
    inside the drain. This policy is evaluated on the huddle/supervisor
    worker (which may lack CUDA) as well as on worker-ocr-gpu, so it does
    not require a local GPU — the OCR worker verifies CUDA before load.
    """
    settings = get_settings()
    requested = str(getattr(settings, "ocr_device", None) or "auto").strip().lower()
    if requested in ("none", "off", "disabled"):
        return False
    if requested in ("cuda", "gpu", "auto", ""):
        return True
    # OCR_DEVICE=cpu: still take GPU when embeddings are not occupying it.
    if not bool(getattr(settings, "rag_embedding_enabled", False)):
        return True
    try:
        from app.services.job_locks import inspect_process_lanes

        lanes = inspect_process_lanes() or {}
        return int(lanes.get("gpu_slots_free") or 0) > 0
    except Exception:
        return True


def _resolve_ocr_device() -> tuple[str, bool]:
    if not ocr_should_use_gpu():
        return "cpu", False
    if _cuda_usable():
        return "cuda:0", True
    log.warning(
        "OCR agent wants CUDA but this process has no GPU — text-layer PDFs only here"
    )
    return "cpu", False


def _get_glm_ocr():
    """Lazy-load GLM-OCR model (transformers)."""
    global _glm_model, _glm_processor, _glm_device, _glm_unavailable, _glm_unavailable_reason
    if _glm_unavailable:
        return None, None, None
    if _glm_model is not None and _glm_processor is not None:
        return _glm_model, _glm_processor, _glm_device
    with _glm_lock:
        if _glm_unavailable:
            return None, None, None
        if _glm_model is not None and _glm_processor is not None:
            return _glm_model, _glm_processor, _glm_device
        settings = get_settings()
        model_id = getattr(settings, "ocr_model", None) or "zai-org/GLM-OCR"
        device_label, gpu = _resolve_ocr_device()
        last_exc: BaseException | None = None
        for attempt in (1, 2):
            try:
                import torch
                from transformers import AutoProcessor, GlmOcrForConditionalGeneration

                if not (gpu and torch.cuda.is_available() and getattr(torch.version, "cuda", None)):
                    raise RuntimeError(
                        "GLM-OCR requires CUDA — refusing CPU fallback (one page can take many minutes)"
                    )
                _prepare_cuda_for_ocr_load()
                dtype = torch.bfloat16
                processor = AutoProcessor.from_pretrained(model_id)
                # Prefer explicit cuda:0 over device_map=auto (avoids multi-device
                # reservation quirks under a per-process memory fraction).
                model = GlmOcrForConditionalGeneration.from_pretrained(
                    model_id,
                    torch_dtype=dtype,
                )
                model.to("cuda:0")
                _glm_device = "cuda"
                model.eval()
                _glm_processor = processor
                _glm_model = model
                from app.services.gpu_thermal import gpu_log_prefix

                log.info("%s GLM-OCR loaded (%s) on %s", gpu_log_prefix(), model_id, _glm_device)
                return _glm_model, _glm_processor, _glm_device
            except Exception as exc:
                last_exc = exc
                if attempt == 1 and gpu and _is_cuda_oom(exc):
                    log.warning(
                        "GLM-OCR CUDA OOM on attempt %d — freeing VRAM and retrying: %s",
                        attempt,
                        exc,
                    )
                    try:
                        from app.services.embedding_gpu import unload_embedder

                        unload_embedder()
                    except Exception:
                        pass
                    try:
                        import gc

                        import torch

                        gc.collect()
                        if torch.cuda.is_available():
                            torch.cuda.empty_cache()
                            torch.cuda.synchronize()
                    except Exception:
                        pass
                    continue
                break

        # Permanent only for missing deps / bad model id — not transient OOM.
        if last_exc is not None and not _is_cuda_oom(last_exc):
            _glm_unavailable = True
            _glm_unavailable_reason = str(last_exc)[:500]
            log.warning("GLM-OCR unavailable (%s): %s", model_id, last_exc)
        elif last_exc is not None:
            # Leave retryable — next OCR batch / exclusive slot can try again.
            _glm_unavailable = False
            _glm_unavailable_reason = str(last_exc)[:500]
            log.warning("GLM-OCR load deferred (VRAM busy) (%s): %s", model_id, last_exc)
        return None, None, None


def _glm_micro_batch_size() -> int:
    """How many page images share one GLM forward pass. Same model and token cap."""
    try:
        raw = int(os.environ.get("OCR_GLM_MICRO_BATCH") or 8)
    except (TypeError, ValueError):
        raw = 4
    return max(1, min(raw, 8))


def _decode_glm_output(processor, output_row, prompt: str) -> tuple[str, float]:
    text = processor.decode(output_row, skip_special_tokens=True).strip()
    if prompt and text.startswith(prompt):
        text = text[len(prompt) :].strip()
    conf = 0.92 if len(text) > 20 else (0.75 if text else 0.0)
    return text, conf


def _glm_generate(model, inputs, *, max_tokens: int, infer_sec: int, batch_n: int):
    import torch

    box: dict = {}

    def _generate() -> None:
        with torch.no_grad():
            box["output"] = model.generate(**inputs, max_new_tokens=max_tokens, do_sample=False)

    worker = threading.Thread(target=_generate, name="glm-ocr-infer", daemon=True)
    worker.start()
    # One timeout budget per page so a batch is not cut shorter than serial runs.
    worker.join(infer_sec * max(batch_n, 1))
    if worker.is_alive():
        log.warning("GLM-OCR infer timed out after %ss — skipping this batch", infer_sec * batch_n)
        raise GlmOcrTimeout(f"infer exceeded {infer_sec * batch_n}s")
    if "output" not in box:
        raise RuntimeError("GLM-OCR returned no output")
    return box["output"]


def _fast_ocr_model_dir() -> str:
    configured = os.environ.get("EASYOCR_MODULE_PATH")
    if configured:
        return configured
    home = os.environ.get("HF_HOME") or "/root/.cache/huggingface"
    return os.path.join(home, "easyocr")


def _fast_ocr_languages() -> list[str]:
    raw = os.environ.get("OCR_LANGS") or "en"
    langs = [part.strip() for part in raw.split(",") if part.strip()]
    return langs or ["en"]


def _get_fast_ocr():
    """Detection plus recognition on CUDA. This is ordinary OCR, not a language model."""
    global _fast_reader, _fast_reader_failed
    if _fast_reader is not None:
        return _fast_reader
    if _fast_reader_failed:
        return None
    with _glm_lock:
        if _fast_reader is not None:
            return _fast_reader
        if _fast_reader_failed:
            return None
        try:
            import easyocr

            _prepare_cuda_for_ocr_load()
            gpu = _cuda_usable()
            if not gpu:
                raise RuntimeError("GPU OCR requires CUDA")
            model_dir = _fast_ocr_model_dir()
            os.makedirs(model_dir, exist_ok=True)
            _fast_reader = easyocr.Reader(
                _fast_ocr_languages(),
                gpu=True,
                model_storage_directory=model_dir,
                download_enabled=True,
                quantize=False,
                verbose=False,
            )
            from app.services.gpu_thermal import gpu_log_prefix

            log.info("%s GPU text detection loaded (easyocr %s)", gpu_log_prefix(), ",".join(_fast_ocr_languages()))
            return _fast_reader
        except ImportError as exc:
            _fast_reader_failed = True
            log.warning("GPU text detection unavailable: %s", exc)
            return None
        except Exception as exc:
            log.warning("GPU text detection could not load: %s", exc)
            return None


def _image_array(img):
    import numpy as np

    if hasattr(img, "convert"):
        img = img.convert("RGB")
        return np.asarray(img)
    return np.asarray(img)


def _text_from_detections(rows) -> tuple[str, float]:
    """Join detected words in reading order. Confidence is the detector's own score."""
    kept: list[tuple[float, float, str, float]] = []
    for row in rows or []:
        if not row or len(row) < 3:
            continue
        box, text, conf = row[0], str(row[1] or "").strip(), float(row[2] or 0.0)
        if not text:
            continue
        xs: list[float] = []
        ys: list[float] = []
        for point in box or []:
            if isinstance(point, (list, tuple)) and len(point) >= 2:
                xs.append(float(point[0]))
                ys.append(float(point[1]))
        kept.append((min(ys) if ys else 0.0, min(xs) if xs else 0.0, text, conf))
    if not kept:
        return "", 0.0
    kept.sort()
    return "\n".join(item[2] for item in kept), sum(item[3] for item in kept) / len(kept)


def _read_with_timeout(fn, seconds: float):
    box: dict = {}

    def _go() -> None:
        try:
            box["value"] = fn()
        except Exception as exc:
            box["error"] = exc

    worker = threading.Thread(target=_go, name="gpu-ocr", daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        raise GlmOcrTimeout(f"infer exceeded {seconds:.0f}s")
    if "error" in box:
        raise box["error"]
    return box.get("value")


def _fast_ocr_images(images: list) -> list[tuple[str, float]]:
    """Find text on each picture and read it. One loaded detector serves the batch."""
    if not images:
        return []
    reader = _get_fast_ocr()
    if reader is None:
        return [("", 0.0) for _ in images]
    from app.services.gpu_thermal import thermal_guard_before_batch

    thermal_guard_before_batch(reason="gpu_ocr")
    settings = get_settings()
    infer_sec = int(getattr(settings, "ocr_max_infer_sec", 30) or 30)
    infer_sec = max(8, min(infer_sec, 45))
    arrays = [_image_array(img) for img in images]

    def _detect() -> list:
        if len(arrays) > 1 and hasattr(reader, "readtext_batched"):
            return list(reader.readtext_batched(arrays))
        return [reader.readtext(arr, detail=1, paragraph=False) for arr in arrays]

    try:
        detected = _read_with_timeout(_detect, infer_sec * max(len(arrays), 1))
        if not isinstance(detected, list) or len(detected) < len(arrays):
            raise RuntimeError("GPU OCR returned fewer images than it was given")
        return [_text_from_detections(rows) for rows in detected[: len(arrays)]]
    except GlmOcrTimeout:
        raise
    except Exception as exc:
        log.warning("GPU OCR batch of %s failed (%s) — reading one image at a time", len(images), exc)
        out: list[tuple[str, float]] = []
        for arr in arrays:
            try:
                rows = _read_with_timeout(
                    lambda arr=arr: reader.readtext(arr, detail=1, paragraph=False),
                    infer_sec,
                )
                out.append(_text_from_detections(rows))
            except GlmOcrTimeout:
                raise
            except Exception:
                out.append(("", 0.0))
        return out
    finally:
        try:
            from app.services.gpu_thermal import should_empty_cuda_cache

            if should_empty_cuda_cache(batch_num=8):
                import torch

                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
        except Exception:
            pass


def _glm_ocr_images(images: list, *, prompt: str) -> list[tuple[str, float]]:
    """OCR several pictures. ``prompt`` is unused: detection reads the text itself."""
    del prompt
    return _fast_ocr_images(images)


def _glm_ocr_image(img, *, prompt: str) -> tuple[str, float]:
    rows = _glm_ocr_images([img], prompt=prompt)
    return rows[0] if rows else ("", 0.0)


def _ocr_image_bytes(data: bytes, *, path: str) -> tuple[str, float]:
    prep = cpu_prepare_ocr_item(data, path=path, allow_photos=True)
    if prep.get("status") == "cpu_done":
        return str(prep.get("text") or ""), float(prep.get("conf") or 0.0)
    if prep.get("status") != "needs_gpu":
        return "", 0.0
    texts: list[str] = []
    confs: list[float] = []
    for seg in prep.get("segments") or []:
        if seg.get("type") == "text" and seg.get("text"):
            texts.append(str(seg["text"]))
            confs.append(0.90)
            continue
        img = seg.get("image")
        if img is None:
            continue
        text, conf = _glm_ocr_image(img, prompt=str(seg.get("prompt") or "Text Recognition:"))
        if text:
            texts.append(text)
            confs.append(conf)
    if not texts:
        return "", 0.0
    avg = sum(confs) / len(confs) if confs else 0.0
    return "\n\n".join(texts), avg


def _is_office_path(path: str) -> bool:
    lower = str(path or "").lower()
    return any(lower.endswith(ext) for ext in OFFICE_EXT)


def _xml_text(blob: bytes) -> str:
    import re

    raw = blob.decode("utf-8", errors="ignore")
    raw = re.sub(r"<[^>]+>", " ", raw)
    return re.sub(r"\s+", " ", raw).strip()


def _office_plain_text(data: bytes, path: str, *, full: bool = False) -> str:
    """Pull the already-digital text out of a Word, Excel, or PowerPoint file."""
    lower = path.lower()
    try:
        import zipfile

        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            chosen: list[str] = []
            if lower.endswith((".docx", ".docm")):
                chosen = [n for n in names if n == "word/document.xml" or n.startswith("word/header")]
            elif lower.endswith((".xlsx", ".xlsm")):
                chosen = [n for n in names if n.startswith("xl/sharedStrings") or n.startswith("xl/worksheets/")]
            elif lower.endswith(".pptx"):
                chosen = [n for n in names if n.startswith("ppt/slides/slide")]
            parts = []
            for name in chosen if full else chosen[:30]:
                try:
                    parts.append(_xml_text(zf.read(name)))
                except Exception:
                    continue
            return "\n".join(p for p in parts if p)
    except Exception:
        return ""
    return ""


def _office_images(data: bytes) -> list:
    """Raster pictures embedded in an Office file. Text-only files return none."""
    from PIL import Image  # type: ignore

    images = []
    try:
        import zipfile

        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                lower = name.lower()
                if not any(lower.startswith(prefix) for prefix in ("word/media/", "ppt/media/", "xl/media/")):
                    continue
                if lower.endswith("/"):
                    continue
                try:
                    img = Image.open(io.BytesIO(zf.read(name))).convert("RGB")
                except Exception:
                    continue
                images.append(img)
    except Exception:
        return []
    return images


def _prepare_office_ocr(data: bytes, *, path: str, full: bool = False) -> dict:
    """OCR only pictures inside Office files. Clear text with no pictures stays off the GPU."""
    text = _office_plain_text(data, path, full=full)
    images = _office_images(data)
    settings = get_settings()
    max_edge = int(getattr(settings, "ocr_max_image_edge", 1280) or 1280)
    glm_segs = []
    for img in images:
        prepared = prepare_ocr_image(img, max_edge=max_edge)
        if prepared is None or not _raster_needs_actual_ocr(prepared):
            continue
        glm_segs.append(
            {"type": "image", "image": prepared, "prompt": _ocr_prompt_for_path(path)}
        )
    if not glm_segs:
        if _digital_text_usable(text):
            return {
                "status": "cpu_done",
                "path": path,
                "text": text,
                "conf": 0.90,
                "engine": "office-text",
                "segments": [],
            }
        return {
            "status": "skip",
            "path": path,
            "text": "",
            "conf": 0.0,
            "engine": "office-no-image",
            "segments": [],
        }
    segments = ([{"type": "text", "text": text}] if _digital_text_usable(text) else []) + glm_segs
    return {
        "status": "needs_gpu",
        "path": path,
        "text": "",
        "conf": 0.0,
        "engine": "easyocr",
        "segments": segments,
    }


def _pdf_page_has_images(page) -> bool:
    try:
        if page.get_images():
            return True
    except Exception:
        pass
    try:
        info = page.get_text("dict") or {}
        for block in info.get("blocks") or []:
            if block.get("type") == 1:
                return True
    except Exception:
        pass
    return False


def _pdf_bytes_have_images(data: bytes, *, full: bool = False) -> bool:
    try:
        import fitz  # type: ignore

        with _fitz_lock:
            doc = fitz.open(stream=data, filetype="pdf")
            try:
                limit = len(doc) if full else min(len(doc), 12)
                for i in range(limit):
                    if _pdf_page_has_images(doc[i]):
                        return True
            finally:
                doc.close()
    except Exception:
        return False
    return False


def _digital_text_usable(text: str | None) -> bool:
    """True when a PDF already has extractable digital text — skip GLM."""
    t = (text or "").strip()
    if len(t) < 8:
        return False
    return sum(ch.isalnum() for ch in t) >= 8


def _ink_run_stats(img) -> tuple[float, float, float, float]:
    """Horizontal and vertical ink-run density and mean run length.

    Printed text and scan lines have repeated edges with strokes several
    pixels wide. A clear photograph is either smooth or speckled, so it does
    not match both the density and the run length.
    """
    gray = img.convert("L")
    small = gray.copy()
    small.thumbnail((240, 240))
    width, height = small.size
    pixels = list(small.getdata())

    def stats(lines: list[list[int]]) -> tuple[float, float]:
        runs: list[int] = []
        transitions = 0
        samples = 0
        for line in lines:
            if len(line) < 2:
                continue
            run = 1
            dark = line[0] < 140
            for value in line[1:]:
                current = value < 140
                samples += 1
                if current == dark:
                    run += 1
                else:
                    transitions += 1
                    runs.append(run)
                    run = 1
                    dark = current
            runs.append(run)
        if not samples or not runs:
            return 0.0, 0.0
        return transitions / samples, sum(runs) / len(runs)

    rows = [pixels[y * width : (y + 1) * width] for y in range(0, height, 2)]
    cols = [
        [pixels[y * width + x] for y in range(height)] for x in range(0, width, 2)
    ]
    horizontal_density, horizontal_run = stats(rows)
    vertical_density, vertical_run = stats(cols)
    return horizontal_density, horizontal_run, vertical_density, vertical_run


def _raster_has_text_structure(img) -> bool:
    """True for scans, screenshots, and photographed pages — not a clear photo."""
    try:
        horizontal_density, horizontal_run, vertical_density, vertical_run = _ink_run_stats(img)
    except Exception:
        return False
    horizontal = 0.035 <= horizontal_density <= 0.45 and horizontal_run >= 3
    vertical = 0.03 <= vertical_density <= 0.50 and vertical_run >= 3
    return horizontal or vertical


def raster_is_hard_to_view(img) -> bool:
    """True when the picture itself is too dark, washed out, or soft to examine."""
    try:
        gray = img.convert("L")
        small = gray.copy()
        small.thumbnail((120, 120))
        hist = small.histogram()
        count = float(sum(hist) or 1)
        mean = sum(index * value for index, value in enumerate(hist)) / count
        if mean < 36 or mean > 225:
            return True
        width, height = small.size
        tiny = small.resize((max(1, width // 8), max(1, height // 8)))
        restored = tiny.resize((width, height))
        sharp = list(small.getdata())
        soft = list(restored.getdata())
        energy = sum((left - right) ** 2 for left, right in zip(sharp, soft)) / float(len(sharp) or 1)
        return energy < 35
    except Exception:
        return False


def _raster_needs_actual_ocr(img) -> bool:
    """True only when the picture looks like text that is not already extracted.

    Blank, tiny, and clear photographs are skipped. A scan or a screen of
    writing still goes to OCR. Clear digital documents never reach here.
    """
    try:
        gray = img.convert("L")
        w, h = gray.size
        if w < 48 or h < 48:
            return False
        small = gray.copy()
        small.thumbnail((160, 160))
        extrema = small.getextrema()
        if extrema is None or extrema[1] - extrema[0] < 24:
            return False
        hist = small.histogram()
        pixels = float(sum(hist) or 1)
        if max(hist) / pixels > 0.92:
            return False
        return _raster_has_text_structure(img)
    except Exception:
        return False


def _sample_video_ocr_frames(data: bytes, *, limit: int = 4) -> list:
    """A few frames from a video, for text that is only visible on screen."""
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path

    if not data or shutil.which("ffmpeg") is None:
        return []
    frames = []
    try:
        from PIL import Image
    except Exception:
        return []
    with tempfile.TemporaryDirectory(prefix="ocr-video-") as tmp:
        src = Path(tmp) / "clip.bin"
        src.write_bytes(data)
        pattern = str(Path(tmp) / "frame-%02d.png")
        try:
            proc = subprocess.run(
                [
                    "ffmpeg",
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-i",
                    str(src),
                    "-vf",
                    "fps=1/15,scale=1280:-2",
                    "-frames:v",
                    str(max(1, limit)),
                    pattern,
                ],
                capture_output=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        if proc.returncode != 0:
            return []
        for path in sorted(Path(tmp).glob("frame-*.png")):
            with Image.open(path) as img:
                img.load()
                frames.append(img.convert("RGB").copy())
    return frames


def cpu_prepare_ocr_item(
    data: bytes | None,
    *,
    path: str,
    max_pages: int | None = None,
    allow_photos: bool = False,
) -> dict:
    """CPU-only OCR prep: text-layer PDFs, decode/downscale, render scan pages.

    Returns status skip | cpu_done | needs_gpu. GLM is never called here so a
    thread pool can run this while the GPU is busy on the previous document.
    """
    path = str(path or "")
    if not data:
        return {"status": "skip", "path": path, "text": "", "conf": 0.0, "engine": "na", "segments": []}
    if is_os_vendor_ocr_path(path):
        return {"status": "skip", "path": path, "text": "", "conf": 0.0, "engine": "os_vendor", "segments": []}
    if not allow_photos and is_photo_like_path(path):
        return {"status": "skip", "path": path, "text": "", "conf": 0.0, "engine": "photo", "segments": []}
    lower = path.lower()
    if _is_office_path(lower):
        return _prepare_office_ocr(data, path=path, full=max_pages == 0)
    if lower.endswith(".pdf"):
        text, conf = _extract_pdf_text_layer(data, full=True) if max_pages == 0 else _extract_pdf_text_layer(data)
        # Clear digital text and no pictures: nothing for GLM to read.
        has_images = _pdf_bytes_have_images(data, full=True) if max_pages == 0 else _pdf_bytes_have_images(data)
        if _digital_text_usable(text) and not has_images:
            return {
                "status": "cpu_done",
                "path": path,
                "text": text,
                "conf": conf,
                "engine": "pypdf",
                "segments": [],
            }
        segments = _cpu_pdf_segments(data, path=path, max_pages=max_pages)
        native_parts = [
            str(seg.get("text") or "")
            for seg in segments
            if seg.get("type") == "text" and seg.get("text")
        ]
        glm_segs = [
            seg
            for seg in segments
            if seg.get("type") == "image" and _raster_needs_actual_ocr(seg.get("image"))
        ]
        native = "\n\n".join(p for p in native_parts if p)
        if _digital_text_usable(native) and not glm_segs:
            return {
                "status": "cpu_done",
                "path": path,
                "text": native,
                "conf": 0.90,
                "engine": "pymupdf-text",
                "segments": [],
            }
        if glm_segs:
            out = ([{"type": "text", "text": native}] if native else []) + glm_segs
            return {
                "status": "needs_gpu",
                "path": path,
                "text": "",
                "conf": 0.0,
                "engine": "easyocr",
                "segments": out,
            }
        if _digital_text_usable(native):
            return {
                "status": "cpu_done",
                "path": path,
                "text": native,
                "conf": 0.90,
                "engine": "pymupdf-text",
                "segments": [],
            }
        return {"status": "skip", "path": path, "text": "", "conf": 0.2, "engine": "stub", "segments": []}
    if any(lower.endswith(ext) for ext in VIDEO_EXT):
        frames = _sample_video_ocr_frames(data)
        if not frames:
            return {"status": "skip", "path": path, "text": "", "conf": 0.0, "engine": "video", "segments": []}
        settings = get_settings()
        max_edge = int(getattr(settings, "ocr_max_image_edge", 1280) or 1280)
        segments = []
        for frame in frames:
            prepared = prepare_ocr_image(frame, max_edge=max_edge)
            if prepared is None or not _raster_needs_actual_ocr(prepared):
                continue
            segments.append(
                {"type": "image", "image": prepared, "prompt": "Text Recognition:"}
            )
        if not segments:
            return {"status": "skip", "path": path, "text": "", "conf": 0.0, "engine": "blank", "segments": []}
        return {
            "status": "needs_gpu",
            "path": path,
            "text": "",
            "conf": 0.0,
            "engine": "easyocr",
            "segments": segments,
        }
    if any(lower.endswith(ext) for ext in IMAGE_EXT):
        try:
            from PIL import Image  # type: ignore

            img = Image.open(io.BytesIO(data)).convert("RGB")
        except Exception:
            return {"status": "skip", "path": path, "text": "", "conf": 0.0, "engine": "na", "segments": []}
        settings = get_settings()
        max_edge = int(getattr(settings, "ocr_max_image_edge", 1280) or 1280)
        prepared = prepare_ocr_image(img, max_edge=max_edge)
        if prepared is None or not _raster_needs_actual_ocr(prepared):
            return {"status": "skip", "path": path, "text": "", "conf": 0.0, "engine": "blank", "segments": []}
        return {
            "status": "needs_gpu",
            "path": path,
            "text": "",
            "conf": 0.0,
            "engine": "easyocr",
            "segments": [
                {"type": "image", "image": prepared, "prompt": _ocr_prompt_for_path(path)}
            ],
        }
    return {"status": "skip", "path": path, "text": "", "conf": 0.0, "engine": "na", "segments": []}


def _cpu_pdf_segments(data: bytes, *, path: str, max_pages: int | None = None) -> list[dict]:
    settings = get_settings()
    page_limit = int(max_pages if max_pages is not None else (getattr(settings, "ocr_max_pages", 8) or 8))
    page_limit = max(1, page_limit)
    try:
        import fitz  # type: ignore

        # PyMuPDF is not thread-safe — serialize open/render across CPU workers.
        with _fitz_lock:
            doc = fitz.open(stream=data, filetype="pdf")
            segments: list[dict] = []
            try:
                for page_num in range(len(doc) if max_pages == 0 else min(len(doc), page_limit)):
                    page = doc[page_num]
                    native = (page.get_text("text") or "").strip()
                    # Clear text stays as text. A page with no embedded image is
                    # not scanned, so rendering it for GLM only burns the GPU.
                    if _digital_text_usable(native):
                        segments.append({"type": "text", "text": native})
                        continue
                    if not _pdf_page_has_images(page):
                        if native:
                            segments.append({"type": "text", "text": native})
                        continue
                    pix = page.get_pixmap(dpi=110)
                    img_bytes = pix.tobytes("png")
                    from PIL import Image  # type: ignore

                    img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
                    max_edge = int(getattr(settings, "ocr_max_image_edge", 1280) or 1280)
                    prepared = prepare_ocr_image(img, max_edge=max_edge)
                    if prepared is None:
                        continue
                    segments.append(
                        {
                            "type": "image",
                            "image": prepared,
                            "prompt": _ocr_prompt_for_path(f"{path}#page{page_num + 1}"),
                        }
                    )
            finally:
                try:
                    doc.close()
                except Exception:
                    pass
            return segments
    except Exception as exc:
        log.warning("PyMuPDF prepare failed for %s: %s", path, exc)
        return []


def _gpu_ocr_prepared(prep: dict) -> tuple[str, float, str]:
    """Run GLM only on CPU-prepared image segments; keep native PDF text as-is."""
    if prep.get("status") == "cpu_done":
        return str(prep.get("text") or ""), float(prep.get("conf") or 0.0), str(prep.get("engine") or "pypdf")
    if prep.get("status") != "needs_gpu":
        engine = str(prep.get("engine") or "na")
        return "", 0.0, engine
    texts: list[str] = []
    confs: list[float] = []
    timed_out = False
    image_segs: list[dict] = []
    for seg in prep.get("segments") or []:
        if seg.get("type") == "text" and seg.get("text"):
            texts.append(str(seg["text"]))
            confs.append(0.90)
            continue
        if seg.get("image") is not None:
            image_segs.append(seg)
    micro = _glm_micro_batch_size()
    idx = 0
    while idx < len(image_segs):
        chunk = image_segs[idx : idx + micro]
        idx += len(chunk)
        prompt = str(chunk[0].get("prompt") or "Text Recognition:")
        if any(str(seg.get("prompt") or "Text Recognition:") != prompt for seg in chunk):
            prompt = "Text Recognition:"
        try:
            decoded = _glm_ocr_images([seg.get("image") for seg in chunk], prompt=prompt)
        except GlmOcrTimeout:
            timed_out = True
            log.warning("GPU OCR abandoned remaining pages for %s after infer timeout", prep.get("path"))
            break
        for text, conf in decoded:
            if text:
                texts.append(text)
                confs.append(conf)
    if not texts:
        return "", 0.0, "timeout" if timed_out else "stub"
    return "\n\n".join(texts), (sum(confs) / len(confs) if confs else 0.0), "easyocr"


def _extract_pdf_text_layer(data: bytes, *, full: bool = False) -> tuple[str, float]:
    try:
        from pypdf import PdfReader  # type: ignore

        reader = PdfReader(io.BytesIO(data))
        pages = []
        for page in reader.pages if full else reader.pages[:50]:
            t = page.extract_text() or ""
            if t.strip():
                pages.append(t.strip())
        if pages:
            return "\n\n".join(pages), 0.90
    except Exception as exc:
        log.debug("pypdf extract failed: %s", exc)
    return "", 0.0


def _ocr_pdf_pages(data: bytes, *, path: str, max_pages: int | None = None) -> tuple[str, float]:
    from app.services.gpu_thermal import GpuThermalAbort, thermal_guard_after_batch, thermal_guard_before_batch

    settings = get_settings()
    page_limit = int(max_pages if max_pages is not None else (getattr(settings, "ocr_max_pages", 10) or 10))
    page_limit = max(1, page_limit)
    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        all_text: list[str] = []
        confidences: list[float] = []
        for page_num in range(len(doc) if max_pages == 0 else min(len(doc), page_limit)):
            thermal_guard_before_batch(reason=f"glm_ocr_pdf_p{page_num + 1}")
            page = doc[page_num]
            native = (page.get_text("text") or "").strip()
            if _digital_text_usable(native) or not _pdf_page_has_images(page):
                if native:
                    all_text.append(native)
                    confidences.append(0.90)
                thermal_guard_after_batch(reason="glm_ocr_pdf_text")
                continue
            pix = page.get_pixmap(dpi=110)
            img_bytes = pix.tobytes("png")
            text, conf = _ocr_image_bytes(img_bytes, path=f"{path}#page{page_num + 1}")
            if text:
                all_text.append(text)
                confidences.append(conf)
            thermal_guard_after_batch(reason="glm_ocr_pdf_page")
        if all_text:
            avg_conf = sum(confidences) / len(confidences) if confidences else 0.7
            return "\n\n".join(all_text), avg_conf
    except GpuThermalAbort:
        raise
    except Exception as exc:
        log.debug("GLM-OCR PDF render failed: %s", exc)
    return "", 0.0


def _ocr_cpu_worker_count(*, gpu: bool, n_items: int, num_buckets: int = 1) -> int:
    """How many CPU threads prepare pictures before GPU text detection.

    Other serial stages stay at four units of evidence. OCR preparation is
    independent of that cap: a 12-core host was leaving eight cores idle.
    """
    settings = get_settings()
    configured = int(getattr(settings, "ocr_cpu_workers", 0) or 0)
    cpus = max(int(os.cpu_count() or 8), 1)
    # 4 is the old serial-stage cap, not a request to leave the other cores idle.
    wanted = configured if configured > 4 else max(8, cpus - 2)
    wanted = min(wanted, cpus)
    buckets = max(int(num_buckets or 1), 1)
    if buckets > 1:
        wanted = max(2, wanted // buckets)
    return max(1, min(wanted, max(int(n_items or 1), 1)))


def open_ocr_cpu_pool(workers: int):
    """CPU text-layer pool. Celery prefork workers cannot spawn processes.

    Spawning a process after ``torch.cuda.is_available()`` has already created a
    CUDA context deadlocks on this host (the pool never starts, so GLM never
    runs and the OCR card stays put). Threads share the process and stay safe.
    """
    n = max(1, int(workers or 1))
    cuda_ready = False
    try:
        import torch

        cuda_ready = bool(torch.cuda.is_initialized())
    except Exception:
        cuda_ready = False
    if multiprocessing.current_process().daemon or cuda_ready:
        log.info(
            "OCR CPU pool — %s thread(s) (CUDA context or prefork worker)",
            n,
        )
        return ThreadPoolExecutor(max_workers=n, thread_name_prefix="ocr-cpu")
    try:
        ctx = multiprocessing.get_context("spawn")
        return ProcessPoolExecutor(max_workers=n, mp_context=ctx)
    except Exception as extra:
        log.warning("OCR process pool unavailable (%s) — using threads", extra)
        return ThreadPoolExecutor(max_workers=n, thread_name_prefix="ocr-cpu")


def _ocr_cpu_process_one(payload: dict) -> dict:
    """Picklable process-pool worker: text-layer / CPU prepare, no CUDA."""
    row = payload.get("row") or {}
    data = payload.get("data")
    path = str(payload.get("path") or "")
    try:
        prep = cpu_prepare_ocr_item(
            data,
            path=path,
            max_pages=payload.get("max_pages"),
            allow_photos=bool(payload.get("allow_photos")),
        )
    except Exception as exc:
        return {
            "row": row,
            "status": "skip",
            "engine": "prep_fail",
            "text": "",
            "conf": 0.0,
            "error": str(exc)[:200],
        }
    if prep.get("status") == "cpu_done":
        return {
            "row": row,
            "status": "ok",
            "text": str(prep.get("text") or ""),
            "conf": float(prep.get("conf") or 0.0),
            "engine": str(prep.get("engine") or "pypdf"),
        }
    if prep.get("status") == "skip":
        return {
            "row": row,
            "status": "skip",
            "engine": str(prep.get("engine") or "na"),
            "text": "",
            "conf": 0.0,
        }
    return {
        "row": row,
        "status": "needs_gpu",
        "engine": "easyocr",
        "text": "",
        "conf": 0.0,
    }


def ocr_bytes(
    data: bytes,
    *,
    path: str,
    max_pages: int | None = None,
) -> tuple[str, float, str]:
    prep = cpu_prepare_ocr_item(
        data, path=path, max_pages=max_pages, allow_photos=forensic_photos_allowed()
    )
    if prep.get("status") == "skip":
        engine = str(prep.get("engine") or "na")
        if engine == "stub":
            return f"[PDF {len(data)} bytes — no text layer, GPU OCR unavailable]", 0.2, "stub"
        return "", 0.0, engine
    text, conf, engine = _gpu_ocr_prepared(prep)
    if text:
        return text, conf, engine
    if str(path).lower().endswith(".pdf"):
        return f"[PDF {len(data)} bytes — no text layer, GPU OCR unavailable]", 0.2, "stub"
    if any(str(path).lower().endswith(ext) for ext in IMAGE_EXT):
        return f"[Image {path} — GPU OCR unavailable, {len(data)} bytes]", 0.0, "stub"
    return "", 0.0, "na"


def _ocr_engine_available() -> bool:
    _, gpu = _resolve_ocr_device()
    if not gpu:
        return False
    return _get_fast_ocr() is not None


def skip_ocr_noise_pending(db, job_id: str) -> int:
    """Skip cache/thumbs/OS vendor trees. Documents-only also drops camera rolls.

    Image-evidence jobs keep every selected artifact (including tiny images).
    OCR_DOCUMENTS_ONLY (default) keeps PDFs plus Documents/Downloads/Desktop
    images so GLM is not spent on DCIM / Pictures / screenshots.
    """
    try:
        from app.services.rag_image_evidence import is_image_evidence_job

        if is_image_evidence_job(db, job_id):
            return 0
    except Exception:
        pass

    result = execute(
        db,
        f"""UPDATE job_artifacts SET ocr_status='skipped', updated_at=NOW()
            WHERE job_id=:jid AND ocr_status='pending'
              AND ({OCR_ELIGIBLE_EXT_SQL})
              AND ({OCR_NOISE_SQL})""",
        {"jid": job_id},
    )
    skipped = int(getattr(result, "rowcount", 0) or 0)
    if not forensic_photos_allowed():
        extra = execute(
            db,
            f"""UPDATE job_artifacts SET ocr_status='skipped', updated_at=NOW()
                WHERE job_id=:jid AND ocr_status='pending'
                  AND lower(coalesce(extension, '')) <> '.pdf'
                  AND NOT ({OCR_DOC_FOLDER_SQL})""",
            {"jid": job_id},
        )
        skipped += int(getattr(extra, "rowcount", 0) or 0)
    return skipped


def _ocr_eligible_keep_sql() -> str:
    keep = f"{OCR_ELIGIBLE_EXT_SQL} AND NOT ({OCR_NOISE_SQL})"
    if not forensic_photos_allowed():
        keep += f" AND (lower(coalesce(extension, '')) = '.pdf' OR {OCR_DOC_FOLDER_SQL})"
    else:
        # Tiny icons were policy-skipped; do not bounce them back into the queue.
        keep += (
            " AND (lower(coalesce(extension, '')) = '.pdf' "
            "OR coalesce(size_bytes, 0) >= 4096)"
        )
    return keep


def enqueue_eligible_ocr(db, job_id: str) -> int:
    """Queue PDFs/images that were never attempted (``na`` / empty status).

    Policy skips stay skipped. Re-opening ``skipped`` every huddle/drain
    bounce put camera-roll files back on the OCR queue and froze the card
    at 1% with hundreds of pending photos that do not need GLM.
    """
    keep = _ocr_eligible_keep_sql()
    result = execute(
        db,
        f"""UPDATE job_artifacts SET ocr_status='pending', updated_at=NOW()
            WHERE job_id=:jid
              AND coalesce(ocr_status, '') IN ('na', '')
              AND {keep}""",
        {"jid": job_id},
    )
    queued = int(getattr(result, "rowcount", 0) or 0)
    return queued


def reopen_failed_ocr_without_results(db, job_id: str) -> int:
    """Re-queue eligible files that CPU drain marked failed because GLM never ran."""
    keep = _ocr_eligible_keep_sql()
    result = execute(
        db,
        f"""UPDATE job_artifacts SET ocr_status='pending', updated_at=NOW()
            WHERE job_id=:jid AND ocr_status='failed' AND {keep}
              AND NOT EXISTS (
                    SELECT 1 FROM ocr_results o WHERE o.job_artifact_id = job_artifacts.id
              )""",
        {"jid": job_id},
    )
    return int(getattr(result, "rowcount", 0) or 0)


def reopen_skipped_forensic_ocr(db, job_id: str) -> int:
    """Re-queue skipped/never-attempted files that still match live OCR policy.

    ``enqueue_eligible_ocr`` only touches ``na`` / empty so huddle cannot bounce
    camera-roll skips. This path is the dedicated GLM retry: Documents/Downloads
    PDFs and images that were parked as ``skipped`` when a CPU worker had no CUDA.
    Noise and camera rolls stay skipped because they fail ``_ocr_eligible_keep_sql``.
    """
    keep = _ocr_eligible_keep_sql()
    result = execute(
        db,
        f"""UPDATE job_artifacts SET ocr_status='pending', updated_at=NOW()
            WHERE job_id=:jid
              AND coalesce(ocr_status, '') IN ('skipped', 'na', '')
              AND {keep}""",
        {"jid": job_id},
    )
    return int(getattr(result, "rowcount", 0) or 0)


def count_ocr_unfinished(db, job_id: str) -> int:
    """Work still to do: pending plus failed files that never produced OCR text.

    Skipped/failed-with-results files are finished policy outcomes — they must
    not keep the OCR card at 85% after the queue is empty.
    """
    keep = _ocr_eligible_keep_sql()
    row = fetchone(
        db,
        f"""SELECT count(*)::int AS c FROM job_artifacts
            WHERE job_id=:jid AND {keep}
              AND (
                coalesce(ocr_status, '') IN ('pending', 'na', '')
                OR (
                  ocr_status = 'failed'
                  AND NOT EXISTS (
                    SELECT 1 FROM ocr_results o WHERE o.job_artifact_id = job_artifacts.id
                  )
                )
              )""",
        {"jid": job_id},
    )
    return int((row or {}).get("c") or 0)


def count_ocr_eligible(db, job_id: str) -> int:
    """PDFs/images that should be OCR'd (any status), excluding cache/OS noise."""
    keep = _ocr_eligible_keep_sql()
    row = fetchone(
        db,
        f"SELECT count(*)::int AS c FROM job_artifacts WHERE job_id=:jid AND {keep}",
        {"jid": job_id},
    )
    return int((row or {}).get("c") or 0)


def count_pending_ocr(
    db,
    job_id: str,
    *,
    apply_skip: bool = False,
    ocr_bucket: int | None = None,
    ocr_buckets: int | None = None,
) -> int:
    """Count artifacts still waiting for OCR. Read-only unless apply_skip=True.

    Counting must not skip evidence. A previous version called skip_ocr_noise_pending
    here, which mass-skipped Pictures/screenshots and made the UI report 100% OCR
    in a few seconds.
    """
    if apply_skip:
        try:
            skip_ocr_noise_pending(db, job_id)
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
    bucket_sql = _ocr_bucket_sql(ocr_bucket, ocr_buckets)
    row = fetchone(
        db,
        f"""SELECT count(*)::int AS c FROM job_artifacts
            WHERE job_id=:jid AND ocr_status='pending' AND {OCR_ELIGIBLE_EXT_SQL}{bucket_sql}""",
        {"jid": job_id},
    )
    return int((row or {}).get("c") or 0)


def write_ocr_live_progress(db, job_id: str, *, label: str | None = None) -> None:
    """Merge OCR counts into jobs.pipeline_progress without wiping orchestration."""
    from app.services.pipeline_progress import write_merged_pipeline_progress

    pending = count_pending_ocr(db, job_id)
    done_row = fetchone(
        db,
        "SELECT count(*)::int AS c FROM job_artifacts WHERE job_id=:jid AND ocr_status='done'",
        {"jid": job_id},
    )
    cum_done = int((done_row or {}).get("c") or 0)
    write_merged_pipeline_progress(
        db,
        job_id,
        {
            "phase": "ocr",
            "completed": cum_done,
            "total": max(cum_done + pending, 1),
            "label": label or f"OCR — {cum_done:,} done, {pending:,} pending",
        },
        writer="ocr",
    )


def _ocr_bucket_sql(bucket_id: int | None, num_buckets: int | None) -> str:
    if bucket_id is None or not num_buckets or int(num_buckets) <= 1:
        return ""
    return f" AND mod(abs(hashtext(file_path)), {int(num_buckets)}) = {int(bucket_id)}"


def _ocr_pending_filter_sql(*, cpu_bucket: bool) -> str:
    """CPU buckets only text-layer PDFs. Images/scans stay for the CUDA GLM drain."""
    if cpu_bucket:
        return " AND lower(coalesce(extension, '')) = '.pdf'"
    return ""


def _ocr_pending_order_sql(*, glm_first: bool) -> str:
    """Pictures that can hold text come first, smallest of those first.

    The largest videos used to lead the queue. Each one was read from the
    archive before any GPU work, so the GPU sat idle.
    """
    if glm_first:
        return """
               ORDER BY
                 CASE
                   WHEN lower(coalesce(extension, '')) IN (
                     '.mp4','.mkv','.mov','.avi','.m4v','.webm','.mpeg','.mpg','.3gp','.3gpp'
                   ) THEN 3
                   WHEN lower(coalesce(extension, '')) = '.pdf' THEN 2
                   WHEN coalesce(size_bytes, 0) BETWEEN 20000 AND 2000000 THEN 0
                   ELSE 1
                 END,
                 size_bytes ASC NULLS LAST
        """
    return " ORDER BY size_bytes ASC NULLS LAST"


def this_is_glm_drain_task() -> bool:
    """True only inside ``ocr_drain_task`` (the dedicated CUDA worker)."""
    try:
        from celery import current_task

        name = str(getattr(current_task, "name", "") or "")
        return name == "app.tasks.ocr_drain_task"
    except Exception:
        return False


def glm_defer_log_message(n: int, *, cpu_bucket: bool, cuda_ok: bool) -> str:
    """Honest status when scans are left pending for GLM."""
    count = int(n or 0)
    if cpu_bucket:
        return f"OCR agent — {count} scan(s) left for GLM on CUDA"
    if cuda_ok:
        return f"OCR agent — {count} scan(s) queued for GLM on CUDA"
    return (
        f"OCR agent — {count} scan(s) need GLM but CUDA is unavailable on this worker"
    )


def handoff_glm_scans_to_cuda_worker(
    schema_name: str,
    job_id: str,
    count: int,
    *,
    cpu_bucket: bool,
) -> tuple[str, bool]:
    """Queue GLM scans onto ``ocr_drain_task`` (CUDA worker). Returns (log, handed_off).

    CPU buckets only park the rows. A full drain running on a disk/agent worker
    must not sit on ``CUDA is unavailable`` — it hands the scans to worker-ocr-gpu.
    """
    n = int(count or 0)
    if cpu_bucket:
        return glm_defer_log_message(n, cpu_bucket=True, cuda_ok=_cuda_usable()), False
    if this_is_glm_drain_task():
        return glm_defer_log_message(n, cpu_bucket=False, cuda_ok=_cuda_usable()), False
    if ocr_should_use_gpu():
        try:
            from app.tasks import ocr_drain_task

            ocr_drain_task.delay(schema_name, job_id)
            return f"OCR agent — {n} scan(s) handed to CUDA GLM worker", True
        except Exception as exc:
            log.warning("OCR handoff to CUDA worker failed: %s", exc)
    return glm_defer_log_message(n, cpu_bucket=False, cuda_ok=_cuda_usable()), False


def ocr_is_gpu_only() -> bool:
    """OCR Celery work belongs on worker-ocr-gpu only (no CPU bucket farm)."""
    settings = get_settings()
    if getattr(settings, "ocr_gpu_only", True):
        return True
    return int(getattr(settings, "ocr_parallel_buckets", 0) or 0) <= 0


def queue_parallel_ocr_buckets(
    schema_name: str,
    job_id: str,
    *,
    num_buckets: int | None = None,
) -> int:
    """Fan CPU OCR across N Celery workers. No-op when OCR is GPU-only."""
    if ocr_is_gpu_only():
        return 0
    settings = get_settings()
    buckets = max(int(num_buckets or getattr(settings, "ocr_parallel_buckets", 0) or 0), 0)
    buckets = min(buckets, 8)
    if buckets <= 0:
        return 0
    from app.tasks import ocr_bucket_task

    for bucket_id in range(buckets):
        ocr_bucket_task.delay(schema_name, job_id, bucket_id, buckets)
    return buckets


def dispatch_ocr_agent(schema_name: str, job_id: str) -> int:
    """Start the CUDA OCR drain only. CPU buckets are not used."""
    from app.tasks import ocr_drain_task

    ocr_drain_task.delay(schema_name, job_id)
    return 1


def run_ocr_for_job(
    db,
    job_id: str,
    *,
    schema_name: str,
    read_file_fn,
    paths: list[str] | None = None,
    batch_limit: int | None = None,
    ocr_bucket: int | None = None,
    ocr_buckets: int | None = None,
    gpu_permit_owned: bool = False,
) -> dict:
    settings = get_settings()
    if not settings.ocr_enabled:
        return {"status": "skipped", "ocr_count": 0}

    from app.services.gpu_thermal import recommended_ocr_batch_limit

    queued = enqueue_eligible_ocr(db, job_id)
    skipped_noise = skip_ocr_noise_pending(db, job_id)
    # The UPDATE inside skip_ocr_noise_pending starts a transaction even when it
    # changes zero rows.  Always commit before waiting for GPU/model/file I/O so
    # PostgreSQL does not retain RowExclusiveLock for hours.
    if queued:
        log.info("ocr enqueue job=%s queued=%s", job_id, queued)
    db.commit()

    image_ev = False
    try:
        from app.services.rag_image_evidence import is_image_evidence_job

        image_ev = is_image_evidence_job(db, job_id)
    except Exception:
        image_ev = False
    ocr_page_budget = None
    if image_ev:
        ocr_page_budget = int(
            getattr(settings, "rag_image_ocr_max_pages", None)
            or getattr(settings, "ocr_max_pages", 10)
            or 200
        )
    from app.services.forensic_serial_policy import current_stage

    if current_stage() == "ocr":
        # A disk image has thousands of PDFs. Read the configured page cap.
        # Clear text stays on CPU; only pages that still look like scans go to GPU.
        ocr_page_budget = int(getattr(settings, "ocr_max_pages", 8) or 8)

    # Thermal-safe batch — live plan + in-process governor (never above .env ceiling).
    configured = max(int(batch_limit or getattr(settings, "ocr_batch_limit", 40) or 40), 1)
    try:
        from app.services.perf_broadcast import live_ocr_batch

        configured = min(configured, live_ocr_batch(configured))
    except Exception:
        pass
    limit = recommended_ocr_batch_limit(configured)
    limit = min(max(limit, 1), 80)

    # One archive, pictures only. Text detection runs as each picture is
    # found, so the GPU is not waiting on the largest videos in the shard.
    rows = []
    if current_stage() == "ocr" and not paths and ocr_bucket is None:
        rows = fetchall(
            db,
            f"""WITH picked AS (
                 SELECT metadata->>'extracted_part_uri' AS uri
                 FROM job_artifacts
                 WHERE job_id=:jid AND ocr_status='pending' AND {OCR_ELIGIBLE_EXT_SQL}
                   AND NOT ({OCR_NOISE_SQL})
                   AND lower(coalesce(extension, '')) NOT IN (
                     '.mp4','.mkv','.mov','.avi','.m4v','.webm','.mpeg','.mpg','.3gp','.3gpp'
                   )
                   AND coalesce(metadata->>'extracted_part_uri', '') <> ''
                 GROUP BY 1
                 ORDER BY count(*) DESC
                 LIMIT 1
               )
               SELECT id, file_path, size_bytes, sha256 FROM job_artifacts
               WHERE job_id=:jid AND ocr_status='pending' AND {OCR_ELIGIBLE_EXT_SQL}
                 AND NOT ({OCR_NOISE_SQL})
                 AND lower(coalesce(extension, '')) NOT IN (
                   '.mp4','.mkv','.mov','.avi','.m4v','.webm','.mpeg','.mpg','.3gp','.3gpp'
                 )
                 AND metadata->>'extracted_part_uri' = (SELECT uri FROM picked)""",
            {"jid": job_id},
        )
    if paths and not rows:
        rows = fetchall(
            db,
            f"""SELECT id, file_path, size_bytes, sha256 FROM job_artifacts
               WHERE job_id=:jid AND ocr_status='pending' AND {OCR_ELIGIBLE_EXT_SQL}
                 AND file_path = ANY(:paths)
               {_ocr_pending_order_sql(glm_first=True)}
               LIMIT :lim""",
            {"jid": job_id, "paths": paths, "lim": limit},
        )
    elif not rows:
        cpu_bucket = ocr_bucket is not None
        bucket_sql = _ocr_bucket_sql(ocr_bucket, ocr_buckets)
        filt = _ocr_pending_filter_sql(cpu_bucket=cpu_bucket)
        rows = fetchall(
            db,
            f"""SELECT id, file_path, size_bytes, sha256 FROM job_artifacts
               WHERE job_id=:jid AND ocr_status='pending' AND {OCR_ELIGIBLE_EXT_SQL}
                 AND NOT ({OCR_NOISE_SQL}){bucket_sql}{filt}
               {_ocr_pending_order_sql(glm_first=not cpu_bucket)}
               LIMIT :lim""",
            {"jid": job_id, "lim": limit},
        )
    # Candidate selection is read-only, but SQLAlchemy still opens a transaction.
    # Close it before the potentially long GPU-slot/model-load phase.
    db.commit()
    if not rows:
        return {"status": "ok", "ocr_count": 0, "skipped_noise": skipped_noise}

    # OCR: CPU process pool extracts native PDF text. Scans/images go to GLM on CUDA
    # when the card is free. Never skip required OCR just because OCR_DEVICE was cpu.
    device_label, gpu = _resolve_ocr_device()
    if ocr_bucket is not None:
        # Path-hash buckets are CPU-only. GLM stays on the unsharded GPU drain.
        device_label, gpu = "cpu", False
    cpu_n = _ocr_cpu_worker_count(
        gpu=False, n_items=len(rows), num_buckets=int(ocr_buckets or 1)
    )
    write_disk_log(
        db,
        job_id,
        (
            f"GPU OCR — {len(rows)} document(s); CPU prep {cpu_n} worker(s), text detection on CUDA"
            if gpu
            else f"CPU OCR — {len(rows)} text-layer document(s) with {cpu_n} CPU worker(s)"
        ),
        stage="ocr",
        metadata={"gpu": gpu, "device": device_label, "ocr_cpu_workers": cpu_n},
    )
    write_ocr_live_progress(
        db,
        job_id,
        label=(
            f"GPU OCR loading — {len(rows)} document(s)"
            if gpu
            else f"CPU OCR — {len(rows)} document(s)"
        ),
    )
    db.commit()

    done = 0

    def _mark_ocr_skip(row: dict, *, engine: str) -> None:
        # Policy skips stay skipped (will not match enqueue keep). Attempt
        # failures stay failed so huddle does not re-queue them forever.
        st = (
            "skipped"
            if engine in ("na", "photo", "tiny", "os_vendor", "blank", "stub")
            else "failed"
        )
        execute(
            db,
            "UPDATE job_artifacts SET ocr_status=:st, updated_at=NOW() WHERE id=:id",
            {"id": row["id"], "st": st},
        )
        if image_ev:
            try:
                execute(
                    db,
                    """UPDATE rag_image_assets SET ocr_status=:st, ocr_engine=:eng,
                           updated_at=NOW() WHERE job_artifact_id=:aid""",
                    {"aid": row["id"], "st": st, "eng": engine},
                )
            except Exception:
                pass

    def _persist_ocr_ok(row: dict, text: str, conf: float, engine: str) -> None:
        safe_text = (text or "").replace("\x00", "").replace("\u0000", "")[:500_000]
        execute(
            db,
            """INSERT INTO ocr_results (job_artifact_id, ocr_text, confidence, engine)
               VALUES (:aid, :text, :conf, :eng)""",
            {"aid": row["id"], "text": safe_text, "conf": conf, "eng": engine},
        )
        execute(
            db,
            "UPDATE job_artifacts SET ocr_status='done', updated_at=NOW() WHERE id=:id",
            {"id": row["id"]},
        )
        if image_ev:
            try:
                execute(
                    db,
                    """UPDATE rag_image_assets SET
                           ocr_text=:text, ocr_confidence=:conf, ocr_engine=:eng,
                           ocr_status='done', stage_status='searchable', updated_at=NOW()
                         WHERE job_artifact_id=:aid""",
                    {"aid": row["id"], "text": safe_text, "conf": conf, "eng": engine},
                )
            except Exception:
                pass

    def _reuse_ocr(row: dict) -> tuple[str | None, float, str]:
        sha = (row.get("sha256") or "").strip()
        if not sha and image_ev:
            try:
                sh_row = fetchone(
                    db,
                    "SELECT sha256 FROM rag_image_assets WHERE job_artifact_id=:aid LIMIT 1",
                    {"aid": row["id"]},
                )
                sha = (sh_row or {}).get("sha256") or ""
            except Exception:
                sha = ""
        if not sha:
            return None, 0.0, "reuse"
        prior = fetchone(
            db,
            """SELECT o.ocr_text, o.confidence, o.engine
               FROM ocr_results o
               JOIN job_artifacts ja ON ja.id = o.job_artifact_id
               WHERE ja.sha256 = :sha
                 AND length(trim(coalesce(o.ocr_text, ''))) > 10
                 AND ja.id <> :aid
               ORDER BY o.created_at DESC
               LIMIT 1""",
            {"sha": sha, "aid": row["id"]},
        )
        if not prior:
            try:
                prior = fetchone(
                    db,
                    """SELECT ocr_text, ocr_confidence AS confidence, ocr_engine AS engine
                       FROM rag_image_assets
                       WHERE sha256 = :sha AND ocr_status = 'done'
                         AND length(trim(coalesce(ocr_text, ''))) > 10
                         AND (job_artifact_id IS NULL OR job_artifact_id <> :aid)
                       LIMIT 1""",
                    {"sha": sha, "aid": row["id"]},
                )
            except Exception:
                prior = None
        if prior and prior.get("ocr_text"):
            return (
                str(prior["ocr_text"]),
                float(prior.get("confidence") or 0.9),
                f"reuse:{prior.get('engine') or 'prior'}",
            )
        return None, 0.0, "reuse"

    def _gpu_chunk(chunk: list[dict]) -> None:
        nonlocal done
        prepared: list[tuple[dict, dict]] = []
        for payload in chunk:
            row = (payload.get("row") or {}) if isinstance(payload, dict) else {}
            path = str(payload.get("path") or row.get("file_path") or "")
            data = payload.get("data")
            if data is None:
                try:
                    data = read_file_fn(path)
                except Exception:
                    data = None
            prep = cpu_prepare_ocr_item(
                data or b"",
                path=path,
                max_pages=ocr_page_budget,
                allow_photos=image_ev or forensic_photos_allowed(),
            )
            prepared.append((payload, prep))
        image_jobs: list[tuple[int, object, str]] = []
        piece_lists: list[list[str]] = [[] for _ in prepared]
        conf_lists: list[list[float]] = [[] for _ in prepared]
        for prep_i, (_payload, prep) in enumerate(prepared):
            if prep.get("status") == "cpu_done" and prep.get("text"):
                piece_lists[prep_i].append(str(prep.get("text") or ""))
                conf_lists[prep_i].append(float(prep.get("conf") or 0.9))
                continue
            for seg in prep.get("segments") or []:
                if seg.get("type") == "text" and seg.get("text"):
                    piece_lists[prep_i].append(str(seg["text"]))
                    conf_lists[prep_i].append(0.90)
                    continue
                img = seg.get("image")
                if img is None:
                    continue
                image_jobs.append((prep_i, img, str(seg.get("prompt") or "Text Recognition:")))
        grouped: dict[str, list[tuple[int, object]]] = {}
        for prep_i, img, prompt in image_jobs:
            grouped.setdefault(prompt, []).append((prep_i, img))
        for prompt, jobs in grouped.items():
            try:
                decoded = _glm_ocr_images([img for _i, img in jobs], prompt=prompt)
            except Exception as exc:
                log.warning("GPU OCR batch failed: %s", exc)
                decoded = [("", 0.0) for _ in jobs]
            for (prep_i, _img), (text, conf) in zip(jobs, decoded):
                if text:
                    piece_lists[prep_i].append(text)
                    conf_lists[prep_i].append(conf)
        for (payload, prep), pieces, confs in zip(prepared, piece_lists, conf_lists):
            row = (payload.get("row") or {}) if isinstance(payload, dict) else {}
            if pieces:
                text = "\n\n".join(pieces)
                conf = sum(confs) / len(confs) if confs else 0.0
                _persist_ocr_ok(
                    row,
                    text,
                    conf,
                    "easyocr" if prep.get("status") != "cpu_done" else str(prep.get("engine") or "pypdf"),
                )
                db.commit()
                done += 1
            elif prep.get("status") == "skip":
                _mark_ocr_skip(row, engine=str(prep.get("engine") or "na"))
                db.commit()
            else:
                _mark_ocr_skip(row, engine="ocr_empty")
                db.commit()

    iter_found = getattr(read_file_fn, "iter_found", None)
    stream_archive = current_stage() == "ocr" and callable(iter_found)
    work_rows: list[dict] = []
    if stream_archive:
        work_rows = [dict(row) for row in rows]
    else:
        for row in rows:
            row_path = str(row.get("file_path") or "")
            skip_photo = (not image_ev) and (not forensic_photos_allowed()) and is_photo_like_path(row_path)
            if skip_photo or is_os_vendor_ocr_path(row_path):
                execute(
                    db,
                    "UPDATE job_artifacts SET ocr_status='skipped', updated_at=NOW() WHERE id=:id",
                    {"id": row["id"]},
                )
                db.commit()
                continue
            text, conf, engine = _reuse_ocr(row)
            if text:
                _persist_ocr_ok(row, text, conf, engine)
                db.commit()
                done += 1
                continue
            db.commit()
            work_rows.append(dict(row))

    needs_gpu_rows: list[dict] = []
    streamed = False
    if stream_archive and work_rows:
        streamed = True
        by_path = {
            str(r.get("file_path") or "").replace("\\", "/"): r for r in work_rows
        }
        flush_at = 1
        announced = False
        allow_photos = image_ev or forensic_photos_allowed()

        def _touch(label: str) -> None:
            from app.services.forensic_serial_stages import report_progress
            from app.services.progress_agent import note_operation

            note_operation(db, job_id, "ocr", label, timeout_seconds=900, advanced=True)
            total_row = fetchone(
                db,
                "SELECT total_items FROM pipeline_stage_runs WHERE job_id=:jid AND stage='ocr'",
                {"jid": job_id},
            )
            total = int((total_row or {}).get("total_items") or 0)
            pending_now = count_pending_ocr(db, job_id)
            if total > 0:
                report_progress(
                    db,
                    job_id,
                    "ocr",
                    total=total,
                    completed=max(total - pending_now, 0),
                    label=label,
                )

        def _flush_gpu() -> None:
            nonlocal flush_at, announced
            if not needs_gpu_rows or not gpu:
                return
            if not announced:
                write_disk_log(
                    db,
                    job_id,
                    f"OCR agent — GPU text detection on {len(needs_gpu_rows)} picture(s)",
                    stage="ocr",
                    metadata={"gpu": True, "device": device_label},
                )
                announced = True
                db.commit()
            chunk = list(needs_gpu_rows)
            needs_gpu_rows.clear()
            micro = _glm_micro_batch_size()
            for start in range(0, len(chunk), micro):
                _gpu_chunk(chunk[start : start + micro])
            flush_at = cpu_n
            _touch(f"GPU text detection — {done:,} document(s)")

        seen = 0
        window: list[dict] = []

        def _apply_cpu(result: dict, payload: dict) -> None:
            nonlocal done, seen
            row_out = result.get("row") or payload["row"]
            if result.get("status") == "ok" and result.get("text"):
                _persist_ocr_ok(
                    row_out,
                    str(result.get("text") or ""),
                    float(result.get("conf") or 0.0),
                    str(result.get("engine") or "pypdf"),
                )
                db.commit()
                done += 1
            elif result.get("status") == "needs_gpu":
                needs_gpu_rows.append(payload)
            else:
                _mark_ocr_skip(row_out, engine=str(result.get("engine") or "na"))
                db.commit()
            seen += 1

        def _drain_window(pool) -> None:
            if not window:
                return
            batch = list(window)
            window.clear()
            futures = [pool.submit(_ocr_cpu_process_one, payload) for payload in batch]
            for fut, payload in zip(futures, batch):
                try:
                    result = fut.result()
                except Exception as exc:
                    log.warning("CPU OCR prepare failed: %s", exc)
                    continue
                _apply_cpu(result, payload)
            if needs_gpu_rows:
                _flush_gpu()
            elif seen and seen % 25 == 0:
                _touch("Reading pictures for GPU text detection")

        with open_ocr_cpu_pool(cpu_n) as pool:
            for norm, data in iter_found(list(by_path)):
                row = by_path.pop(norm, None)
                if row is None:
                    continue
                if is_os_vendor_ocr_path(norm):
                    _mark_ocr_skip({"id": row["id"], "file_path": norm}, engine="os_vendor")
                    db.commit()
                    seen += 1
                    continue
                window.append(
                    {
                        "row": {"id": row["id"], "file_path": norm},
                        "data": data,
                        "path": norm,
                        "max_pages": ocr_page_budget,
                        "allow_photos": allow_photos,
                    }
                )
                if len(window) >= cpu_n:
                    _drain_window(pool)
            _drain_window(pool)
        for leftover in by_path.values():
            _mark_ocr_skip(leftover, engine="na")
            db.commit()
        _flush_gpu()

    if not streamed:
        payloads: list[dict] = []
        preload = getattr(read_file_fn, "preload", None)
        if callable(preload) and work_rows:
            try:
                preload([str(r.get("file_path") or "") for r in work_rows])
            except Exception as exc:
                log.warning("OCR batch file read failed: %s", exc)
        for r in work_rows:
            path = str(r.get("file_path") or "")
            try:
                data = read_file_fn(r["file_path"])
            except Exception:
                data = None
            payloads.append(
                {
                    "row": {"id": r["id"], "file_path": path},
                    "data": data,
                    "path": path,
                    "max_pages": ocr_page_budget,
                    "allow_photos": image_ev or forensic_photos_allowed(),
                }
            )

        inflight: dict = {}
        payload_iter = iter(payloads)

        def _fill(pool) -> None:
            while len(inflight) < cpu_n:
                try:
                    nxt = next(payload_iter)
                except StopIteration:
                    return
                inflight[pool.submit(_ocr_cpu_process_one, nxt)] = nxt

        with open_ocr_cpu_pool(cpu_n) as pool:
            _fill(pool)
            while inflight:
                finished, _ = wait(inflight, return_when=FIRST_COMPLETED)
                for fut in finished:
                    payload = inflight.pop(fut, None)
                    try:
                        result = fut.result()
                    except Exception as exc:
                        log.warning("CPU OCR worker failed: %s", exc)
                        continue
                    row = result.get("row") or {}
                    if result.get("status") == "ok" and result.get("text"):
                        log.info("OCR text-layer %s", row.get("file_path") or row.get("id"))
                        _persist_ocr_ok(
                            row,
                            str(result.get("text") or ""),
                            float(result.get("conf") or 0.0),
                            str(result.get("engine") or "pypdf"),
                        )
                        db.commit()
                        done += 1
                        continue
                    if result.get("status") == "needs_gpu":
                        needs_gpu_rows.append(dict(payload or {}) if payload else {"row": row})
                        continue
                    _mark_ocr_skip(row, engine=str(result.get("engine") or "na"))
                    db.commit()
                _fill(pool)

    if needs_gpu_rows and gpu:
        from app.services.job_locks import gpu_heavy_slot

        glm_ran = False
        # Never run GLM without a GPU permit.  Earlier fail-open behaviour let
        # OCR overlap RAG after a slot timeout, causing VRAM/thermal spikes.
        # The Celery drain catches GpuHeavySlotTimeout and requeues cleanly.
        from contextlib import ExitStack
        from app.services.gpu_thermal import release_gpu_model_after_task_enabled

        with ExitStack() as gpu_stack:
            got_gpu = True if gpu_permit_owned else gpu_stack.enter_context(
                gpu_heavy_slot(reason="ocr", wait_sec=8.0, fail_closed=True)
            )
            if release_gpu_model_after_task_enabled() and not gpu_permit_owned:
                # Free GLM before releasing the shared GPU permit so another
                # product never sees a free semaphore while this process retains VRAM.
                gpu_stack.callback(unload_glm_ocr)
            write_disk_log(
                db,
                job_id,
                (
                    f"OCR agent — GPU text detection on {len(needs_gpu_rows)} scan(s)/image(s)"
                ),
                stage="ocr",
                metadata={
                    "gpu": True,
                    "device": device_label,
                    "glm_docs": len(needs_gpu_rows),
                    "slot": bool(got_gpu),
                },
            )
            write_ocr_live_progress(
                db,
                job_id,
                label=f"GPU OCR — text detection, {len(needs_gpu_rows)} scan(s)",
            )
            from app.services.progress_agent import note_operation

            note_operation(
                db,
                job_id,
                "ocr",
                f"GPU text detection on {len(needs_gpu_rows)} images",
                timeout_seconds=900,
                advanced=True,
            )
            db.commit()
            glm_ran = True
            micro = _glm_micro_batch_size()
            write_disk_log(
                db,
                job_id,
                f"OCR agent — CUDA text detection, {micro} picture(s) at a time",
                stage="ocr",
            )
            db.commit()
            for start in range(0, len(needs_gpu_rows), micro):
                chunk = needs_gpu_rows[start : start + micro]
                prepared: list[tuple[dict, dict]] = []
                for payload in chunk:
                    row = (payload.get("row") or {}) if isinstance(payload, dict) else {}
                    path = str(payload.get("path") or row.get("file_path") or "")
                    data = payload.get("data")
                    if data is None:
                        try:
                            data = read_file_fn(path)
                        except Exception:
                            data = None
                    prep = cpu_prepare_ocr_item(
                        data or b"",
                        path=path,
                        max_pages=ocr_page_budget,
                        allow_photos=forensic_photos_allowed(),
                    )
                    prepared.append((payload, prep))
                image_jobs: list[tuple[int, object, str]] = []
                piece_lists: list[list[str]] = [[] for _ in prepared]
                conf_lists: list[list[float]] = [[] for _ in prepared]
                for prep_i, (_payload, prep) in enumerate(prepared):
                    if prep.get("status") == "cpu_done" and prep.get("text"):
                        piece_lists[prep_i].append(str(prep.get("text") or ""))
                        conf_lists[prep_i].append(float(prep.get("conf") or 0.9))
                        continue
                    for seg in prep.get("segments") or []:
                        if seg.get("type") == "text" and seg.get("text"):
                            piece_lists[prep_i].append(str(seg["text"]))
                            conf_lists[prep_i].append(0.90)
                            continue
                        img = seg.get("image")
                        if img is None:
                            continue
                        image_jobs.append((prep_i, img, str(seg.get("prompt") or "Text Recognition:")))
                grouped: dict[str, list[tuple[int, object]]] = {}
                for prep_i, img, prompt in image_jobs:
                    grouped.setdefault(prompt, []).append((prep_i, img))
                for prompt, jobs in grouped.items():
                    try:
                        decoded = _glm_ocr_images([img for _i, img in jobs], prompt=prompt)
                    except Exception as exc:
                        log.warning("GPU OCR batch failed: %s", exc)
                        decoded = [("", 0.0) for _ in jobs]
                    for (prep_i, _img), (text, conf) in zip(jobs, decoded):
                        if text:
                            piece_lists[prep_i].append(text)
                            conf_lists[prep_i].append(conf)
                for (payload, prep), pieces, confs in zip(prepared, piece_lists, conf_lists):
                    row = (payload.get("row") or {}) if isinstance(payload, dict) else {}
                    path = str(payload.get("path") or row.get("file_path") or "")
                    if pieces:
                        text = "\n\n".join(pieces)
                        conf = sum(confs) / len(confs) if confs else 0.0
                        _persist_ocr_ok(row, text, conf, "easyocr" if prep.get("status") != "cpu_done" else str(prep.get("engine") or "pypdf"))
                        db.commit()
                        done += 1
                    elif prep.get("status") == "skip":
                        _mark_ocr_skip(row, engine=str(prep.get("engine") or "na"))
                        db.commit()
                    else:
                        _mark_ocr_skip(row, engine="ocr_empty")
                        db.commit()
                    write_ocr_live_progress(db, job_id)
                    db.commit()
        gpu_deferred = bool(needs_gpu_rows) and not glm_ran
    elif needs_gpu_rows and not gpu:
        defer_msg, handed_off = handoff_glm_scans_to_cuda_worker(
            schema_name,
            job_id,
            len(needs_gpu_rows),
            cpu_bucket=ocr_bucket is not None,
        )
        write_disk_log(
            db,
            job_id,
            defer_msg,
            stage="ocr",
            metadata={
                "gpu": False,
                "glm_pending": len(needs_gpu_rows),
                "cpu_bucket": ocr_bucket is not None,
                "handed_to_cuda": handed_off,
            },
        )
        db.commit()
        gpu_deferred = True
    else:
        gpu_deferred = False

    pending_left = count_pending_ocr(
        db, job_id, ocr_bucket=ocr_bucket, ocr_buckets=ocr_buckets
    )
    lane = "GPU" if gpu else "CPU"
    write_disk_log(
        db,
        job_id,
        f"{lane} OCR batch — {done} document(s) on {device_label}"
        + (f"; {pending_left:,} still pending" if pending_left else " (queue empty)"),
        stage="ocr",
        metadata={"gpu": gpu, "device": device_label, "pending_left": pending_left},
    )
    db.commit()
    return {
        "status": "ok",
        "ocr_count": done,
        "engine": "easyocr" if gpu else "cpu-ocr",
        "gpu": gpu,
        "device": device_label,
        "pending_left": pending_left,
        "skipped_noise": skipped_noise,
        "gpu_deferred": bool(gpu_deferred),
        "reason": "",
    }
