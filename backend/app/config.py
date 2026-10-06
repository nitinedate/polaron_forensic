from functools import lru_cache
import json

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # forensic | mobile-extract | vuln — each process is one product.
    aetheris_service: str = Field(default="forensic", validation_alias="AETHERIS_SERVICE")

    database_url: str = "postgresql+psycopg2://forensic:forensic@localhost:5434/forensic"
    jwt_secret: str = "dev-secret-change-in-production"
    jwt_access_ttl_minutes: int = 30
    jwt_refresh_ttl_days: int = 0
    # Same value on forensic, mobile-extract, and vuln so the emailed token matches.
    client_token_secret: str = Field(default="", validation_alias="CLIENT_TOKEN_SECRET")
    forensic_app_url: str = Field(default="http://localhost:3000", validation_alias="FORENSIC_APP_URL")
    mobile_extract_app_url: str = Field(default="http://localhost:3000", validation_alias="MOBILE_EXTRACT_APP_URL")
    vuln_app_url: str = Field(default="http://localhost:3000", validation_alias="VULN_APP_URL")

    mail_host: str = Field(default="localhost", validation_alias=AliasChoices("MAIL_HOST", "SMTP_HOST"))
    mail_port: int = Field(default=1025, validation_alias=AliasChoices("MAIL_PORT", "SMTP_PORT"))
    mail_username: str = Field(default="", validation_alias=AliasChoices("MAIL_USERNAME", "SMTP_USERNAME"))
    mail_password: str = Field(default="", validation_alias=AliasChoices("MAIL_PASSWORD", "SMTP_PASSWORD"))
    mail_from: str = Field(default="noreply@forensic.local", validation_alias=AliasChoices("MAIL_FROM", "SMTP_FROM"))
    mail_smtp_auth: bool = Field(default=False, validation_alias=AliasChoices("MAIL_SMTP_AUTH", "SMTP_AUTH"))
    mail_smtp_starttls: bool = Field(
        default=False, validation_alias=AliasChoices("MAIL_SMTP_STARTTLS", "SMTP_STARTTLS")
    )
    # None selects implicit TLS automatically on port 465.
    mail_smtp_ssl: bool | None = Field(
        default=None, validation_alias=AliasChoices("MAIL_SMTP_SSL", "SMTP_SSL")
    )
    # Only the identity API (Forensic / gateway login) should email users.
    mail_send_enabled: bool = Field(default=True, validation_alias="MAIL_SEND_ENABLED")

    app_base_url: str = "http://localhost:3000"
    platform_admin_email: str = "superadmin@admin.com"
    platform_admin_password: str = "admin@123456789"
    platform_tenant_slug: str = "platform"

    redis_url: str = Field(default="redis://localhost:6380/0", validation_alias="REDIS_URL")
    # Optional shared Redis used only for host-level adaptive semaphores. Point
    # forensic + mobile-extract stacks at the same URL when they share one GPU/CPU.
    resource_governor_redis_url: str = Field(default="", validation_alias="RESOURCE_GOVERNOR_REDIS_URL")
    resource_governor_enabled: bool = Field(default=True, validation_alias="RESOURCE_GOVERNOR_ENABLED")
    resource_governor_group: str = Field(default="aetheris-host", validation_alias="RESOURCE_GOVERNOR_GROUP")
    # If the shared host-level governor Redis is temporarily unreachable, CPU/I/O
    # forensic extraction may continue under the product-local Redis/thermal lease.
    # Capacity exhaustion still fails closed; this applies only to governor transport/DNS outages.
    resource_governor_fail_open_on_unavailable: bool = Field(
        default=True, validation_alias="RESOURCE_GOVERNOR_FAIL_OPEN_ON_UNAVAILABLE"
    )

    minio_endpoint: str = Field(default="localhost:9000", validation_alias="MINIO_ENDPOINT")
    minio_access_key: str = Field(default="minioadmin", validation_alias="MINIO_ACCESS_KEY")
    minio_secret_key: str = Field(default="minioadmin", validation_alias="MINIO_SECRET_KEY")
    minio_secure: bool = Field(default=False, validation_alias="MINIO_SECURE")
    minio_bucket: str = Field(default="forensic", validation_alias="MINIO_BUCKET")

    data_root: str = Field(default="./data", validation_alias="DATA_ROOT")
    host_data_root: str = Field(default="", validation_alias="HOST_DATA_ROOT")
    host_evidence_enabled: bool = Field(default=True, validation_alias="HOST_EVIDENCE_ENABLED")
    host_evidence_root: str = Field(default="", validation_alias="HOST_EVIDENCE_ROOT")
    host_drive_map: str = Field(default="", validation_alias="HOST_DRIVE_MAP")
    host_path_mappings: str = Field(default="", validation_alias="HOST_PATH_MAPPINGS")

    extract_disk_workers: int = Field(default=4, validation_alias="EXTRACT_DISK_WORKERS")
    list_folder_workers: int = Field(default=16, validation_alias="LIST_FOLDER_WORKERS")
    list_folder_max_entries: int = Field(default=500_000, validation_alias="LIST_FOLDER_MAX_ENTRIES")
    # Wall-clock cap for a deep List folder walk (seconds). 0 disables the cap.
    list_folder_max_seconds: float = Field(default=900.0, validation_alias="LIST_FOLDER_MAX_SECONDS")
    # Parallel readers for mobile folder/ZIP dumps (not E01). Folder iOS backups use up to 16.
    extract_mobile_workers: int = Field(default=8, validation_alias="EXTRACT_MOBILE_WORKERS")
    # How many sequential MinIO parts to emit (Phase 3 can start after each on NVMe).
    extract_shard_count: int = Field(default=8, validation_alias="EXTRACT_SHARD_COUNT")
    extract_upload_concurrency: int = Field(default=4, validation_alias="EXTRACT_UPLOAD_CONCURRENCY")
    extract_zstd_level: int = Field(default=1, validation_alias="EXTRACT_ZSTD_LEVEL")
    extract_mode: str = Field(default="defensible", validation_alias="EXTRACT_MODE")
    extract_max_file_bytes: int = Field(default=104_857_600, validation_alias="EXTRACT_MAX_FILE_BYTES")
    extract_uncertain_max_bytes: int = Field(default=4_194_304, validation_alias="EXTRACT_UNCERTAIN_MAX_BYTES")
    extract_hash_files: bool = Field(default=False, validation_alias="EXTRACT_HASH_FILES")
    extract_progress_step: int = Field(default=2000, validation_alias="EXTRACT_PROGRESS_STEP")
    extract_stop_check_interval: int = Field(default=500, validation_alias="EXTRACT_STOP_CHECK_INTERVAL")
    extract_tar_bufsize: int = Field(default=1_048_576, validation_alias="EXTRACT_TAR_BUFSIZE")
    extract_progress_flush_sec: float = Field(default=15.0, validation_alias="EXTRACT_PROGRESS_FLUSH_SEC")
    extract_progress_log_sec: float = Field(default=30.0, validation_alias="EXTRACT_PROGRESS_LOG_SEC")
    # When false (default), full mode keeps WinSxS/DriverStore/etc. for complete artifact coverage.
    # Windows full mode always keeps critical system trees regardless of this flag.
    extract_skip_system_paths: bool = Field(default=False, validation_alias="EXTRACT_SKIP_SYSTEM_PATHS")
    # One active E01 extract keeps I/O sequential and host cooler; raise only for multi-case labs.
    max_concurrent_disk_builds: int = Field(default=2, validation_alias="MAX_CONCURRENT_DISK_BUILDS")
    # When true, resume discards incomplete hash-shard layout and replans with path_range (re-extracts).
    # Use after upgrading extract performance; all forensic files are still extracted — nothing skipped.
    extract_replan_on_resume: bool = Field(default=False, validation_alias="EXTRACT_REPLAN_ON_RESUME")
    # Parse drain: bounded rounds per Celery task — re-queue when pending remains (avoids 90min locks).
    parse_drain_max_rounds: int = Field(default=25, validation_alias="PARSE_DRAIN_MAX_ROUNDS")
    parse_batch_limit: int = Field(default=8000, validation_alias="PARSE_BATCH_LIMIT")
    parse_drain_batch_limit: int = Field(default=1200, validation_alias="PARSE_DRAIN_BATCH_LIMIT")
    parse_file_timeout_sec: int = Field(default=0, validation_alias="PARSE_FILE_TIMEOUT_SEC")
    # Skip full parse for large non-critical .evtx (Security/System/Application still parsed).
    parse_evtx_max_bytes: int = Field(default=6_000_000, validation_alias="PARSE_EVTX_MAX_BYTES")
    # Cap bytes read from storage for metadata-only / unknown binaries (never used for forensic paths).
    parse_metadata_max_bytes: int = Field(default=65_536, validation_alias="PARSE_METADATA_MAX_BYTES")
    parse_text_max_bytes: int = Field(default=512_000, validation_alias="PARSE_TEXT_MAX_BYTES")
    # Soft threshold for bulk-skipping non-forensic oversized files (forensic paths are exempt).
    parse_max_file_bytes: int = Field(default=50_000_000, validation_alias="PARSE_MAX_FILE_BYTES")
    # Absolute ceiling for a single non-forensic known-parser read (forensic = unlimited via exemption).
    parse_hard_max_bytes: int = Field(default=512_000_000, validation_alias="PARSE_HARD_MAX_BYTES")
    parse_workers: int = Field(default=12, validation_alias="PARSE_WORKERS")
    parse_parallel_enabled: bool = Field(default=True, validation_alias="PARSE_PARALLEL_ENABLED")
    parse_db_commit_batch: int = Field(default=75, validation_alias="PARSE_DB_COMMIT_BATCH")
    parse_parallel_buckets: int = Field(default=4, validation_alias="PARSE_PARALLEL_BUCKETS")
    parse_bucket_min_pending: int = Field(default=2000, validation_alias="PARSE_BUCKET_MIN_PENDING")
    parse_drain_forensic_only: bool = Field(default=True, validation_alias="PARSE_DRAIN_FORENSIC_ONLY")
    parse_drain_interleave_rag: bool = Field(default=False, validation_alias="PARSE_DRAIN_INTERLEAVE_RAG")
    parse_drain_requeue_no_parser: bool = Field(default=False, validation_alias="PARSE_DRAIN_REQUEUE_NO_PARSER")
    # Sample cap for RAG/parse browser URL extraction (inventory uses separate limits).
    browser_url_parse_limit: int = Field(default=5000, validation_alias="BROWSER_URL_PARSE_LIMIT")
    # Max bytes written to temp SQLite file during parse (History DBs can exceed 80 MiB).
    parse_sqlite_max_bytes: int = Field(default=512_000_000, validation_alias="PARSE_SQLITE_MAX_BYTES")
    parse_whatsapp_msg_limit: int = Field(default=500, validation_alias="PARSE_WHATSAPP_MSG_LIMIT")
    parse_evtx_account_limit: int = Field(default=5000, validation_alias="PARSE_EVTX_ACCOUNT_LIMIT")
    browser_inventory_url_limit: int = Field(default=50_000, validation_alias="BROWSER_INVENTORY_URL_LIMIT")
    browser_inventory_source_limit: int = Field(default=80, validation_alias="BROWSER_INVENTORY_SOURCE_LIMIT")
    browser_inventory_max_db_bytes: int = Field(default=512_000_000, validation_alias="BROWSER_INVENTORY_MAX_DB_BYTES")
    rag_embedding_model: str = Field(
        default="BAAI/bge-m3", validation_alias="RAG_EMBEDDING_MODEL"
    )
    rag_embedding_fallback: str = Field(
        default="nomic-embed-text", validation_alias="RAG_EMBEDDING_FALLBACK"
    )
    rag_embedding_dim: int = Field(default=1024, validation_alias="RAG_EMBEDDING_DIM")
    rag_embedding_device: str = Field(default="cuda", validation_alias="RAG_EMBEDDING_DEVICE")
    rag_batch_size: int = Field(default=16, validation_alias="RAG_BATCH_SIZE")
    rag_batch_size_cap: int = Field(default=16, validation_alias="RAG_BATCH_SIZE_CAP")
    rag_cuda_memory_fraction: float = Field(default=0.40, validation_alias="RAG_CUDA_MEMORY_FRACTION")
    rag_auto_after_disk: bool = Field(default=False, validation_alias="RAG_AUTO_AFTER_DISK")
    # Forensic cases do not need vector embeddings; opt in only for semantic Q&A.
    rag_embedding_enabled: bool = Field(default=False, validation_alias="RAG_EMBEDDING_ENABLED")
    rag_chunk_size: int = Field(default=2200, validation_alias="RAG_CHUNK_SIZE")
    rag_chunk_overlap: int = Field(default=200, validation_alias="RAG_CHUNK_OVERLAP")
    rag_rerank_enabled: bool = Field(default=False, validation_alias="RAG_RERANK_ENABLED")
    # When false, stop after baseline RAG (~500+ chunks) — Q&A ready without embedding full corpus.
    rag_background_after_baseline: bool = Field(
        default=False, validation_alias="RAG_BACKGROUND_AFTER_BASELINE"
    )
    # After baseline: never run background corpus RAG while OCR documents remain.
    # Prevents bge-m3 ↔ GLM-OCR model thrash on one laptop GPU (main bottleneck).
    defer_background_rag_while_ocr: bool = Field(
        default=False, validation_alias="DEFER_BACKGROUND_RAG_WHILE_OCR"
    )
    # Image Evidence RAG (HLD) — additive multimodal path on agentic base
    rag_image_embed_enabled: bool = Field(default=False, validation_alias="RAG_IMAGE_EMBED_ENABLED")
    rag_image_embed_model: str = Field(default="clip-ViT-B-32", validation_alias="RAG_IMAGE_EMBED_MODEL")
    rag_image_embed_dim: int = Field(default=512, validation_alias="RAG_IMAGE_EMBED_DIM")
    rag_image_embed_batch_size: int = Field(default=8, validation_alias="RAG_IMAGE_EMBED_BATCH_SIZE")
    rag_default_processing_profile: str = Field(
        default="STANDARD", validation_alias="RAG_DEFAULT_PROCESSING_PROFILE"
    )
    # High-quality OCR page/token budget for image-evidence jobs
    rag_image_ocr_max_pages: int = Field(default=200, validation_alias="RAG_IMAGE_OCR_MAX_PAGES")
    rag_image_ocr_max_new_tokens: int = Field(default=2048, validation_alias="RAG_IMAGE_OCR_MAX_NEW_TOKENS")

    ollama_base_url: str = Field(default="http://ollama:11434", validation_alias="OLLAMA_BASE_URL")
    # Laptop-safe defaults (12GB VRAM): avoid 32b/70b which force GPU 100% and thermal shutdown.
    llm_primary_model: str = Field(default="qwen2.5:14b", validation_alias="LLM_PRIMARY_MODEL")
    llm_review_model: str = Field(default="deepseek-r1:14b", validation_alias="LLM_REVIEW_MODEL")
    llm_review_model_large: str = Field(default="deepseek-r1:14b", validation_alias="LLM_REVIEW_MODEL_LARGE")
    llm_fast_model: str = Field(default="qwen3.5:9b", validation_alias="LLM_FAST_MODEL")
    # 12GB VRAM app-role set only (no 15GB+ / 27b / 32b / 70b).
    ollama_pull_models: str = Field(
        default=(
            "qwen2.5:14b,qwen2.5:7b,deepseek-r1:14b,"
            "llama3.1:8b,gemma4:12b,qwen3.5:9b,nomic-embed-text"
        ),
        validation_alias="OLLAMA_PULL_MODELS",
    )
    llm_dual_review_enabled: bool = Field(default=True, validation_alias="LLM_DUAL_REVIEW_ENABLED")
    llm_dual_review_sections: str = Field(
        default="objectives_procedure_observation,final_analysis_summary,artifact_summary,evidence_details",
        validation_alias="LLM_DUAL_REVIEW_SECTIONS",
    )
    llm_vram_profile: str = Field(default="recommended", validation_alias="LLM_VRAM_PROFILE")
    gap_report_llm_enabled: bool = Field(default=True, validation_alias="GAP_REPORT_LLM_ENABLED")
    gap_report_llm_model: str = Field(default="qwen2.5:7b", validation_alias="GAP_REPORT_LLM_MODEL")
    # Mobile report findings → simple client language (no paths / jargon).
    mobile_report_llm_enabled: bool = Field(default=True, validation_alias="MOBILE_REPORT_LLM_ENABLED")
    mobile_report_llm_model: str = Field(default="qwen2.5:14b", validation_alias="MOBILE_REPORT_LLM_MODEL")
    mobile_report_llm_fallback_model: str = Field(
        default="llama3.1:8b", validation_alias="MOBILE_REPORT_LLM_FALLBACK_MODEL"
    )
    # Extra models tried for plain-language rewrite (comma-separated).
    mobile_report_llm_models: str = Field(
        default="qwen2.5:14b,gemma4:12b,qwen3.5:9b,llama3.1:8b,qwen2.5:7b",
        validation_alias="MOBILE_REPORT_LLM_MODELS",
    )

    neo4j_uri: str = Field(default="bolt://neo4j:7687", validation_alias="NEO4J_URI")
    neo4j_user: str = Field(default="neo4j", validation_alias="NEO4J_USER")
    neo4j_password: str = Field(default="forensic123", validation_alias="NEO4J_PASSWORD")

    opensearch_url: str = Field(default="http://opensearch:9200", validation_alias="OPENSEARCH_URL")
    opensearch_index_prefix: str = Field(default="forensic", validation_alias="OPENSEARCH_INDEX_PREFIX")

    # When true (default), workers/API probe host room and retune concurrency/batch/thermal knobs.
    dynamic_perf_enabled: bool = Field(default=True, validation_alias="DYNAMIC_PERF_ENABLED")
    dynamic_perf_force: bool = Field(default=False, validation_alias="DYNAMIC_PERF_FORCE")
    # Comma-separated env keys that dynamic tuning must never overwrite (hard ceilings).
    dynamic_perf_lock: str = Field(
        default="PARSE_WORKERS,PARSE_PARALLEL_BUCKETS,PARSE_PARALLEL_ENABLED,PARSE_DRAIN_BATCH_LIMIT,PARSE_DRAIN_MAX_ROUNDS,PARSE_DRAIN_INTERLEAVE_RAG,FORENSIC_WORKER_CONCURRENCY,MAX_CONCURRENT_DISK_BUILDS,RAG_BATCH_SIZE,RAG_BATCH_SIZE_CAP,RAG_CUDA_MEMORY_FRACTION,OCR_BATCH_LIMIT,OCR_CPU_WORKERS,OCR_DEVICE,AXIOM_INVENTORY_WORKERS,AXIOM_INVENTORY_BATCH_SIZE,EXTRACT_MOBILE_WORKERS,GPU_HEAVY_MAX_CONCURRENT",
        validation_alias="DYNAMIC_PERF_LOCK",
    )
    # adaptive = cool path uses .env ceilings, heat only decreases; respect_env = never raise above env.
    perf_policy_mode: str = Field(default="throughput", validation_alias="PERF_POLICY_MODE")
    # Optional fast-LLM confirmation of the live plan when GPU is idle (default off).
    perf_llm_advisor: bool = Field(default=False, validation_alias="PERF_LLM_ADVISOR")
    # When true, laptop GPU clamp will not lower user .env thermal ceilings.
    gpu_thermal_honor_env: bool = Field(default=True, validation_alias="GPU_THERMAL_HONOR_ENV")
    ocr_enabled: bool = Field(default=True, validation_alias="OCR_ENABLED")
    ocr_engine: str = Field(default="glm-ocr", validation_alias="OCR_ENGINE")
    ocr_model: str = Field(default="zai-org/GLM-OCR", validation_alias="OCR_MODEL")
    ocr_device: str = Field(default="auto", validation_alias="OCR_DEVICE")
    # Exclusive OCR slot may use more VRAM than RAG's tight laptop cap.
    ocr_cuda_memory_fraction: float = Field(default=0.45, validation_alias="OCR_CUDA_MEMORY_FRACTION")
    ocr_max_pages: int = Field(default=8, validation_alias="OCR_MAX_PAGES")
    ocr_max_new_tokens: int = Field(default=512, validation_alias="OCR_MAX_NEW_TOKENS")
    ocr_max_image_edge: int = Field(default=1280, validation_alias="OCR_MAX_IMAGE_EDGE")
    # CPU threads that decode/render/extract text while GLM runs on GPU.
    ocr_cpu_workers: int = Field(default=6, validation_alias="OCR_CPU_WORKERS")
    # Celery processes on the OCR queue. GPU-only OCR uses solo/1.
    ocr_celery_concurrency: int = Field(default=1, validation_alias="OCR_CELERY_CONCURRENCY")
    # 0 = never fan CPU OCR buckets. OCR runs only on worker-ocr-gpu.
    ocr_parallel_buckets: int = Field(default=0, validation_alias="OCR_PARALLEL_BUCKETS")
    ocr_gpu_only: bool = Field(default=True, validation_alias="OCR_GPU_ONLY")
    # Skip a page/document if GLM generate exceeds this (seconds).
    ocr_max_infer_sec: int = Field(default=90, validation_alias="OCR_MAX_INFER_SEC")
    # Thermal-safe GPU OCR batch size (requeues until pending cleared).
    ocr_batch_limit: int = Field(default=32, validation_alias="OCR_BATCH_LIMIT")
    ocr_drain_max_rounds: int = Field(default=25, validation_alias="OCR_DRAIN_MAX_ROUNDS")
    # When true, skip camera rolls / Pictures / screenshots and keep PDFs + Documents only.
    # GLM then runs only on scanned PDFs and document-folder images with no text layer.
    ocr_documents_only: bool = Field(default=True, validation_alias="OCR_DOCUMENTS_ONLY")
    phase3_auto_after_disk: bool = Field(default=True, validation_alias="PHASE3_AUTO_AFTER_DISK")
    # Accuracy/performance barrier: complete the evidence image walk + extraction
    # exactly once before materialize/OCR/parse/RAG/inventory are allowed to run.
    # This avoids I/O/CPU contention and makes Job Detail progress deterministic.
    extract_then_process: bool = Field(default=True, validation_alias="EXTRACT_THEN_PROCESS")
    # Legacy opt-in only. EXTRACT_THEN_PROCESS=true is the normal forensic mode.
    phase3_stream_during_extract: bool = Field(default=False, validation_alias="PHASE3_STREAM_DURING_EXTRACT")
    # When false, GPU RAG waits until extract finishes (prevents thermal shutdown on laptops).
    phase3_stream_rag_during_extract: bool = Field(default=False, validation_alias="PHASE3_STREAM_RAG_DURING_EXTRACT")
    phase3_stream_ocr_during_extract: bool = Field(default=False, validation_alias="PHASE3_STREAM_OCR_DURING_EXTRACT")

    # GPU thermal governor — keep working when the card is merely warm.
    # Laptop OEM shutdown is typically ~95–100°C GPU / ~100°C CPU. Stay under that.
    gpu_thermal_enabled: bool = Field(default=True, validation_alias="GPU_THERMAL_ENABLED")
    gpu_thermal_pause_c: int = Field(default=92, validation_alias="GPU_THERMAL_PAUSE_C")
    gpu_thermal_resume_c: int = Field(default=84, validation_alias="GPU_THERMAL_RESUME_C")
    gpu_thermal_throttle_c: int = Field(default=87, validation_alias="GPU_THERMAL_THROTTLE_C")
    gpu_thermal_start_max_c: int = Field(default=90, validation_alias="GPU_THERMAL_START_MAX_C")
    gpu_thermal_poll_sec: float = Field(default=2.0, validation_alias="GPU_THERMAL_POLL_SEC")
    gpu_thermal_hot_batch_sleep_sec: float = Field(default=6.0, validation_alias="GPU_THERMAL_HOT_BATCH_SLEEP_SEC")
    gpu_thermal_embed_rest_sec: float = Field(default=1.0, validation_alias="GPU_THERMAL_EMBED_REST_SEC")
    gpu_thermal_duty_cycle_batches: int = Field(default=3, validation_alias="GPU_THERMAL_DUTY_CYCLE_BATCHES")
    gpu_thermal_duty_cycle_rest_sec: float = Field(default=5.0, validation_alias="GPU_THERMAL_DUTY_CYCLE_REST_SEC")
    gpu_thermal_adaptive_batch: bool = Field(default=True, validation_alias="GPU_THERMAL_ADAPTIVE_BATCH")
    gpu_thermal_cool_boost_c: int = Field(default=50, validation_alias="GPU_THERMAL_COOL_BOOST_C")
    gpu_thermal_cool_batch_multiplier: float = Field(
        default=1.10, validation_alias="GPU_THERMAL_COOL_BATCH_MULTIPLIER"
    )
    gpu_thermal_power_limit_w: int | None = Field(default=70, validation_alias="GPU_THERMAL_POWER_LIMIT_W")
    gpu_thermal_unload_ollama_before_rag: bool = Field(
        default=True, validation_alias="GPU_THERMAL_UNLOAD_OLLAMA_BEFORE_RAG"
    )
    gpu_thermal_fallback_duty: bool = Field(default=True, validation_alias="GPU_THERMAL_FALLBACK_DUTY")
    gpu_thermal_rise_delta_c: int = Field(default=5, validation_alias="GPU_THERMAL_RISE_DELTA_C")
    gpu_thermal_rise_window_sec: float = Field(default=15.0, validation_alias="GPU_THERMAL_RISE_WINDOW_SEC")
    gpu_thermal_abort_c: int = Field(default=94, validation_alias="GPU_THERMAL_ABORT_C")
    # Independent GPU slots so OCR and RAG can run together (2 on 12GB+ cards).
    gpu_heavy_max_concurrent: int = Field(default=2, validation_alias="GPU_HEAVY_MAX_CONCURRENT")
    gpu_heavy_lock_wait_sec: float = Field(default=0.0, validation_alias="GPU_HEAVY_LOCK_WAIT_SEC")
    gpu_heavy_lock_ttl_sec: int = Field(default=600, validation_alias="GPU_HEAVY_LOCK_TTL_SEC")
    # CPU thermal — parse/parallelism backs off before chassis shutdown.
    cpu_thermal_throttle_c: int = Field(default=86, validation_alias="CPU_THERMAL_THROTTLE_C")
    cpu_thermal_pause_c: int = Field(default=94, validation_alias="CPU_THERMAL_PAUSE_C")

    pipeline_supervisor_enabled: bool = Field(default=True, validation_alias="PIPELINE_SUPERVISOR_ENABLED")
    pipeline_stale_sec: float = Field(default=55.0, validation_alias="PIPELINE_STALE_SEC")
    pipeline_supervisor_interval_sec: float = Field(default=30.0, validation_alias="PIPELINE_SUPERVISOR_INTERVAL_SEC")
    # Run pipeline stage agents strictly one group at a time (extract → parse → RAG → graph → enrich → inventory).
    pipeline_sequential_agents: bool = Field(default=False, validation_alias="PIPELINE_SEQUENTIAL_AGENTS")
    axiom_inventory_batch_size: int = Field(default=50, validation_alias="AXIOM_INVENTORY_BATCH_SIZE")
    axiom_inventory_workers: int = Field(default=2, validation_alias="AXIOM_INVENTORY_WORKERS")
    # Phase 1-40 artifact scope: drop non-evidence files at materialize; keep parser join sidecars.
    phase1_artifact_filter: bool = Field(default=True, validation_alias="PHASE1_ARTIFACT_FILTER")

    retrieval_rrf_k: int = Field(default=60, validation_alias="RETRIEVAL_RRF_K")
    retrieval_vector_weight: float = Field(default=1.0, validation_alias="RETRIEVAL_VECTOR_WEIGHT")
    retrieval_bm25_weight: float = Field(default=1.0, validation_alias="RETRIEVAL_BM25_WEIGHT")
    retrieval_default_top_k: int = Field(default=10, validation_alias="RETRIEVAL_DEFAULT_TOP_K")

    # Vulnerability / Nessus module (isolated from forensic extract/RAG)
    vuln_module_enabled: bool = Field(default=True, validation_alias="VULN_MODULE_ENABLED")
    nessus_api_timeout_sec: int = Field(default=0, validation_alias="NESSUS_API_TIMEOUT_SEC")
    nessus_verify_ssl: bool = Field(default=True, validation_alias="NESSUS_VERIFY_SSL")
    nessus_default_url: str = Field(default="", validation_alias="NESSUS_DEFAULT_URL")
    nessus_access_key: str = Field(default="", validation_alias="NESSUS_ACCESS_KEY")
    nessus_secret_key: str = Field(default="", validation_alias="NESSUS_SECRET_KEY")

    # Greenbone / OpenVAS GMP (built-in scanner — FR-1)
    gvm_host: str = Field(default="gvmd", validation_alias="GVM_HOST")
    gvm_port: int = Field(default=9390, validation_alias="GVM_PORT")
    gvm_url: str = Field(default="", validation_alias="GVM_URL")
    gvm_socket_path: str = Field(default="/run/gvmd/gvmd.sock", validation_alias="GVM_SOCKET_PATH")
    gvm_username: str = Field(default="admin", validation_alias="GVM_USERNAME")
    gvm_password: str = Field(default="", validation_alias="GVM_PASSWORD")
    gvm_admin_password: str = Field(default="admin", validation_alias="GVM_ADMIN_PASSWORD")
    gvm_verify_tls: bool = Field(default=False, validation_alias="GVM_VERIFY_TLS")
    gvm_live_enabled: bool = Field(default=False, validation_alias="GVM_LIVE_ENABLED")
    # Poll frequently so completed scans are noticed quickly.
    gvm_scan_poll_interval_sec: int = Field(default=5, validation_alias="GVM_SCAN_POLL_INTERVAL_SEC")
    # 0 = adaptive cap from port profile and host count (not unlimited).
    gvm_scan_timeout_sec: int = Field(default=0, validation_alias="GVM_SCAN_TIMEOUT_SEC")
    # Extra wait once progress is high; unused when scan timeout is 0.
    gvm_scan_near_complete_grace_sec: int = Field(
        default=0, validation_alias="GVM_SCAN_NEAR_COMPLETE_GRACE_SEC"
    )
    gvm_scan_near_complete_progress_pct: int = Field(
        default=85, validation_alias="GVM_SCAN_NEAR_COMPLETE_PROGRESS_PCT"
    )
    # 0 = adaptive stall harvest (do not wait forever at a stuck percent).
    gvm_scan_stall_progress_pct: int = Field(default=80, validation_alias="GVM_SCAN_STALL_PROGRESS_PCT")
    gvm_scan_stall_sec: int = Field(default=0, validation_alias="GVM_SCAN_STALL_SEC")
    # Performance: scan config name in Greenbone (Full and fast is the balanced default).
    gvm_scan_config: str = Field(default="Full and fast", validation_alias="GVM_SCAN_CONFIG")
    # How long a scan worker should wait when gvmd is reachable but feed
    # data objects (for example "Full and fast") are not imported yet.
    gvm_feed_ready_timeout_sec: int = Field(default=0, validation_alias="GVM_FEED_READY_TIMEOUT_SEC")
    gvm_feed_ready_poll_interval_sec: int = Field(default=15, validation_alias="GVM_FEED_READY_POLL_INTERVAL_SEC")
    # Port profile: full is the forensic-quality default.  Operators may explicitly
    # choose fast for a time-constrained authorized scan, but the default must not
    # silently miss services outside the common-port subset.
    gvm_port_profile: str = Field(default="full", validation_alias="GVM_PORT_PROFILE")
    # Optional override, e.g. T:1-1024,T:3306,T:3389,T:8080,T:8443
    gvm_target_port_range: str = Field(default="", validation_alias="GVM_TARGET_PORT_RANGE")
    # OpenVAS task parallelism (NVTs per host / concurrent hosts).
    gvm_max_checks: int = Field(default=20, validation_alias="GVM_MAX_CHECKS")
    gvm_max_hosts: int = Field(default=8, validation_alias="GVM_MAX_HOSTS")
    gvm_optimize_test: bool = Field(default=False, validation_alias="GVM_OPTIMIZE_TEST")
    # Keep safe checks on by default; operators may explicitly disable them only
    # in an authorized maintenance window because some VTs can disrupt services.
    gvm_safe_checks: bool = Field(default=True, validation_alias="GVM_SAFE_CHECKS")
    gvm_checks_read_timeout: int = Field(default=10, ge=1, validation_alias="GVM_CHECKS_READ_TIMEOUT")
    gvm_timeout_retry: int = Field(default=3, ge=0, validation_alias="GVM_TIMEOUT_RETRY")
    gvm_open_sock_max_attempts: int = Field(default=5, ge=0, validation_alias="GVM_OPEN_SOCK_MAX_ATTEMPTS")
    gvm_expand_vhosts: bool = Field(default=True, validation_alias="GVM_EXPAND_VHOSTS")
    gvm_test_empty_vhost: bool = Field(default=True, validation_alias="GVM_TEST_EMPTY_VHOST")
    gvm_allow_bare_task_fallback: bool = Field(default=False, validation_alias="GVM_ALLOW_BARE_TASK_FALLBACK")
    gvm_report_min_qod: int = Field(default=0, ge=0, le=100, validation_alias="GVM_REPORT_MIN_QOD")
    gvm_min_nvt_count: int = Field(default=10000, ge=1, validation_alias="GVM_MIN_NVT_COUNT")
    # 0 = do not cap individual NVT runtime (OpenVAS still needs a positive integer; we send 30d).
    gvm_plugins_timeout_sec: int = Field(default=0, validation_alias="GVM_PLUGINS_TIMEOUT_SEC")
    gvm_scanner_plugins_timeout_sec: int = Field(
        default=0, validation_alias="GVM_SCANNER_PLUGINS_TIMEOUT_SEC"
    )
    # Start OpenVAS then run nuclei/zap while it works (overlap wall-clock time).
    vuln_orch_overlap_enabled: bool = Field(default=True, validation_alias="VULN_ORCH_OVERLAP_ENABLED")

    # Multi-scanner orchestration (OpenVAS + Nmap + Nuclei + ZAP + Wazuh + Trivy)
    vuln_orchestration_enabled: bool = Field(default=True, validation_alias="VULN_ORCHESTRATION_ENABLED")
    # Parallel premise scan jobs across cases (capacity-gated; Celery worker concurrency).
    nessus_worker_concurrency: int = Field(default=4, validation_alias="NESSUS_WORKER_CONCURRENCY")
    vuln_max_parallel_jobs: int = Field(default=4, validation_alias="VULN_MAX_PARALLEL_JOBS")
    vuln_parallel_min_pace: float = Field(default=0.45, validation_alias="VULN_PARALLEL_MIN_PACE")
    vuln_allow_stub_findings: bool = Field(default=False, validation_alias="VULN_ALLOW_STUB_FINDINGS")
    zap_api_url: str = Field(default="", validation_alias="ZAP_API_URL")
    zap_api_key: str = Field(default="", validation_alias="ZAP_API_KEY")
    zap_scan_timeout_sec: int = Field(default=180, validation_alias="ZAP_SCAN_TIMEOUT_SEC")
    # Parallel aux scans across IPs inside one job (nuclei; nmap is multi-host).
    vuln_target_workers: int = Field(default=4, validation_alias="VULN_TARGET_WORKERS")
    # Parallel OpenVAS GMP tasks — one client IP per task.
    vuln_openvas_ip_workers: int = Field(default=4, validation_alias="VULN_OPENVAS_IP_WORKERS")
    wazuh_api_url: str = Field(default="", validation_alias="WAZUH_API_URL")
    wazuh_api_user: str = Field(default="", validation_alias="WAZUH_API_USER")
    wazuh_api_password: str = Field(default="", validation_alias="WAZUH_API_PASSWORD")
    wazuh_verify_tls: bool = Field(default=False, validation_alias="WAZUH_VERIFY_TLS")
    trivy_server_url: str = Field(default="", validation_alias="TRIVY_SERVER_URL")

    # PCI ASV external attestation workflow (FR-17 companion — not self-attestation)
    asv_module_enabled: bool = Field(default=True, validation_alias="ASV_MODULE_ENABLED")

    # Bounded pentest (safe recon only — not destructive exploitation)
    pentest_module_enabled: bool = Field(default=True, validation_alias="PENTEST_MODULE_ENABLED")

    # Endpoint inventory collection via agent (not behavioral EDR)
    edr_inventory_enabled: bool = Field(default=True, validation_alias="EDR_INVENTORY_ENABLED")

    # Forensic Agentic AI (isolated queue; does not change extract/vuln logic)
    agent_module_enabled: bool = Field(default=True, validation_alias="AGENT_MODULE_ENABLED")
    agent_max_steps: int = Field(default=6, validation_alias="AGENT_MAX_STEPS")
    agent_model: str = Field(default="", validation_alias="AGENT_MODEL")  # empty = llm_fast_model

    @property
    def llm_dual_review_section_set(self) -> set[str]:
        return {s.strip() for s in self.llm_dual_review_sections.split(",") if s.strip()}

    @field_validator("mail_password", mode="before")
    @classmethod
    def normalize_mail_password(cls, value: object) -> object:
        if isinstance(value, str):
            return value.replace(" ", "")
        return value

    @field_validator("extract_skip_system_paths", mode="before")
    @classmethod
    def coerce_extract_skip_system_paths(cls, value: object) -> object:
        if isinstance(value, str):
            v = value.strip().lower()
            if v in {"0", "false", "no", "off", ""}:
                return False
            if v in {"1", "true", "yes", "on"}:
                return True
        return value

    @property
    def smtp_host(self) -> str:
        return self.mail_host

    @property
    def smtp_port(self) -> int:
        return self.mail_port

    @property
    def smtp_from(self) -> str:
        return self.mail_from

    @property
    def host_drive_map_dict(self) -> dict[str, str]:
        if not self.host_drive_map.strip():
            return {}
        try:
            data = json.loads(self.host_drive_map)
            if isinstance(data, dict):
                return {str(k).lower(): str(v) for k, v in data.items()}
        except json.JSONDecodeError:
            pass
        out: dict[str, str] = {}
        for part in self.host_drive_map.split(","):
            part = part.strip()
            if not part or "=" not in part:
                continue
            key, val = part.split("=", 1)
            out[key.strip().lower()] = val.strip()
        return out

    @property
    def host_path_mappings_dict(self) -> dict[str, str]:
        if not self.host_path_mappings.strip():
            return {}
        try:
            data = json.loads(self.host_path_mappings)
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()}
        except json.JSONDecodeError:
            pass
        return {}


@lru_cache
def get_settings() -> Settings:
    return Settings()


def rag_embedding_is_enabled() -> bool:
    """Vector embedding is optional and off by default for forensic cases."""
    try:
        from app.services.forensic_serial_policy import serial_enabled
        if serial_enabled():
            return False
        return bool(getattr(get_settings(), "rag_embedding_enabled", False))
    except Exception:
        return False
