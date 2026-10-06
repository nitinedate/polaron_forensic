-- Additive Image Evidence RAG tables (HLD) — never drops existing evidence.
-- Usage: SELECT public.apply_firm_rag_image_evidence('firm_acme');

CREATE OR REPLACE FUNCTION public.apply_firm_rag_image_evidence(schema_name text)
RETURNS VOID AS $$
BEGIN
    EXECUTE format($sql$
        ALTER TABLE %I.jobs
            ADD COLUMN IF NOT EXISTS rag_selection_session_id UUID,
            ADD COLUMN IF NOT EXISTS rag_processing_profile TEXT NOT NULL DEFAULT 'STANDARD',
            ADD COLUMN IF NOT EXISTS job_kind TEXT NOT NULL DEFAULT 'forensic'
    $sql$, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.rag_selection_sessions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            case_id UUID,
            job_id UUID,
            created_by UUID,
            status TEXT NOT NULL DEFAULT 'open',
            processing_profile TEXT NOT NULL DEFAULT 'STANDARD',
            root_labels JSONB NOT NULL DEFAULT '[]'::jsonb,
            selected_count INTEGER NOT NULL DEFAULT 0,
            selected_bytes BIGINT NOT NULL DEFAULT 0,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            committed_at TIMESTAMPTZ
        )
    $sql$, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.rag_selection_manifest_items (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            session_id UUID NOT NULL REFERENCES %I.rag_selection_sessions(id) ON DELETE CASCADE,
            node_id TEXT NOT NULL,
            parent_node_id TEXT,
            node_type TEXT NOT NULL,
            root_label TEXT,
            relative_path TEXT NOT NULL,
            name TEXT NOT NULL,
            selected BOOLEAN NOT NULL DEFAULT FALSE,
            selection_state TEXT NOT NULL DEFAULT 'unchecked',
            size_bytes BIGINT,
            mime_type TEXT,
            preview_status TEXT NOT NULL DEFAULT 'not_requested',
            ingest_status TEXT NOT NULL DEFAULT 'pending',
            sha256 TEXT,
            source_object_uri TEXT,
            image_asset_id UUID,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (session_id, node_id)
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE INDEX IF NOT EXISTS rag_manifest_session_selected_idx
            ON %I.rag_selection_manifest_items (session_id)
            WHERE selected = TRUE
    $sql$, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.rag_image_assets (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            case_id UUID,
            job_id UUID,
            selection_session_id UUID,
            job_artifact_id UUID,
            root_label TEXT,
            relative_path TEXT NOT NULL,
            folder_path TEXT,
            filename TEXT NOT NULL,
            extension TEXT,
            sha256 TEXT,
            file_size BIGINT,
            source_object_uri TEXT,
            mime_type TEXT,
            format TEXT,
            width INTEGER,
            height INTEGER,
            orientation INTEGER,
            exif_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            filesystem_mtime TIMESTAMPTZ,
            exif_taken_at TIMESTAMPTZ,
            gps_lat DOUBLE PRECISION,
            gps_lon DOUBLE PRECISION,
            thumbnail_uri TEXT,
            ocr_text TEXT,
            ocr_boxes JSONB NOT NULL DEFAULT '[]'::jsonb,
            ocr_confidence REAL,
            ocr_engine TEXT,
            ocr_engine_version TEXT,
            ocr_status TEXT NOT NULL DEFAULT 'pending',
            ai_description TEXT,
            ai_description_model TEXT,
            stage_status TEXT NOT NULL DEFAULT 'registered',
            retry_count INTEGER NOT NULL DEFAULT 0,
            parser_fingerprint TEXT,
            completion_marker TEXT,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name);

    EXECUTE format($sql$
        CREATE INDEX IF NOT EXISTS rag_image_assets_job_idx
            ON %I.rag_image_assets (job_id)
    $sql$, schema_name);

    EXECUTE format($sql$
        CREATE INDEX IF NOT EXISTS rag_image_assets_sha256_idx
            ON %I.rag_image_assets (sha256)
            WHERE sha256 IS NOT NULL
    $sql$, schema_name);

    EXECUTE format($sql$
        CREATE INDEX IF NOT EXISTS rag_image_assets_ocr_fts_idx
            ON %I.rag_image_assets
            USING GIN (to_tsvector('english', coalesce(ocr_text, '') || ' ' || coalesce(filename, '') || ' ' || coalesce(relative_path, '')))
    $sql$, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.rag_image_embeddings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            image_id UUID NOT NULL REFERENCES %I.rag_image_assets(id) ON DELETE CASCADE,
            modality TEXT NOT NULL,
            model_name TEXT NOT NULL,
            model_version TEXT NOT NULL DEFAULT '1',
            dimensions INTEGER NOT NULL,
            embedding vector,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (image_id, modality, model_name, model_version)
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE INDEX IF NOT EXISTS rag_image_embeddings_image_idx
            ON %I.rag_image_embeddings (image_id, modality)
    $sql$, schema_name);

    -- Soft FK from jobs.rag_selection_session_id (avoid circular CREATE TABLE order issues)
    BEGIN
        EXECUTE format(
            'ALTER TABLE %I.jobs ADD CONSTRAINT jobs_rag_selection_session_fk
             FOREIGN KEY (rag_selection_session_id) REFERENCES %I.rag_selection_sessions(id)
             ON DELETE SET NULL',
            schema_name, schema_name
        );
    EXCEPTION
        WHEN duplicate_object THEN NULL;
        WHEN undefined_table THEN NULL;
    END;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION public.apply_firm_rag_image_evidence_all()
RETURNS VOID AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT schema_name FROM public.firms WHERE schema_name IS NOT NULL LOOP
        PERFORM public.apply_firm_rag_image_evidence(r.schema_name);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

SELECT public.apply_firm_rag_image_evidence_all();
