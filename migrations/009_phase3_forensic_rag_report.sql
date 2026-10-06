-- Phase 3: Encyclopedia (public), forensic evidence, dual RAG, report generation.

-- ---------------------------------------------------------------------------
-- Public encyclopedia (shared across firms)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.encyclopedia_artifacts (
    artifact_id TEXT PRIMARY KEY,
    artifact_name TEXT NOT NULL DEFAULT '',
    volume TEXT,
    section TEXT,
    category TEXT,
    subcategory TEXT,
    operating_system TEXT,
    supported_versions TEXT,
    default_paths TEXT,
    registry_keys TEXT,
    file_extensions TEXT,
    evidence_value TEXT,
    timeline_importance TEXT,
    acquisition_method TEXT,
    parser_recommendations TEXT,
    related_artifacts TEXT,
    neo4j_node_type TEXT,
    neo4j_relationships TEXT,
    mitre_attack TEXT,
    case_uco_mapping TEXT,
    nist_references TEXT,
    example_scenario TEXT,
    search_text TEXT,
    annotations JSONB NOT NULL DEFAULT '{}'::jsonb,
    raw_row JSONB,
    version_tag TEXT DEFAULT '1.0',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_enc_artifacts_os ON public.encyclopedia_artifacts(operating_system);
CREATE INDEX IF NOT EXISTS ix_enc_artifacts_category ON public.encyclopedia_artifacts(category);
CREATE INDEX IF NOT EXISTS ix_enc_artifacts_search ON public.encyclopedia_artifacts USING gin(to_tsvector('english', coalesce(search_text, '')));

CREATE TABLE IF NOT EXISTS public.encyclopedia_field_rows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id TEXT NOT NULL,
    supplement TEXT NOT NULL,
    field_name TEXT NOT NULL,
    where_found TEXT,
    source_artifact TEXT,
    notes TEXT,
    search_text TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_enc_field_supplement ON public.encyclopedia_field_rows(supplement);
CREATE UNIQUE INDEX IF NOT EXISTS ux_enc_field_row ON public.encyclopedia_field_rows (supplement, artifact_id, field_name);

CREATE TABLE IF NOT EXISTS public.encyclopedia_sections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    volume TEXT NOT NULL,
    title TEXT NOT NULL,
    intro_text TEXT,
    source_file TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.encyclopedia_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_artifact_id TEXT NOT NULL,
    to_artifact_id TEXT NOT NULL,
    relationship_type TEXT NOT NULL DEFAULT 'RELATED_TO',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- Per-firm Phase 3 tables
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.apply_firm_phase3(schema_name text)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    -- Phase 2.5 base table/columns required before Phase 3 ALTERs.
    PERFORM public.apply_firm_rag_gpu(schema_name);

    -- Extend rag_chunks for dual RAG (1024-dim BGE-M3 default)
    EXECUTE format(
        'ALTER TABLE %I.rag_chunks ADD COLUMN IF NOT EXISTS artifact_id TEXT',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.rag_chunks ADD COLUMN IF NOT EXISTS chunk_type TEXT DEFAULT ''evidence''',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.rag_chunks ADD COLUMN IF NOT EXISTS parent_chunk_id UUID',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.rag_chunks ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT ''{}''::jsonb',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.rag_chunks ADD COLUMN IF NOT EXISTS content_tsv tsvector',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.rag_chunks ADD COLUMN IF NOT EXISTS embedding_v2 vector(1024)',
        schema_name
    );

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.job_artifacts (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID NOT NULL REFERENCES %I.jobs(id) ON DELETE CASCADE,
            file_path TEXT NOT NULL,
            file_name TEXT,
            extension TEXT,
            size_bytes BIGINT DEFAULT 0,
            sha256 TEXT,
            encyclopedia_artifact_id TEXT,
            parse_status TEXT NOT NULL DEFAULT 'pending',
            ocr_status TEXT NOT NULL DEFAULT 'pending',
            minio_uri TEXT,
            attribution JSONB DEFAULT '{}'::jsonb,
            metadata JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(job_id, file_path)
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.artifact_parse_results (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_artifact_id UUID NOT NULL REFERENCES %I.job_artifacts(id) ON DELETE CASCADE,
            parser_name TEXT NOT NULL,
            parser_version TEXT,
            record_count INTEGER DEFAULT 0,
            byte_offset BIGINT,
            normalized JSONB,
            error TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.ocr_results (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_artifact_id UUID NOT NULL REFERENCES %I.job_artifacts(id) ON DELETE CASCADE,
            page_index INTEGER DEFAULT 0,
            ocr_text TEXT,
            confidence REAL,
            engine TEXT,
            preprocessing JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.parser_runs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID NOT NULL REFERENCES %I.jobs(id) ON DELETE CASCADE,
            parser_name TEXT NOT NULL,
            parser_version TEXT,
            files_processed INTEGER DEFAULT 0,
            files_skipped INTEGER DEFAULT 0,
            errors JSONB DEFAULT '[]'::jsonb,
            started_at TIMESTAMPTZ,
            finished_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.rag_retrieval_log (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID REFERENCES %I.jobs(id) ON DELETE CASCADE,
            query TEXT NOT NULL,
            filters JSONB,
            retrieved_ids JSONB,
            rerank_scores JSONB,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.case_intake (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID NOT NULL UNIQUE REFERENCES %I.jobs(id) ON DELETE CASCADE,
            case_id UUID,
            case_type TEXT,
            organization TEXT,
            report_type TEXT,
            objective_ids JSONB DEFAULT '[]'::jsonb,
            custom_objectives JSONB DEFAULT '[]'::jsonb,
            subjects JSONB DEFAULT '[]'::jsonb,
            scan_scope_json JSONB DEFAULT '{}'::jsonb,
            background TEXT,
            incident_summary TEXT,
            independent_review BOOLEAN DEFAULT FALSE,
            report_ready BOOLEAN DEFAULT FALSE,
            missing_fields JSONB DEFAULT '[]'::jsonb,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.artifact_scope (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID NOT NULL UNIQUE REFERENCES %I.jobs(id) ON DELETE CASCADE,
            sections JSONB NOT NULL DEFAULT '[]'::jsonb,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.report_runs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID NOT NULL REFERENCES %I.jobs(id) ON DELETE CASCADE,
            status TEXT NOT NULL DEFAULT 'pending',
            started_at TIMESTAMPTZ,
            completed_at TIMESTAMPTZ,
            duration_ms BIGINT,
            primary_model TEXT,
            review_model TEXT,
            fast_model TEXT,
            embedding_model TEXT,
            prompt_hash TEXT,
            error TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.report_sections (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            report_run_id UUID NOT NULL REFERENCES %I.report_runs(id) ON DELETE CASCADE,
            job_id UUID NOT NULL REFERENCES %I.jobs(id) ON DELETE CASCADE,
            section_key TEXT NOT NULL,
            title TEXT,
            content_md TEXT,
            structured_json JSONB,
            status TEXT NOT NULL DEFAULT 'draft',
            confidence_grade TEXT,
            primary_model TEXT,
            review_model TEXT,
            review_passed BOOLEAN,
            review_notes JSONB,
            approved BOOLEAN DEFAULT FALSE,
            approved_by UUID,
            approved_at TIMESTAMPTZ,
            sort_order INTEGER DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(report_run_id, section_key)
        )
    $sql$, schema_name, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.report_citations (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            report_section_id UUID NOT NULL REFERENCES %I.report_sections(id) ON DELETE CASCADE,
            artifact_id TEXT,
            job_artifact_id UUID,
            chunk_id UUID,
            file_path TEXT,
            sha256 TEXT,
            citation_label TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.report_findings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            report_section_id UUID NOT NULL REFERENCES %I.report_sections(id) ON DELETE CASCADE,
            finding_text TEXT NOT NULL,
            confidence_grade TEXT NOT NULL DEFAULT 'C',
            limitations TEXT,
            artifact_ids JSONB DEFAULT '[]'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.report_exports (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            report_run_id UUID NOT NULL REFERENCES %I.report_runs(id) ON DELETE CASCADE,
            format TEXT NOT NULL,
            uri TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.human_feedback (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            report_section_id UUID REFERENCES %I.report_sections(id) ON DELETE CASCADE,
            user_id UUID,
            feedback TEXT,
            rating INTEGER,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.graph_sync_state (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID NOT NULL UNIQUE REFERENCES %I.jobs(id) ON DELETE CASCADE,
            nodes_synced INTEGER DEFAULT 0,
            edges_synced INTEGER DEFAULT 0,
            last_sync_at TIMESTAMPTZ,
            status TEXT DEFAULT 'pending',
            error TEXT
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.timeline_events (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID NOT NULL REFERENCES %I.jobs(id) ON DELETE CASCADE,
            event_time_utc TIMESTAMPTZ,
            original_time TEXT,
            timezone TEXT,
            source_artifact_id TEXT,
            description TEXT,
            metadata JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS ix_job_artifacts_job ON %I.job_artifacts(job_id)',
        schema_name
    );
    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS ix_rag_chunks_type ON %I.rag_chunks(job_id, chunk_type)',
        schema_name
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.apply_firm_phase3_all()
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    rec RECORD;
BEGIN
    FOR rec IN SELECT schema_name FROM public.firms WHERE status = 'active' LOOP
        PERFORM public.apply_firm_phase3(rec.schema_name);
    END LOOP;
END;
$$;

SELECT public.apply_firm_phase3_all();
