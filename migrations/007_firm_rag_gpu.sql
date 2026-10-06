-- Phase 2.5: GPU RAG indexing tables and job progress columns.

CREATE OR REPLACE FUNCTION public.apply_firm_rag_gpu(schema_name text)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    EXECUTE format(
        'ALTER TABLE %I.jobs ADD COLUMN IF NOT EXISTS extract_coverage JSONB',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.jobs ADD COLUMN IF NOT EXISTS pipeline_progress JSONB',
        schema_name
    );

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.rag_chunks (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID NOT NULL REFERENCES %I.jobs(id) ON DELETE CASCADE,
            file_path TEXT NOT NULL,
            chunk_index INTEGER NOT NULL DEFAULT 0,
            content TEXT NOT NULL,
            embedding vector(384),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format(
        'ALTER TABLE %I.rag_chunks ADD COLUMN IF NOT EXISTS embedding vector(384)',
        schema_name
    );

    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS ix_rag_chunks_job ON %I.rag_chunks(job_id)',
        schema_name
    );
    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS ix_rag_chunks_path ON %I.rag_chunks(job_id, file_path)',
        schema_name
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.apply_firm_rag_gpu_all()
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    rec RECORD;
BEGIN
    FOR rec IN SELECT schema_name FROM public.firms WHERE status = 'active' LOOP
        PERFORM public.apply_firm_rag_gpu(rec.schema_name);
    END LOOP;
END;
$$;

SELECT public.apply_firm_rag_gpu_all();
