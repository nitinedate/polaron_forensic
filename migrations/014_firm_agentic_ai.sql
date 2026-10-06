-- Forensic Agentic AI module (firm-scoped). Additive only.
-- Does not alter extract/RAG/vuln tables. Distinct from Nessus vuln_agents.
-- Usage: SELECT public.apply_firm_agentic_ai('firm_acme');

CREATE OR REPLACE FUNCTION public.apply_firm_agentic_ai(schema_name text)
RETURNS VOID AS $$
BEGIN
    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.agent_threads (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID NOT NULL,
            user_id UUID,
            title TEXT,
            agent_id TEXT NOT NULL DEFAULT 'investigator',
            status TEXT NOT NULL DEFAULT 'open',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.agent_messages (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            thread_id UUID NOT NULL REFERENCES %I.agent_threads(id) ON DELETE CASCADE,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            metadata_json JSONB,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.agent_runs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            thread_id UUID REFERENCES %I.agent_threads(id) ON DELETE SET NULL,
            job_id UUID NOT NULL,
            agent_id TEXT NOT NULL,
            parent_run_id UUID,
            status TEXT NOT NULL DEFAULT 'queued',
            message TEXT,
            plan_json JSONB,
            started_at TIMESTAMPTZ,
            finished_at TIMESTAMPTZ,
            latency_ms INT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.agent_tool_calls (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            run_id UUID NOT NULL REFERENCES %I.agent_runs(id) ON DELETE CASCADE,
            step_index INT NOT NULL DEFAULT 0,
            tool_name TEXT NOT NULL,
            input_json JSONB,
            output_json JSONB,
            status TEXT NOT NULL DEFAULT 'ok',
            error_text TEXT,
            latency_ms INT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_agent_threads_job ON %I.agent_threads (job_id)', schema_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_agent_runs_job ON %I.agent_runs (job_id, created_at DESC)', schema_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_agent_messages_thread ON %I.agent_messages (thread_id, created_at)', schema_name);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION public.apply_firm_agentic_ai_all()
RETURNS VOID AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT schema_name FROM public.firms LOOP
        PERFORM public.apply_firm_agentic_ai(r.schema_name);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

SELECT public.apply_firm_agentic_ai_all();
