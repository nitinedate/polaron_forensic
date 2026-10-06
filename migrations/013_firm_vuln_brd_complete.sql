-- BRD completion tables for Vulnerability module (additive to 012).
-- Does not ALTER forensic tables or change existing vuln_* column semantics.
-- Usage: SELECT public.apply_firm_vuln_brd('firm_acme');

CREATE OR REPLACE FUNCTION public.apply_firm_vuln_brd(schema_name text)
RETURNS VOID AS $$
BEGIN
    -- Nessus/Tenable agents (BRD §8.3) — separate from forensic /api/agents
    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_agents (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            agent_uuid TEXT NOT NULL,
            asset_id UUID REFERENCES %I.vuln_assets(id) ON DELETE SET NULL,
            scanner_id UUID REFERENCES %I.vuln_scanners(id) ON DELETE SET NULL,
            name TEXT,
            hostname TEXT,
            platform TEXT,
            version TEXT,
            lifecycle_state TEXT NOT NULL DEFAULT 'planned',
            last_checkin_at TIMESTAMPTZ,
            last_scan_at TIMESTAMPTZ,
            policy_name TEXT,
            link_key_provenance TEXT,
            error_text TEXT,
            device_class TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (agent_uuid)
        )
    $sql$, schema_name, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_credential_refs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL,
            vault_ref TEXT NOT NULL,
            credential_type TEXT NOT NULL DEFAULT 'ssh',
            privilege_scope TEXT,
            lifecycle_state TEXT NOT NULL DEFAULT 'requested',
            last_tested_at TIMESTAMPTZ,
            last_test_result TEXT,
            rotation_due_at TIMESTAMPTZ,
            approved_by UUID,
            created_by UUID,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_scan_results (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            scan_job_id UUID NOT NULL REFERENCES %I.vuln_scan_jobs(id) ON DELETE CASCADE,
            hosts_attempted INT NOT NULL DEFAULT 0,
            hosts_assessed INT NOT NULL DEFAULT 0,
            credential_success_count INT NOT NULL DEFAULT 0,
            credential_fail_count INT NOT NULL DEFAULT 0,
            plugin_error_count INT NOT NULL DEFAULT 0,
            integrity_hash TEXT,
            result_json JSONB,
            completed_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_risk_scores (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            finding_id UUID REFERENCES %I.vuln_findings(id) ON DELETE CASCADE,
            asset_id UUID REFERENCES %I.vuln_assets(id) ON DELETE CASCADE,
            model_version TEXT NOT NULL,
            enterprise_risk_score DOUBLE PRECISION NOT NULL,
            risk_band TEXT NOT NULL,
            factors_json JSONB,
            scored_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_dashboard_snapshots (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            layer TEXT NOT NULL,
            filter_hash TEXT,
            filters_json JSONB,
            widgets_json JSONB NOT NULL,
            freshness_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            created_by UUID,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_alert_thresholds (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            metric_key TEXT NOT NULL,
            operator TEXT NOT NULL DEFAULT 'gte',
            threshold_value DOUBLE PRECISION NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            last_triggered_at TIMESTAMPTZ,
            created_by UUID,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (metric_key)
        )
    $sql$, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_notifications (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            channel TEXT NOT NULL DEFAULT 'in_app',
            event_type TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT,
            resource_type TEXT,
            resource_id UUID,
            acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_asset_owners (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            asset_id UUID NOT NULL REFERENCES %I.vuln_assets(id) ON DELETE CASCADE,
            owner_role TEXT NOT NULL,
            owner_user_id UUID,
            owner_email TEXT,
            effective_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            effective_to TIMESTAMPTZ,
            source TEXT NOT NULL DEFAULT 'manual',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_vuln_agents_state ON %I.vuln_agents (lifecycle_state)', schema_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_vuln_agents_checkin ON %I.vuln_agents (last_checkin_at)', schema_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_vuln_risk_scores_finding ON %I.vuln_risk_scores (finding_id)', schema_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_vuln_snapshots_layer ON %I.vuln_dashboard_snapshots (layer, created_at DESC)', schema_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_vuln_notifications_ack ON %I.vuln_notifications (acknowledged, created_at DESC)', schema_name);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION public.apply_firm_vuln_brd_all()
RETURNS VOID AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT schema_name FROM public.firms LOOP
        PERFORM public.apply_firm_vuln_brd(r.schema_name);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

SELECT public.apply_firm_vuln_brd_all();
