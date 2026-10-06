-- Vulnerability / Nessus enterprise module (firm-scoped).
-- Additive only — does not alter forensic jobs/artifacts/rag tables.
-- Usage: SELECT public.apply_firm_vuln('firm_acme');

CREATE OR REPLACE FUNCTION public.apply_firm_vuln(schema_name text)
RETURNS VOID AS $$
BEGIN
    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_scanners (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            edition TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            api_key_ref TEXT,
            plugin_feed_updated_at TIMESTAMPTZ,
            last_heartbeat_at TIMESTAMPTZ,
            version TEXT,
            capacity_hosts INT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_scan_policies (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            case_id UUID,
            name TEXT NOT NULL,
            policy_type TEXT NOT NULL DEFAULT 'basic_network',
            scanner_id UUID REFERENCES %I.vuln_scanners(id) ON DELETE SET NULL,
            settings_json JSONB,
            compliance_framework TEXT,
            lifecycle_state TEXT NOT NULL DEFAULT 'draft',
            created_by UUID,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_scan_jobs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            case_id UUID NOT NULL,
            policy_id UUID REFERENCES %I.vuln_scan_policies(id) ON DELETE SET NULL,
            scanner_id UUID REFERENCES %I.vuln_scanners(id) ON DELETE SET NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            scheduled_at TIMESTAMPTZ,
            started_at TIMESTAMPTZ,
            completed_at TIMESTAMPTZ,
            source TEXT NOT NULL DEFAULT 'platform',
            authorization_ref TEXT,
            scan_window_start TIMESTAMPTZ,
            scan_window_end TIMESTAMPTZ,
            external_scan_id TEXT,
            preflight_json JSONB,
            error TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_scan_targets (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            scan_job_id UUID NOT NULL REFERENCES %I.vuln_scan_jobs(id) ON DELETE CASCADE,
            target TEXT NOT NULL,
            target_type TEXT DEFAULT 'host',
            credential_ref TEXT,
            excluded BOOLEAN NOT NULL DEFAULT FALSE
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_assets (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            case_id UUID NOT NULL,
            hostname TEXT,
            primary_ip TEXT,
            mac TEXT,
            os TEXT,
            asset_type TEXT,
            criticality TEXT,
            business_owner_id UUID,
            technical_owner_id UUID,
            risk_score DOUBLE PRECISION,
            external_exposure TEXT,
            lifecycle_state TEXT NOT NULL DEFAULT 'active',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_asset_identifiers (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            asset_id UUID NOT NULL REFERENCES %I.vuln_assets(id) ON DELETE CASCADE,
            id_type TEXT NOT NULL,
            value TEXT NOT NULL,
            source TEXT
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_findings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            case_id UUID NOT NULL,
            scan_job_id UUID REFERENCES %I.vuln_scan_jobs(id) ON DELETE SET NULL,
            asset_id UUID REFERENCES %I.vuln_assets(id) ON DELETE SET NULL,
            plugin_id TEXT,
            plugin_family TEXT,
            cve TEXT,
            cvss DOUBLE PRECISION,
            severity TEXT NOT NULL DEFAULT 'info',
            port INT,
            protocol TEXT,
            service TEXT,
            synopsis TEXT,
            remediation TEXT,
            status TEXT NOT NULL DEFAULT 'open',
            enterprise_risk_score DOUBLE PRECISION,
            risk_band TEXT,
            risk_factors_json JSONB,
            is_kev BOOLEAN NOT NULL DEFAULT FALSE,
            first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_remediation_tasks (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            finding_id UUID NOT NULL REFERENCES %I.vuln_findings(id) ON DELETE CASCADE,
            owner_id UUID,
            sla_due TIMESTAMPTZ,
            status TEXT NOT NULL DEFAULT 'open',
            resolution TEXT,
            rescan_job_id UUID REFERENCES %I.vuln_scan_jobs(id) ON DELETE SET NULL,
            accepted_risk_ref TEXT,
            escalation_level INT NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_exceptions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            finding_id UUID NOT NULL REFERENCES %I.vuln_findings(id) ON DELETE CASCADE,
            requested_by UUID NOT NULL,
            approved_by UUID,
            status TEXT NOT NULL DEFAULT 'pending',
            reason TEXT,
            compensating_controls TEXT,
            expires_at TIMESTAMPTZ,
            residual_risk TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT vuln_exception_sod CHECK (approved_by IS NULL OR approved_by <> requested_by)
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_evidence_packages (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            case_id UUID,
            framework TEXT,
            control_id TEXT,
            title TEXT NOT NULL,
            metadata_json JSONB,
            integrity_hash TEXT,
            period_start TIMESTAMPTZ,
            period_end TIMESTAMPTZ,
            created_by UUID,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_timeline_events (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            case_id UUID NOT NULL,
            source_type TEXT NOT NULL,
            source_id UUID,
            timestamp_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            event_type TEXT NOT NULL,
            actor TEXT,
            asset_id UUID,
            summary TEXT
        )
    $sql$, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_audit_events (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            actor_id UUID,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id UUID,
            details JSONB,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name);

    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_vuln_findings_case ON %I.vuln_findings (case_id)', schema_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_vuln_findings_severity ON %I.vuln_findings (severity)', schema_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_vuln_assets_case ON %I.vuln_assets (case_id)', schema_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_vuln_scan_jobs_case ON %I.vuln_scan_jobs (case_id)', schema_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_vuln_remediation_status ON %I.vuln_remediation_tasks (status)', schema_name);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION public.apply_firm_vuln_all()
RETURNS VOID AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT schema_name FROM public.firms LOOP
        PERFORM public.apply_firm_vuln(r.schema_name);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

SELECT public.apply_firm_vuln_all();
