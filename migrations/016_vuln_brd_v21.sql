-- BRD v2.1: KEV catalog, custom checks, exploit validation, PCI tags.
-- Usage: SELECT public.apply_vuln_platform_v21();
--        SELECT public.apply_firm_vuln_v21('firm_acme');

CREATE TABLE IF NOT EXISTS public.cisa_kev_catalog (
    cve_id TEXT PRIMARY KEY,
    vendor_project TEXT,
    product TEXT,
    vulnerability_name TEXT,
    date_added DATE,
    synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION public.apply_firm_vuln_v21(schema_name text)
RETURNS VOID AS $$
BEGIN
    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_custom_checks (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL,
            check_type TEXT NOT NULL DEFAULT 'nuclei',
            content_ref TEXT NOT NULL,
            lifecycle_state TEXT NOT NULL DEFAULT 'draft',
            severity_hint TEXT,
            cve_hint TEXT,
            pci_requirement_tag TEXT,
            created_by UUID,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name);

    EXECUTE format($sql$
        ALTER TABLE %I.vuln_findings
            ADD COLUMN IF NOT EXISTS exploit_validation_status TEXT,
            ADD COLUMN IF NOT EXISTS exploit_validated_at TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS exploit_validated_by UUID,
            ADD COLUMN IF NOT EXISTS pci_requirement_tag TEXT,
            ADD COLUMN IF NOT EXISTS validation_metadata_json JSONB
    $sql$, schema_name);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION public.apply_vuln_platform_v21()
RETURNS VOID AS $$
BEGIN
    -- Ensures public KEV table exists (idempotent).
    CREATE TABLE IF NOT EXISTS public.cisa_kev_catalog (
        cve_id TEXT PRIMARY KEY,
        vendor_project TEXT,
        product TEXT,
        vulnerability_name TEXT,
        date_added DATE,
        synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
END;
$$ LANGUAGE plpgsql;
