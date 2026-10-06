ALTER TABLE vuln_scanners
    ADD COLUMN IF NOT EXISTS openvas_ready boolean,
    ADD COLUMN IF NOT EXISTS agent_status_detail text,
    ADD COLUMN IF NOT EXISTS openvas_ready_at timestamptz;
