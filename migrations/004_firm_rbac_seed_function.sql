-- Seeds firm-level permissions and system roles (admin, user) inside a firm schema.
-- Called automatically when a firm is provisioned via the API; provided here for
-- manual / DBA use.
--
-- Usage:
--   SELECT public.seed_firm_rbac('firm_acme');

CREATE OR REPLACE FUNCTION public.seed_firm_rbac(p_schema TEXT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_admin_role_id UUID;
    v_user_role_id UUID;
BEGIN
    EXECUTE format($sql$
        INSERT INTO %I.permissions (code, resource, action, description) VALUES
            ('user:read', 'user', 'read', 'View users'),
            ('user:create', 'user', 'create', 'Invite and create users'),
            ('user:update', 'user', 'update', 'Update and deactivate users'),
            ('permission:read', 'permission', 'read', 'View permission catalog'),
            ('role:read', 'role', 'read', 'View roles'),
            ('role:manage', 'role', 'manage', 'Create and manage roles'),
            ('job:read', 'job', 'read', 'View forensic jobs'),
            ('job:run', 'job', 'run', 'Run forensic jobs'),
            ('artifact:read', 'artifact', 'read', 'View artifacts'),
            ('artifact:manage', 'artifact', 'manage', 'Register and manage forensic evidence'),
            ('report:generate', 'report', 'generate', 'Generate reports'),
            ('case:manage', 'case', 'manage', 'Manage forensic cases'),
            ('scan:read', 'scan', 'read', 'View vulnerability scans'),
            ('vuln:read', 'vuln', 'read', 'View vulnerabilities'),
            ('asset:read', 'asset', 'read', 'View assets'),
            ('correlation:read', 'correlation', 'read', 'View correlations')
        ON CONFLICT (code) DO NOTHING
    $sql$, p_schema);

    EXECUTE format($sql$
        INSERT INTO %I.roles (name, description, is_system) VALUES
            ('admin', 'Firm administrator — full IAM and operational access', TRUE),
            ('user', 'Standard firm user — profile and security settings only', TRUE)
        ON CONFLICT (name) DO NOTHING
    $sql$, p_schema);

    EXECUTE format('SELECT id FROM %I.roles WHERE name = ''admin'' LIMIT 1', p_schema) INTO v_admin_role_id;
    EXECUTE format('SELECT id FROM %I.roles WHERE name = ''user'' LIMIT 1', p_schema) INTO v_user_role_id;

    EXECUTE format($sql$
        INSERT INTO %I.role_permissions (role_id, permission_id)
        SELECT $1, p.id FROM %I.permissions p
        ON CONFLICT DO NOTHING
    $sql$, p_schema, p_schema) USING v_admin_role_id;

    EXECUTE format($sql$
        INSERT INTO %I.role_permissions (role_id, permission_id)
        SELECT $1, p.id FROM %I.permissions p
        WHERE FALSE
        ON CONFLICT DO NOTHING
    $sql$, p_schema, p_schema) USING v_user_role_id;
END;
$$;
