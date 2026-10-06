-- Platform RBAC catalog + one Superadmin account.
--
-- Superadmin credentials (change after first login in production):
--   Email:        superadmin@admin.com
--   Password:     admin@123456789
--   Tenant:       None (platform-scoped; not a firm member)
--
-- Password hash generated with bcrypt (passlib, rounds=12).

-- Fixed UUIDs keep seeds idempotent across environments.
-- Superadmin user:  a0000000-0000-4000-8000-000000000001
-- Superadmin role:  a0000000-0000-4000-8000-000000000010

INSERT INTO platform_permissions (id, code, resource, action, description) VALUES
    ('b1000001-0000-4000-8000-000000000001', 'tenant:manage', 'tenant', 'manage', 'Provision and manage firms'),
    ('b1000001-0000-4000-8000-000000000002', 'user:read',     'user',   'read',   'View platform users'),
    ('b1000001-0000-4000-8000-000000000003', 'user:create',   'user',   'create', 'Create platform users'),
    ('b1000001-0000-4000-8000-000000000004', 'user:update',   'user',   'update', 'Update platform users')
ON CONFLICT (code) DO NOTHING;

INSERT INTO platform_roles (id, name, description, is_system) VALUES
    ('a0000000-0000-4000-8000-000000000010', 'superadmin', 'Platform super administrator — provisions firms and firm admins', TRUE)
ON CONFLICT (name) DO NOTHING;

-- Grant all platform permissions to superadmin
INSERT INTO platform_role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM platform_roles r
CROSS JOIN platform_permissions p
WHERE r.name = 'superadmin'
ON CONFLICT DO NOTHING;

-- Legacy alias: migrate tenant_admin role assignments to superadmin if present
UPDATE platform_user_roles ur
SET role_id = (SELECT id FROM platform_roles WHERE name = 'superadmin')
WHERE role_id = (SELECT id FROM platform_roles WHERE name = 'tenant_admin')
  AND EXISTS (SELECT 1 FROM platform_roles WHERE name = 'superadmin');

DELETE FROM platform_role_permissions
WHERE role_id = (SELECT id FROM platform_roles WHERE name = 'tenant_admin');

DELETE FROM platform_roles WHERE name = 'tenant_admin';

-- Upsert by fixed id so email/password can be rotated safely
INSERT INTO platform_users (
    id,
    email,
    password_hash,
    status,
    is_email_verified,
    mfa_enabled,
    profile
) VALUES (
    'a0000000-0000-4000-8000-000000000001',
    'superadmin@admin.com',
    '$2b$12$6G2KYUmYNm079nYoFi5XOeB8yoXkqV7dkWtYJTIiqtkc.FK1WY3/G',
    'active',
    TRUE,
    FALSE,
    '{"first_name": "Platform", "last_name": "Superadmin", "locale": "en", "timezone": "UTC"}'::jsonb
)
ON CONFLICT (id) DO UPDATE SET
    email = EXCLUDED.email,
    password_hash = EXCLUDED.password_hash,
    status = 'active',
    is_email_verified = TRUE,
    mfa_enabled = FALSE,
    profile = EXCLUDED.profile,
    updated_at = NOW();

-- Remove legacy seed email if present under a different id
DELETE FROM platform_user_roles
WHERE user_id IN (SELECT id FROM platform_users WHERE email = 'admin@platform.test'
                  AND id <> 'a0000000-0000-4000-8000-000000000001');
DELETE FROM platform_users
WHERE email = 'admin@platform.test'
  AND id <> 'a0000000-0000-4000-8000-000000000001';

-- Assign superadmin role
INSERT INTO platform_user_roles (user_id, role_id)
SELECT u.id, r.id
FROM platform_users u
CROSS JOIN platform_roles r
WHERE u.email = 'superadmin@admin.com'
  AND r.name = 'superadmin'
ON CONFLICT DO NOTHING;
