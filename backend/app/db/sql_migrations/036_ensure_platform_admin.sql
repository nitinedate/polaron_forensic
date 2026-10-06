-- Idempotent Superadmin create / password reset.
-- Documented login: superadmin@admin.com / admin@123456789
-- Login organization slug: platform

INSERT INTO public.platform_users (
    id, email, password_hash, status, is_email_verified, mfa_enabled, profile
) VALUES (
    'a0000000-0000-4000-8000-000000000001',
    'superadmin@admin.com',
    '$2b$12$6G2KYUmYNm079nYoFi5XOeB8yoXkqV7dkWtYJTIiqtkc.FK1WY3/G',
    'active',
    true,
    false,
    '{"first_name":"Platform","last_name":"Superadmin","locale":"en","timezone":"UTC"}'::jsonb
)
ON CONFLICT (id) DO UPDATE SET
    email = EXCLUDED.email,
    password_hash = EXCLUDED.password_hash,
    status = 'active',
    is_email_verified = true,
    mfa_enabled = false;

INSERT INTO public.platform_roles (id, name, description, is_system)
VALUES (
    'a0000000-0000-4000-8000-000000000010',
    'superadmin',
    'Platform super administrator — provisions firms and firm admins',
    true
)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    is_system = true;

INSERT INTO public.platform_user_roles (user_id, role_id)
VALUES (
    'a0000000-0000-4000-8000-000000000001',
    'a0000000-0000-4000-8000-000000000010'
)
ON CONFLICT DO NOTHING;
