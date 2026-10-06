-- Remove IAM permissions from the firm "user" role in all existing firm schemas.
-- Standard users may only access /api/users/me (profile) and security settings.

CREATE OR REPLACE FUNCTION public.restrict_firm_user_roles()
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    rec RECORD;
BEGIN
    IF to_regclass('public.firms') IS NULL THEN
        RETURN;
    END IF;
    FOR rec IN SELECT schema_name FROM public.firms LOOP
        EXECUTE format(
            $sql$
            DELETE FROM %I.role_permissions rp
            USING %I.roles ro
            WHERE rp.role_id = ro.id
              AND ro.name = 'user'
            $sql$,
            rec.schema_name,
            rec.schema_name
        );
        EXECUTE format(
            $sql$
            UPDATE %I.roles
            SET description = 'Standard firm user — profile and security settings only'
            WHERE name = 'user'
            $sql$,
            rec.schema_name
        );
    END LOOP;
END;
$$;

SELECT public.restrict_firm_user_roles();
