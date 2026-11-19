-- One-off upgrade for a volume created before v2, where the services connect as the bootstrap
-- superuser. Run as that superuser:  psql -v app_password='...' -f adopt-app-role.sql
-- then set SIEM_DB_USER=siem_service and SIEM_DB_PASSWORD in .env and restart the services.
-- Data is untouched; only object ownership and grants change. Review before running in production.
\set ON_ERROR_STOP on
CREATE ROLE siem_service LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'app_password';
GRANT CONNECT, TEMPORARY ON DATABASE siem TO siem_service;
GRANT USAGE, CREATE ON SCHEMA public TO siem_service;
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
        EXECUTE format('ALTER TABLE public.%I OWNER TO siem_service', r.tablename);
    END LOOP;
    FOR r IN SELECT sequencename FROM pg_sequences WHERE schemaname = 'public' LOOP
        EXECUTE format('ALTER SEQUENCE public.%I OWNER TO siem_service', r.sequencename);
    END LOOP;
    FOR r IN SELECT p.oid::regprocedure AS fn FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'public' LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO siem_service', r.fn);
    END LOOP;
END $$;
