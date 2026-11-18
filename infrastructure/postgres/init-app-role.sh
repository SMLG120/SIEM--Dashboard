#!/bin/sh
# Runs once, on first initialisation of the PostgreSQL volume. Creates the role the SIEM services
# use: it owns the tables Flyway creates but is not a superuser and cannot create roles or databases.
# Skipped when SIEM_DB_PASSWORD is unset (services then fall back to POSTGRES_USER, the v1 behaviour).
set -eu
if [ -z "${SIEM_DB_PASSWORD:-}" ]; then
  echo "SIEM_DB_PASSWORD not set; services will use the bootstrap role." >&2
  exit 0
fi
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v app_user="${SIEM_DB_USER:-siem_service}" -v app_password="$SIEM_DB_PASSWORD" -v db="$POSTGRES_DB" <<'SQL'
CREATE ROLE :"app_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'app_password';
GRANT CONNECT, TEMPORARY ON DATABASE :"db" TO :"app_user";
GRANT USAGE, CREATE ON SCHEMA public TO :"app_user";
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
