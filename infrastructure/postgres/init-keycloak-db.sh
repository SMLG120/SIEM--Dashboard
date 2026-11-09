#!/bin/sh
# Runs once, on first initialisation of the PostgreSQL volume: a separate database and user for Keycloak.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v kc_password="$KEYCLOAK_DB_PASSWORD" <<'SQL'
CREATE USER keycloak WITH PASSWORD :'kc_password';
CREATE DATABASE keycloak OWNER keycloak;
SQL
