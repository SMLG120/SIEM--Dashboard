#!/usr/bin/env bash
# Generates /opt/siem/.env on the server with random secrets. Never overwrites an existing file.
# Usage: make-env.sh <public-host> [public-demo-password]
#   e.g. make-env.sh siem.203-0-113-10.sslip.io
set -euo pipefail
HOST="${1:?usage: make-env.sh <public-host> [public-demo-password]}"
DEMO_PASSWORD="${2:-explore-the-siem}"
ENV_FILE="$(cd "$(dirname "$0")/../.." && pwd)/.env"
if [[ -e "$ENV_FILE" ]]; then
  echo "$ENV_FILE already exists; leaving it untouched." >&2
  exit 0
fi
(( ${#DEMO_PASSWORD} >= 12 )) || { echo "demo password must be at least 12 characters" >&2; exit 1; }
gen() { openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-32; }
umask 077
cat > "$ENV_FILE" <<ENV
# Production secrets, generated $(date -u +%F). Keep this file on the server only.
SIEM_SITE_ADDRESS=${HOST}
SIEM_PUBLIC_URL=https://${HOST}
SIEM_TLS_MODE=auto

POSTGRES_DB=siem
POSTGRES_USER=siem_app
POSTGRES_PASSWORD=$(gen)
KEYCLOAK_DB_PASSWORD=$(gen)
REDIS_PASSWORD=$(gen)
KEYCLOAK_ADMIN_USERNAME=admin
KEYCLOAK_ADMIN_PASSWORD=$(gen)
SIEM_DEMO_PASSWORD=$(gen)
SIEM_PUBLIC_DEMO_PASSWORD=${DEMO_PASSWORD}
GF_SECURITY_ADMIN_USER=admin
GF_SECURITY_ADMIN_PASSWORD=$(gen)
KAFKA_UI_USERNAME=admin
KAFKA_UI_PASSWORD=$(gen)

KAFKA_BOOTSTRAP_SERVERS=kafka:9092
OIDC_ISSUER_URI=https://${HOST}/auth/realms/enterprise-siem
OIDC_JWK_SET_URI=http://keycloak:8080/auth/realms/enterprise-siem/protocol/openid-connect/certs
ENV
echo "Wrote $ENV_FILE (mode 600)."
