#!/usr/bin/env bash
#
# ingest-demo-events.sh
#
# Pushes sample security events through the API Gateway into the ingestion
# service so the Kafka -> detection -> alert pipeline can be exercised.
#
# Usage:
#   scripts/ingest-demo-events.sh [path/to/events.json]
#
# Requires: curl and jq. Reads credentials from .env (SIEM_DEMO_PASSWORD,
# SIEM_*_PORT); SIEM_DEMO_PASSWORD has no default and must be set.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$BASE_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$BASE_DIR/.env"
  set +a
fi

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:${SIEM_KEYCLOAK_PORT:-18088}}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:${SIEM_GATEWAY_PORT:-18080}}"
REALM="${SIEM_REALM:-enterprise-siem}"
CLIENT_ID="${SIEM_DEMO_CLIENT_ID:-siem-demo}"
USERNAME="${SIEM_DEMO_USER:-admin}"
PASSWORD="${SIEM_DEMO_PASSWORD:?SIEM_DEMO_PASSWORD must be set (see .env.example)}"
EVENTS_FILE="${1:-$BASE_DIR/sample-data/security-events.json}"

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required but was not found" >&2
  exit 1
fi

if [[ ! -f "$EVENTS_FILE" ]]; then
  echo "error: events file not found: $EVENTS_FILE" >&2
  exit 1
fi

echo ">>> Requesting token as $USERNAME from $KEYCLOAK_URL"
TOKEN_RESPONSE="$(curl -sf -X POST \
  "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT_ID" \
  -d "username=$USERNAME" \
  -d "password=$PASSWORD" \
  -d "grant_type=password")"

TOKEN="$(jq -r '.access_token' <<<"$TOKEN_RESPONSE")"
if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
  echo "error: failed to obtain access token" >&2
  exit 1
fi

COUNT="$(jq 'length' "$EVENTS_FILE")"
echo ">>> Ingesting $COUNT events from $EVENTS_FILE via $GATEWAY_URL"

RESULT="$(curl -sf -X POST \
  "$GATEWAY_URL/api/events/batch" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary "@$EVENTS_FILE")"

jq -r '.[] | "  + " + .eventType + " [" + .severity + "] " + (.sourceIp // "-")' <<<"$RESULT"

echo ">>> Done. Detection will publish alerts for matching rules."
echo "    open the SOC console at http://localhost:${SIEM_FRONTEND_PORT:-15173} to triage them."