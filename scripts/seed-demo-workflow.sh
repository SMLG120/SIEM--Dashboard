#!/usr/bin/env bash
#
# seed-demo-workflow.sh
#
# Stages realistic analyst activity on top of scripts/ingest-demo-events.sh:
# acknowledges, investigates and resolves alerts, assigns incidents, moves
# them through their lifecycle and adds analyst notes. Run once, after ingest.
#
# Usage: scripts/seed-demo-workflow.sh
# Reads SIEM_DEMO_PASSWORD (and optional KEYCLOAK_URL / GATEWAY_URL) from .env.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# Load .env, but let variables already set in the environment win (e.g. when targeting production).
if [[ -f "$BASE_DIR/.env" ]]; then
  while IFS='=' read -r key value; do
    [[ "$key" =~ ^[A-Z_][A-Z0-9_]*$ ]] || continue
    [[ -n "${!key+x}" ]] || export "$key=$value"
  done < "$BASE_DIR/.env"
fi

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:${SIEM_KEYCLOAK_PORT:-18088}}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:${SIEM_GATEWAY_PORT:-18080}}"
PASSWORD="${SIEM_DEMO_PASSWORD:?SIEM_DEMO_PASSWORD must be set (see .env.example)}"

token() {
  curl -sf -X POST "$KEYCLOAK_URL/realms/enterprise-siem/protocol/openid-connect/token" \
    -d client_id=siem-demo -d grant_type=password -d "username=$1" \
    --data-urlencode "password=$PASSWORD" | jq -r .access_token
}
call() { # token method path [json]
  local args=(-sf -o /dev/null -X "$2" -H "Authorization: Bearer $1" -H 'Content-Type: application/json')
  [[ $# -ge 4 ]] && args+=(--data "$4")
  curl "${args[@]}" "$GATEWAY_URL$3"
}

ANALYST="$(token sam.analyst)"
MANAGER="$(token sam.manager)"

alerts=()
while IFS= read -r id; do alerts+=("$id"); done < <(curl -sf -H "Authorization: Bearer $ANALYST" "$GATEWAY_URL/api/alerts" | jq -r '.[].id')
(( ${#alerts[@]} >= 11 )) || { echo "error: run scripts/ingest-demo-events.sh first (found ${#alerts[@]} alerts)" >&2; exit 1; }

echo ">>> Triaging alerts as sam.analyst"
for i in 0 1 2 3; do call "$ANALYST" POST "/api/alerts/${alerts[$i]}/acknowledge"; done
for i in 4 5 6; do
  call "$ANALYST" POST "/api/alerts/${alerts[$i]}/investigate"
  call "$ANALYST" POST "/api/alerts/${alerts[$i]}/assign" '{"assignedTo":"sam.analyst"}'
done
for i in 7 8 9 10; do call "$ANALYST" POST "/api/alerts/${alerts[$i]}/resolve"; done
call "$ANALYST" POST "/api/alerts/${alerts[4]}/notes" '{"text":"Process tree shows encoded PowerShell spawned from Outlook. Isolating host."}'
call "$ANALYST" POST "/api/alerts/${alerts[7]}/notes" '{"text":"False positive: authorised pentest window, ticket SEC-4821."}'

incidents=()
while IFS= read -r id; do incidents+=("$id"); done < <(curl -sf -H "Authorization: Bearer $MANAGER" "$GATEWAY_URL/api/incidents" | jq -r 'sort_by(-(.relatedAlerts|length), .id) | .[].id')

echo ">>> Working incidents as sam.manager and sam.analyst"
call "$MANAGER" PATCH "/api/incidents/${incidents[0]}" '{"status":"INVESTIGATING","assignedTo":"sam.analyst"}'
call "$MANAGER" POST "/api/incidents/${incidents[0]}/notes" '{"text":"Confirmed malicious activity on this host. Escalated to IR lead."}'
call "$ANALYST" POST "/api/incidents/${incidents[0]}/notes" '{"text":"Blocked destination at egress proxy; collecting a memory image."}'
call "$MANAGER" PATCH "/api/incidents/${incidents[1]}" '{"status":"CONTAINED","assignedTo":"sam.manager"}'
call "$MANAGER" PATCH "/api/incidents/${incidents[2]}" '{"status":"INVESTIGATING","assignedTo":"sam.analyst"}'
call "$MANAGER" PATCH "/api/incidents/${incidents[3]}" '{"status":"RESOLVED","assignedTo":"sam.manager"}'
call "$MANAGER" PATCH "/api/incidents/${incidents[4]}" '{"assignedTo":"sam.analyst"}'

echo ">>> Done."
