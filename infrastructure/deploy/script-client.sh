#!/usr/bin/env bash
# Temporarily enables (or disables) the password-grant `siem-demo` client on the production realm,
# e.g. to run the demo seeding scripts. Production imports it disabled; leave it disabled afterwards.
# Usage: infrastructure/deploy/script-client.sh <server-ip> enable|disable
set -euo pipefail
IP="${1:?usage: script-client.sh <server-ip> enable|disable}"
case "${2:-}" in
  enable) ENABLED=true ;;
  disable) ENABLED=false ;;
  *) echo "usage: script-client.sh <server-ip> enable|disable" >&2; exit 2 ;;
esac
# kcadm runs inside the Keycloak container against its local port with the bootstrap admin
# credentials already in that container's environment; nothing secret crosses this machine.
ssh "siem@${IP}" "cd /opt/siem && docker compose -f docker-compose.yml -f docker-compose.prod.yml exec -T keycloak bash -c '
  set -euo pipefail
  kc=/opt/keycloak/bin/kcadm.sh
  \$kc config credentials --server http://localhost:8080/auth --realm master \
    --user \"\$KC_BOOTSTRAP_ADMIN_USERNAME\" --password \"\$KC_BOOTSTRAP_ADMIN_PASSWORD\" >/dev/null
  id=\$(\$kc get clients -r enterprise-siem -q clientId=siem-demo --fields id --format csv --noquotes)
  [ -n \"\$id\" ] || { echo \"siem-demo client not found\" >&2; exit 1; }
  \$kc update clients/\$id -r enterprise-siem -s enabled=${ENABLED}
  echo \"siem-demo enabled=${ENABLED}\"
'"
