#!/usr/bin/env bash
# Ships the working tree to the server and (re)starts the production stack.
# Usage: infrastructure/deploy/deploy.sh <server-ip> [public-demo-password]
set -euo pipefail
IP="${1:?usage: deploy.sh <server-ip> [public-demo-password]}"
DEMO_PASSWORD="${2:-explore-the-siem}"
HOST="siem.${IP//./-}.sslip.io"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE="siem@${IP}"

echo ">>> Syncing code to ${REMOTE}:/opt/siem"
rsync -az --delete \
  --exclude .git --exclude .env --exclude '.env.*' \
  --exclude node_modules --exclude target --exclude dist --exclude .github --exclude .DS_Store \
  --filter 'P .env' \
  "${REPO}/" "${REMOTE}:/opt/siem/"

echo ">>> Ensuring production .env exists (secrets are generated on the server)"
ssh "${REMOTE}" "cd /opt/siem && bash infrastructure/deploy/make-env.sh '${HOST}' '${DEMO_PASSWORD}'"

echo ">>> Building and starting the stack (first build takes several minutes)"
ssh "${REMOTE}" "cd /opt/siem && docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build --remove-orphans"

echo ">>> Done: https://${HOST}  (demo login: demo / ${DEMO_PASSWORD})"
