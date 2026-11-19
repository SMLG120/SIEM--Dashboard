#!/usr/bin/env bash
# Ships one committed revision to the server and (re)starts the production stack.
# Usage: infrastructure/deploy/deploy.sh <server-ip> [public-demo-password] [git-ref]
#   git-ref defaults to HEAD. Only committed content is deployed (via `git archive`), so local
#   uncommitted edits can never reach production, and the deployed SHA is recorded on the server.
set -euo pipefail
IP="${1:?usage: deploy.sh <server-ip> [public-demo-password] [git-ref]}"
DEMO_PASSWORD="${2:-explore-the-siem}"
REF="${3:-HEAD}"
HOST="siem.${IP//./-}.sslip.io"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
REMOTE="siem@${IP}"

SHA="$(git -C "$REPO" rev-parse --verify "${REF}^{commit}")"
if [[ "$REF" == "HEAD" && -n "$(git -C "$REPO" status --porcelain --untracked-files=no)" ]]; then
  echo "note: uncommitted changes are present and will NOT be deployed (deploying ${SHA:0:12})." >&2
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
git -C "$REPO" archive --format=tar "$SHA" | tar -x -C "$STAGE"
echo "$SHA" > "$STAGE/DEPLOYED_SHA"

echo ">>> Syncing ${SHA:0:12} to ${REMOTE}:/opt/siem"
rsync -az --delete \
  --exclude .github \
  --filter 'P .env' \
  "${STAGE}/" "${REMOTE}:/opt/siem/"

echo ">>> Ensuring production .env exists (secrets are generated on the server)"
ssh "${REMOTE}" "cd /opt/siem && bash infrastructure/deploy/make-env.sh '${HOST}' '${DEMO_PASSWORD}'"

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.prod.yml"
echo ">>> Building images one at a time (first build takes several minutes)"
# Compose builds every image in parallel by default: nine Maven JVMs at once exhaust an 8 GB server.
# Sequential builds keep peak memory at one build on top of the running stack.
ssh "${REMOTE}" "cd /opt/siem && for s in \$(${COMPOSE} config --services); do ${COMPOSE} build \"\$s\" || exit 1; done"

echo ">>> Starting the stack"
ssh "${REMOTE}" "cd /opt/siem && ${COMPOSE} up -d --remove-orphans"

echo ">>> Done: https://${HOST} at ${SHA:0:12}  (demo login: demo / ${DEMO_PASSWORD})"
