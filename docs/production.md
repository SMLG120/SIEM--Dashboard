# Production Deployment

The live stack is the same Docker Compose project as local development, plus [`docker-compose.prod.yml`](../docker-compose.prod.yml):

- **Caddy** is the only container with published ports (80/443). It obtains a Let's Encrypt certificate automatically and serves one origin:
  `/` → dashboard, `/api` → API gateway, `/auth` → Keycloak.
- **Keycloak** runs in production mode on PostgreSQL. Its admin console and master realm return 404 publicly.
- Password reset is disabled (there is no real SMTP relay) and Mailpit is not started.
- Prometheus, Grafana, Kafka, OpenSearch, Redis and PostgreSQL are reachable only on the internal Compose network.

## Server

Any Ubuntu 24.04 VM with 8 vCPU / 16 GB RAM works; the reference is a Hetzner Cloud **CX42**. The address is free via [sslip.io](https://sslip.io): a server at `203.0.113.10` is served at `https://siem.203-0-113-10.sslip.io`.

## First deployment

1. Create an SSH key on your machine if you don't have one: `ssh-keygen -t ed25519`.
2. Create the server with that public key (`~/.ssh/id_ed25519.pub`) and note its IPv4 address.
3. Harden it (Docker, firewall for 22/80/443 only, fail2ban, unattended upgrades, a `siem` deploy user, swap):

   ```bash
   ssh root@<ip> 'bash -s' < infrastructure/deploy/bootstrap-server.sh
   ```

4. Deploy. Secrets are generated **on the server** into `/opt/siem/.env` (mode 600) and never leave it:

   ```bash
   infrastructure/deploy/deploy.sh <ip> [public-demo-password]
   ```

5. Load the demo data once the site responds. Run from the repo; variables you export take precedence over your local `.env`:

   ```bash
   export SIEM_PUBLIC_URL=https://siem.<ip-dashed>.sslip.io
   export KEYCLOAK_URL=$SIEM_PUBLIC_URL/auth GATEWAY_URL=$SIEM_PUBLIC_URL
   export SIEM_DEMO_PASSWORD="$(ssh siem@<ip> 'grep ^SIEM_DEMO_PASSWORD= /opt/siem/.env | cut -d= -f2')"
   scripts/ingest-demo-events.sh && scripts/seed-demo-workflow.sh
   unset SIEM_DEMO_PASSWORD
   ```

## Accounts

| Account | Role | Password |
|---|---|---|
| `demo` | `VIEWER` (read-only everywhere) | `SIEM_PUBLIC_DEMO_PASSWORD`, meant to be published |
| `admin`, `sam.*` | Full and analyst roles | `SIEM_DEMO_PASSWORD`, random, server-only |

Keycloak imports the realm only on its **first** start against an empty database; changing passwords in `.env` afterwards does not update existing users.

## Redeploying

Re-run `infrastructure/deploy/deploy.sh <ip>`. It syncs the working tree (excluding `.env`, `.git`, build output), keeps the server's `.env`, and rebuilds only what changed.

## Administration

Grafana and the Keycloak admin console listen on the server's loopback interface only. Open an SSH tunnel and use them from your machine:

```bash
ssh -N -L 13000:localhost:13000 -L 18088:localhost:18088 siem@<ip>
# Grafana:        http://localhost:13000        (GF_SECURITY_ADMIN_* from the server's .env)
# Keycloak admin: http://localhost:18088/auth/admin   (KEYCLOAK_ADMIN_* from the server's .env)
```

Read a secret without copying the whole file: `ssh siem@<ip> 'grep ^KEYCLOAK_ADMIN_PASSWORD= /opt/siem/.env'`.

Logs and status:

```bash
ssh siem@<ip> 'cd /opt/siem && docker compose -f docker-compose.yml -f docker-compose.prod.yml ps'
ssh siem@<ip> 'cd /opt/siem && docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f --tail 100 api-gateway'
```
