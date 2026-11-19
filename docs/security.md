# Security

Authentication is OAuth2/OpenID Connect through Keycloak. Every service is a JWT resource server that validates the signature, issuer and `api-gateway` audience, and applies role checks of its own in addition to the gateway route rules. Request bodies are validated with Bean Validation before anything reaches Kafka or PostgreSQL.

Secrets are not committed. Local development uses `.env`, which is ignored by Git.

## Authentication

- Keycloak realm: `enterprise-siem`
- Public browser client: `siem-dashboard`
- API resource client: `api-gateway`
- Demo/test client: `siem-demo` (password grant only) used by `scripts/ingest-demo-events.sh`. **Enabled only in local Compose**; the production realm import sets it disabled. An operator can enable it temporarily with `infrastructure/deploy/script-client.sh <ip> enable` and must disable it afterwards.
- Frontend flow: Authorization Code with PKCE through `keycloak-js`
- Backend validation: Spring Security OAuth2 resource server JWT validation

## Local Test Credentials

- Keycloak admin console: `KEYCLOAK_ADMIN_USERNAME` / `KEYCLOAK_ADMIN_PASSWORD` from `.env`
- Realm users (`admin`, `sam.admin`, `sam.manager`, `sam.analyst`, `sam.viewer`): password from `SIEM_DEMO_PASSWORD` in `.env` (no default; Compose refuses to start without it)
- Public read-only `demo` user (`VIEWER`): password from `SIEM_PUBLIC_DEMO_PASSWORD`, meant to be shared. `VIEWER` may read every SIEM page (GET only) except the audit log, and every write is refused by both the gateway and the owning service.

## Authorization

Realm roles are mapped from `realm_access.roles` to Spring authorities:

- `ADMIN` -> `ROLE_ADMIN`
- `SOC_MANAGER` -> `ROLE_SOC_MANAGER`
- `SECURITY_ANALYST` -> `ROLE_SECURITY_ANALYST`
- `VIEWER` -> `ROLE_VIEWER`

The API Gateway enforces route-level policy and each downstream service also validates JWTs and applies domain-specific role checks. The frontend uses roles only to hide controls.

| Capability | ADMIN | SOC_MANAGER | SECURITY_ANALYST | VIEWER |
|---|:-:|:-:|:-:|:-:|
| Read events, alerts, incidents, rules, detection, search, threat intel | ✓ | ✓ | ✓ | ✓ |
| Ingest events; triage alerts (transition, assign, note); create/update incidents | ✓ | ✓ | ✓ | |
| Test rules in the sandbox (`POST /api/rules/test`) | ✓ | ✓ | ✓ | |
| Enable/disable/re-grade rules; manage indicators | ✓ | ✓ | | |
| Read the audit log | ✓ | ✓ | | |

Every cell is asserted at the gateway by `AuthorizationMatrixTest` (68 cells plus anonymous access).

## Hardening

- **Input limits:** request bodies over 2 MB return `413` at the gateway and again in each service. Batches are capped at 500 events, event attributes at 32 keys, search queries at 256 characters, and rule tests at 500 events. Search uses `simple_query_string` (no scripts or regex).
- **Correlation IDs:** client-supplied `X-Correlation-Id` values are accepted only if they match `[A-Za-z0-9._-]{8,64}`; anything else is replaced, which prevents log injection.
- **Least-privilege database:** in production the services connect as `siem_service` (no superuser, `CREATEROLE` or `CREATEDB`). It owns only the application tables. `infrastructure/postgres/init-app-role.sh` creates the role on a fresh volume and `adopt-app-role.sql` adopts existing ones.
- **Containers:** Spring images run as uid 10001 and the frontend as nginx uid 101. Helm pods set `runAsNonRoot`, a read-only root filesystem, dropped capabilities, `seccompProfile: RuntimeDefault`, and no service-account token.
- **Browser:** nginx serves a strict Content-Security-Policy (script/style `'self'`, `connect-src` limited to the API and identity origins, `frame-ancestors 'none'`), plus `X-Content-Type-Options` and `Referrer-Policy`.
- **Actuator:** only `health`, `info` and `prometheus` are exposed.
- **Accountability:** the actor on every change comes from the JWT, never from the request body.
  - Alert workflow history and rule changes are recorded.
  - Incident timeline entries are recorded.
  - All of these reach the append-only `siem_audit_log`; the database rejects `UPDATE`/`DELETE` there and on `siem_alert_history`.
- **Supply chain (CI):**
  - Workflows: actions pinned to commit SHAs, read-only default permissions.
  - Secret and code scanning: gitleaks and CodeQL.
  - Trivy scans dependencies and IaC. Ignores are scoped to specific files in `.trivyignore.yaml`.
  - `npm audit` fails the build on high-severity issues in production dependencies.
- **Deployment:** `deploy.sh` ships only a committed revision (`git archive`) and records `DEPLOYED_SHA` on the server. The GitHub deploy workflow requires a full SHA on `main` whose CI passed, plus approval in the `production` environment.

## Notes

- The `siem-demo` client enables only the password (direct access) grant and is intended for local development and test automation. It is disabled in production (see above).
- The e2e build mode (`vite build --mode e2e`) replaces Keycloak with a fixed identity for Playwright. That code is removed from production builds at compile time, which CI's normal build verifies.
- Event payloads are validated with Bean Validation (`@Valid`) at the ingestion boundary before they are published to Kafka.
- The gateway and ingestion-service both require `ADMIN`, `SOC_MANAGER`, or `SECURITY_ANALYST` for event writes; viewer-level accounts can read alerts but cannot transition alert status.
