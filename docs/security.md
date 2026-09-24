# Security

Phase 2 implements Keycloak-backed OAuth2/OpenID Connect authentication and JWT resource-server validation. Phase 3 adds event schema validation and role-gated ingestion/detection/alert APIs.

Secrets are not committed. Local development uses `.env`, which is ignored by Git.

## Authentication

- Keycloak realm: `enterprise-siem`
- Public browser client: `siem-dashboard`
- API resource client: `api-gateway`
- Demo/test client: `siem-demo` (confidential, password-grant only) used by `scripts/ingest-demo-events.sh`
- Frontend flow: Authorization Code with PKCE through `keycloak-js`
- Backend validation: Spring Security OAuth2 resource server JWT validation

## Local Test Credentials

- Keycloak admin console: `admin` / `admin123`
- Realm users (`admin`, `sam.admin`, `sam.manager`, `sam.analyst`, `sam.viewer`): password from `SIEM_DEMO_PASSWORD` in `.env` (default `admin123`)

## Authorization

Realm roles are mapped from `realm_access.roles` to Spring authorities:

- `ADMIN` -> `ROLE_ADMIN`
- `SOC_MANAGER` -> `ROLE_SOC_MANAGER`
- `SECURITY_ANALYST` -> `ROLE_SECURITY_ANALYST`
- `VIEWER` -> `ROLE_VIEWER`

The API Gateway enforces route-level policy and each downstream service also validates JWTs and applies domain-specific role checks.

## Phase 3 Notes

- The `siem-demo` client enables only the password (direct access) grant and is intended exclusively for local development and test automation; it has no service account and cannot mint app tokens by itself.
- Event payloads are validated with Bean Validation (`@Valid`) at the ingestion boundary before they are published to Kafka.
- The gateway and ingestion-service both require `ADMIN`, `SOC_MANAGER`, or `SECURITY_ANALYST` for event writes; viewer-level accounts can read alerts but cannot transition alert status.
