# Security

Authentication is OAuth2/OpenID Connect through Keycloak. Every service is a JWT resource server that validates the signature, issuer and `api-gateway` audience, and applies role checks of its own in addition to the gateway route rules. Request bodies are validated with Bean Validation before anything reaches Kafka or PostgreSQL.

Secrets are not committed. Local development uses `.env`, which is ignored by Git.

## Authentication

- Keycloak realm: `enterprise-siem`
- Public browser client: `siem-dashboard`
- API resource client: `api-gateway`
- Demo/test client: `siem-demo` (confidential, password-grant only) used by `scripts/ingest-demo-events.sh`
- Frontend flow: Authorization Code with PKCE through `keycloak-js`
- Backend validation: Spring Security OAuth2 resource server JWT validation

## Local Test Credentials

- Keycloak admin console: `KEYCLOAK_ADMIN_USERNAME` / `KEYCLOAK_ADMIN_PASSWORD` from `.env`
- Realm users (`admin`, `sam.admin`, `sam.manager`, `sam.analyst`, `sam.viewer`): password from `SIEM_DEMO_PASSWORD` in `.env` (no default; Compose refuses to start without it)
- Public read-only `demo` user (`VIEWER`): password from `SIEM_PUBLIC_DEMO_PASSWORD`, meant to be shared. `VIEWER` may read every SIEM page (GET only) but not the audit or threat-intel services, and every write is refused by both the gateway and the owning service.

## Authorization

Realm roles are mapped from `realm_access.roles` to Spring authorities:

- `ADMIN` -> `ROLE_ADMIN`
- `SOC_MANAGER` -> `ROLE_SOC_MANAGER`
- `SECURITY_ANALYST` -> `ROLE_SECURITY_ANALYST`
- `VIEWER` -> `ROLE_VIEWER`

The API Gateway enforces route-level policy and each downstream service also validates JWTs and applies domain-specific role checks.

## Notes

- The `siem-demo` client enables only the password (direct access) grant and is intended exclusively for local development and test automation; it has no service account and cannot mint app tokens by itself.
- Event payloads are validated with Bean Validation (`@Valid`) at the ingestion boundary before they are published to Kafka.
- The gateway and ingestion-service both require `ADMIN`, `SOC_MANAGER`, or `SECURITY_ANALYST` for event writes; viewer-level accounts can read alerts but cannot transition alert status.
