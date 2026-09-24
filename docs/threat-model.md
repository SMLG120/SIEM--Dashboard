# Threat Model

## Phase 3 STRIDE notes

- Spoofing: Keycloak-issued JWTs are validated by Spring Security at the gateway and every service.
- Tampering: Events are schema-validated at the ingestion boundary before entering Kafka; detection rules are packaged and immutable in this phase.
- Repudiation: Phase 5 and later will add append-only audit logging for state transitions. Alerts carry the triggering `eventId` for correlation.
- Information disclosure: Secrets are loaded from environment variables and not committed. Default local credentials (`admin`/`admin123`) are for test environments only.
- Denial of service: Redis-backed gateway rate limiting is still planned (Phase 6+).
- Elevation of privilege: Realm roles are enforced server-side at the gateway and downstream services; the frontend only uses roles for presentation.
- Data integrity: bounded in-memory stores are used; durability after restart requires persistent stores (Phase 4+).