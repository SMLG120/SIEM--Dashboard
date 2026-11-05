# Threat Model

STRIDE summary for the local Compose deployment. Items marked **local-only** must change before the stack is reachable from other machines.

| Threat | Mitigation | Residual risk |
|---|---|---|
| **Spoofing** | Keycloak-issued JWTs are validated (signature, issuer, `aud: api-gateway`) by the gateway and every service. Brute-force lockout after 5 failures; 12-character minimum password policy. | The `siem-demo` client allows the password grant for scripting; disable it outside development. |
| **Tampering** | Bean Validation on every request body; field limits match database columns; batch ingestion capped at 500 events. Kafka is reachable only from the Compose network and loopback. | **Local-only:** Kafka uses PLAINTEXT without authentication; enable SASL/TLS and topic ACLs for shared use. |
| **Repudiation** | Rule changes are logged with the acting user and replayable from `siem.rules`. Incident timelines and analyst notes record the authenticated user. | Alert status changes and assignments are not yet attributed; an append-only audit service is on the roadmap. |
| **Information disclosure** | No default credentials: Compose refuses to start without secrets in `.env` (gitignored and excluded from Docker builds). All host ports bind to `127.0.0.1`; Grafana anonymous access is disabled; Redis requires a password. | **Local-only:** OpenSearch runs with its security plugin disabled and Keycloak runs `start-dev` over HTTP. |
| **Denial of service** | Redis token-bucket rate limiting per user on every gateway route; malformed Kafka records are logged and skipped instead of blocking consumers; per-container memory limits. | Rate limits are per user, so a large number of accounts could still exhaust capacity. |
| **Elevation of privilege** | Realm roles are enforced server-side twice (gateway route rules and each service's own security config); the frontend uses roles only for presentation. Containers run as non-root users. | — |
| **Data integrity** | Writes are persisted to PostgreSQL before the in-memory read model changes; alert transitions are atomic and validated; Kafka redeliveries are idempotent. | Single PostgreSQL and Kafka broker; no replication in the local stack. |
