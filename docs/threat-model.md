# Threat Model

STRIDE summary for the Compose deployment: local, and the single-server production profile behind Caddy. Items marked **private-network** depend on the component being reachable only inside the Compose network.

| Threat | Mitigation | Residual risk |
|---|---|---|
| **Spoofing** | Gateway and every service validate Keycloak JWTs (signature, issuer, `aud: api-gateway`). Brute-force lockout after 5 failures; 12-character password policy. Production realm disables the password-grant `siem-demo` client. Detection rules flag brute force and success-after-failures in the monitored telemetry. | Public `demo` viewer account is shared by design (read-only, rate-limited). |
| **Tampering** | Bean Validation and size limits on every body, enforced at the gateway (2 MB) and in each service. Batches ≤ 500, attributes ≤ 32 keys. Services use a least-privilege DB role. Rule changes can only be made via the authenticated API and are versioned. | **Private-network:** Kafka uses PLAINTEXT without ACLs; anyone on the Compose network could publish records. Enable SASL/TLS + ACLs for multi-host deployments. |
| **Repudiation** | Actor taken from the JWT for every change. Alert history and incident timelines are committed with the change. Rule changes, alert workflow and incident lifecycle feed the append-only `siem_audit_log` (DB triggers block `UPDATE`/`DELETE`). | Triggers stop the application, not the table owner. Audit forwarding is after-commit and best-effort: a Kafka outage at that moment loses the audit copy, though the source history row remains. Export to WORM storage for true immutability. |
| **Information disclosure** | No default credentials (Compose refuses to start without secrets). Host ports bind to `127.0.0.1`, with only Caddy (80/443) public. Grafana has no anonymous access; Redis requires a password. Actuator is limited to `health`/`info`/`prometheus`. CSP and security headers apply. The audit log is visible to managers only. | **Private-network:** OpenSearch runs with its security plugin disabled. |
| **Denial of service** | Redis token-bucket rate limiting per user; request-size limits; bounded correlation state (10k groups × 1k events per rule); poison Kafka records go to a DLT instead of blocking partitions; per-container memory limits. | Single broker, single DB on one VM; many accounts could still exhaust capacity. |
| **Elevation of privilege** | Roles are enforced twice (gateway + service), and the matrix is tested cell by cell. The UI uses roles only for presentation. Containers run as non-root; Helm pods use a read-only root FS and drop all capabilities. | — |
| **Data integrity** | Ingestion uses a transactional outbox. Consumers are idempotent (deterministic IDs, unique constraints). Workflow transitions use row locks, and incident correlation uses an advisory lock per source IP. Migrations are versioned by Flyway. | Correlation (threshold/sequence) state is in-memory per detection instance: exact for one instance, may miss or delay (never duplicate) alerts across restarts or with multiple instances. |

## Telemetry and demo data

All demo telemetry is simulated: `sample-data/` and the rule examples. The threat-intel demo seed uses RFC 5737 documentation IPs, an RFC 2606 domain and the harmless EICAR test-file hashes, and labels them `SIMULATED_DEMO`. No external feeds are connected.
