# Architecture

The platform is a set of event-driven Spring Boot services behind a single gateway:

1. Events enter over HTTP and are written to PostgreSQL together with an outbox row in one transaction.
2. A relay publishes the outbox to Kafka.
3. A rules engine turns events into alerts that carry evidence.
4. Alerts are triaged and correlated into incidents.

Every security-relevant change ends up in an append-only audit log. Other stores:

- **PostgreSQL** holds durable state.
- **OpenSearch** serves search.
- **Redis** backs gateway rate limiting.
- **Keycloak** issues the OIDC tokens that every service validates.

## Vertical slice

```text
 POST /api/events ──► ingestion ──► siem_event + outbox (1 tx) ──► relay ──► Kafka siem.events
                                                                              │
          ┌──────────────────────────────┬───────────────────────────────────┼─────────────────┐
          ▼                              ▼                                   ▼                 ▼
  detection (rules engine)        threat-intel                         search            (DLT on poison
  SINGLE / THRESHOLD / SEQUENCE   indicator match ─► siem_sighting      OpenSearch        records)
  evidence + ATT&CK + version
          │
          ▼  Kafka siem.alerts (alert id = hash(rule, event|group))
   ┌──────┴───────────────┐
   ▼                      ▼
 alert-service          incident-service
 siem_alert (+history)  correlate by source IP (advisory lock), siem_incident_alert links
 triage workflow        lifecycle + timeline
   │                      │
   ▼ siem.audit           ▼ siem.incidents (one record per timeline entry)
   └──────────► audit-service ◄── siem.rules (rule changes, compacted)
                siem_audit_log (append-only)

 React console ──► gateway (OIDC, RBAC, rate limit, size limit, correlation id) ──► services
```

## Services

| Service | Owns | Consumes | Produces |
|---|---|---|---|
| api-gateway | routing, edge RBAC, rate limiting, request-size limit, `X-Correlation-Id` | — | — |
| ingestion | `siem_event`, `siem_outbox` | — | `siem.events` (via outbox relay) |
| detection | rule catalogue (JSON + runtime changes) | `siem.events`, `siem.rules` | `siem.alerts`, `siem.rules` |
| alert | `siem_alert`, `siem_alert_note`, `siem_alert_history` | `siem.alerts` | `siem.audit` |
| incident | `siem_incident`, `siem_incident_alert` | `siem.alerts` | `siem.incidents` |
| search | OpenSearch indices `siem-events`, `siem-alerts` | `siem.events`, `siem.alerts` | — |
| threat-intelligence | `siem_indicator`, `siem_sighting` | `siem.events` | — |
| audit | `siem_audit_log` | `siem.rules`, `siem.audit`, `siem.incidents` | — |
| auth | Keycloak integration facade | — | — |

Each service applies its own Flyway migrations with a separate history table (`flyway_history_<service>`) in the shared `siem` database. In production it connects as the non-superuser `siem_service` role.

## Delivery guarantees

- **Ingestion → Kafka:** transactional outbox. An accepted event is never lost, even if Kafka is down when it arrives.
- **Consumers:** at-least-once. Every write is idempotent, so redelivery is safe:
  - Deterministic alert IDs.
  - `ON CONFLICT DO NOTHING` inserts.
  - Sightings are unique per (indicator, event, field).
  - Audit rows are unique per (topic, partition, offset).
- **Poison records:** a record that can never succeed (unparseable, or failing validation) goes to `<topic>.DLT` after the shared error handler stops retrying. It does not block the partition.
- **Workflow writes:** alert and incident transitions run in one database transaction with a `SELECT … FOR UPDATE` on the row. History and timeline entries commit with the change. Notifications to `siem.audit` and `siem.incidents` are sent *after* commit, on a best-effort basis.

## Detection engine

See [detection-rules.md](detection-rules.md). In summary:

- Rules are `SINGLE`, `THRESHOLD` (count, distinct, sum or periodicity) or `SEQUENCE`.
- Correlation state is in memory and bounded:
  - 10,000 groups per rule.
  - 1,000 events per group.
- Rule changes:
  1. The detection service publishes the change to the compacted `siem.rules` topic.
  2. Each instance applies it.
  3. Each instance replays the topic from offset 0 on startup, de-duplicated by change ID.

## Edge protection (gateway)

- **Rate limiting:** a Redis token bucket per authenticated user, with a shared `anonymous` bucket.
  - Defaults: 20 req/s, burst 40.
  - Configured by `SIEM_RATE_LIMIT_REPLENISH` / `SIEM_RATE_LIMIT_BURST`.
- **Request bodies:** above 2 MB they are rejected with `413` (`SIEM_MAX_REQUEST_SIZE`). Each service enforces the same limit again with a servlet filter.
- **Correlation IDs:** `X-Correlation-Id` is accepted if it matches `[A-Za-z0-9._-]{8,64}`; otherwise the gateway generates one. It is echoed on every response, including errors.
- **Actuator:** only `health`, `info` and `prometheus` are exposed. Everything else under `/actuator` is denied.

## Data stores

- **PostgreSQL 16:** system of record. Event attributes and alert evidence/ATT&CK are stored as JSON columns. `siem_alert_history` and `siem_audit_log` reject `UPDATE`/`DELETE` through triggers.
- **Kafka (KRaft, single broker locally):**
  - `siem.events`, `siem.alerts`, `siem.incidents`, `siem.audit`, `siem.rules` (compacted, infinite retention).
  - `*.DLT` topics, with 14-day retention.
- **OpenSearch:** explicit mappings (`dynamic: false`, text + keyword). Queries use `simple_query_string`, so user input cannot run scripts or regex. `SIEM_SEARCH_STORAGE=memory` swaps in a bounded in-memory index.
- **Redis:** gateway rate-limit buckets.
- **Prometheus/Grafana:** every service exposes `/actuator/prometheus`. Detection adds per-rule alert counters and a latency timer (`siem_detection_latency`). Threat intel adds `siem_threat_intel_sightings_total`.

## Known limits

- Threshold and sequence rules are exact only with a single detection instance, or when events are partitioned by the grouping key. State is lost on restart.
- The append-only triggers make tampering *evident* and stop the application from changing history. They do not stop the table owner from disabling them; real immutability needs WORM storage or export.
- Kafka uses PLAINTEXT, and OpenSearch runs without its security plugin. Both are reachable only on the private Compose network (see [threat-model.md](threat-model.md)).
