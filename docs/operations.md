# Operations Guide

Verification steps and fixes for the local Docker Compose stack. See [deployment.md](deployment.md) for ports and configuration.

## PostgreSQL Persistence

PostgreSQL is the system of record. Each service applies its own versioned Flyway migrations from `db/migration/<service>`. Every service tracks them in its own history table (`flyway_history_<service>`), with baseline version 0, so v1 databases are adopted in place.

| Table | Owner | Data |
|-------|-------|------|
| `siem_event`, `siem_outbox` | ingestion | Events (with `attributes` JSON) and the transactional outbox |
| `siem_alert`, `siem_alert_note`, `siem_alert_history` | alert | Alerts with rule version, ATT&CK and evidence; notes; append-only workflow history |
| `siem_incident`, `siem_incident_alert` | incident | Incidents (timeline and notes in `payload`) and alert links |
| `siem_indicator`, `siem_sighting` | threat-intelligence | Analyst/demo indicators and the events that matched them |
| `siem_audit_log` | audit | Append-only audit trail |

APIs read straight from PostgreSQL, so lists survive restarts. The exception is detection: its correlation state and recent-alert window are in memory, by design.

**Upgrading a v1 database:** start the v2 services against the existing volume. The migrations add columns, tables and indexes without rewriting data. Incident links are backfilled from each incident's `payload`. This was verified on a copy of a v1 database: all 76 events, 64 alerts and 24 incidents were preserved, and 64 links were backfilled. For production, also run `infrastructure/postgres/adopt-app-role.sql` once to move table ownership to the least-privilege `siem_service` role (see [production.md](production.md)).

## Verification Checklist

- `http://localhost:15173` opens the SOC dashboard.
- Sign in as `admin` with `SIEM_DEMO_PASSWORD`.
- `http://localhost:18080/actuator/health` returns gateway health; `GET /api/events` returns `401` without a token.
- After `scripts/ingest-demo-events.sh`: `GET /api/events`, `/api/detection/summary`, `/api/rules`, `/api/alerts`, and `/api/incidents` return data.
- PostgreSQL persistence: restart a service (e.g. `docker compose restart alert-service`). Alerts and incidents remain listed.
- v2 scenario: `scripts/ingest-demo-events.sh sample-data/v2-attack-scenario.json`. `GET /api/alerts/search?ruleId=SIEM-1009` then returns an alert, and so does each of `SIEM-1008`…`SIEM-1018` except `SIEM-1013`, and `GET /api/threat-intel/sightings` lists matches.
- Audit: as a manager, disable and re-enable a rule. `GET /api/audit/events?resourceType=RULE` shows both changes with your username.
- Dead letters: topics `siem.events.DLT` / `siem.alerts.DLT` stay empty during normal operation. A message there is a poison record worth inspecting.
- Alert workflow endpoints return `200`: `/api/alerts/{id}/acknowledge|investigate|resolve|reopen|assign|notes`, `/api/alerts/{id}/workflow`.
- Incident endpoints return `200`: `GET /api/incidents`, `GET /api/incidents/{id}`, `PATCH`, `POST /{id}/notes`, `POST /{id}/alerts`.
- `http://localhost:18090` (Kafka UI, `docker compose --profile tools up -d kafka-ui`) shows topics `siem.events`, `siem.alerts`, `siem.incidents`, `siem.rules`, `siem.audit` and the `*.DLT` topics.
- Rate limiting: burst a routed endpoint (e.g. 60 parallel `GET /api/detection/summary`) and confirm the excess returns `429` with `X-RateLimit-*` headers (default replenish 20/s, burst 40; override via `SIEM_RATE_LIMIT_REPLENISH` / `SIEM_RATE_LIMIT_BURST`).
- Rule updates: `POST /api/rules/{id}/disable` flips the rule to `enabled:false` in `GET /api/rules`; unknown id → `404`, bad severity → `400`.
- Search: after ingest, `GET /api/search/summary` returns `eventsCount`/`alertsCount` plus `eventsBySeverity`/`alertsBySeverity` buckets; `GET /api/search/events?q=ransomware` returns matches; `http://localhost:19200/_cat/indices` shows `siem-events` and `siem-alerts`.
- Observability: `http://localhost:19090/targets` shows all 9 services `up`; `http://localhost:13000` opens the provisioned "SIEM Overview" Grafana dashboard (sign in with `GF_SECURITY_ADMIN_*`).
- `http://localhost:18088` opens Keycloak; PostgreSQL, Redis, Kafka, and OpenSearch report healthy.
- Injected rows survive restarts: `docker exec -it siem_dashboard-postgres-1 psql -U siem_app -d siem -c "SELECT COUNT(*) FROM siem_event"` matches the number of ingested events.

## Troubleshooting

**Replaying a topic.** Consumers commit offsets, so a restarted service receives only new messages. Every consumer is idempotent, so replaying is safe. To reprocess, reset the consumer group's offsets while the services are stopped:

```bash
docker compose stop alert-service incident-service
docker exec siem_dashboard-kafka-1 /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 --group alert-service --reset-offsets --to-earliest --all-topics --execute
docker exec siem_dashboard-kafka-1 /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 --group incident-service --reset-offsets --to-earliest --all-topics --execute
docker compose start alert-service incident-service
```

**`@PathVariable` mappings return HTTP 400.** The root `pom.xml` must keep `<maven.compiler.parameters>true</maven.compiler.parameters>` (there is no `spring-boot-starter-parent`), otherwise Spring cannot resolve parameter names.

**Kafka consumer sees no messages.** Kafka YAML must be nested under `spring.kafka.*`; a root-level `kafka:` block is silently ignored and consumers fall back to `localhost:9092`. Compose overrides `KAFKA_BOOTSTRAP_SERVERS` to `kafka:9092` at runtime.

**Tests crash mocking `KafkaTemplate`.** On JDK 27, Byte Buddy cannot proxy `KafkaTemplate`; tests subclass it and override `send()` instead of using Mockito.

**Gateway returns `500` on every routed request.** A `RequestRateLimiter` default filter must use the explicit `name`/`args` form with `redis-rate-limiter.replenishRate` / `redis-rate-limiter.burstCapacity`. The shortcut form (`RequestRateLimiter=replenishRate=${...:20},…`) binds the raw placeholder string and fails at runtime with `No Configuration found for route … or defaultFilters`.

**No `429`s under a burst.** The rate limiter applies to *routed* requests only — the gateway's own `/actuator/*` endpoints bypass it. Also confirm Redis is healthy (`docker compose ps redis`) and the key resolver is finding your principal (anonymous clients share the `anonymous` bucket).

**Prometheus targets are `down`.** Scraping needs `/actuator/prometheus` to be `permitAll` in each service `SecurityConfig` (401 responses mark targets down). The bundled `prometheus.yml` also relabels `job` into an `application` label so the Grafana dashboard panels resolve.

**Search returns empty results or empty severity bars.** The search service creates explicit mappings at startup (`dynamic: false`; text fields have a `.keyword` sub-field used for aggregations). Indices auto-created by v1 have dynamic mappings and still work. Queries use `simple_query_string`: use `ransom*` for a prefix match. Check that documents landed with `curl localhost:19200/_cat/indices`. If OpenSearch is down, search endpoints return `503` and indexing retries, then dead-letters.

**Rule change returns `503`.** The detection service publishes the change to Kafka *before* applying it, so it is never applied on only one instance. Check that Kafka is healthy and retry.

**Audit log is missing an alert change.** Alert history is forwarded to `siem.audit` after commit, on a best-effort basis. The authoritative copy is always `GET /api/alerts/{id}/history`.
