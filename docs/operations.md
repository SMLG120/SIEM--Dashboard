# Operations Guide

Verification steps and fixes for the local Docker Compose stack. See [deployment.md](deployment.md) for ports and configuration.

## PostgreSQL Persistence

Events, alerts, and incidents are durably stored in the shared `siem` database (owned tables per service, idempotent `schema.sql` applied on startup):

| Table | Owner | Persisted data |
|-------|-------|----------------|
| `siem_event` | ingestion-service | Full security events |
| `siem_alert` | alert-service | Alerts + `assigned_to` |
| `siem_alert_note` | alert-service | Analyst notes per alert |
| `siem_incident` | incident-service | Incident envelope + JSON child collection (`related_alerts`, `timeline`, `notes` in `payload`) |

Each service keeps its bounded in-memory store as the low-latency read model, writes through to PostgreSQL on every mutation, and rehydrates the store from the database at startup. This removes the "empty lists after restart" behavior for the three domain stores. (Detection-service keeps only a bounded in-memory recent-alert window; that one still uses the offset-reset procedure below if you replay.)

## Verification Checklist

- `http://localhost:15173` opens the SOC dashboard.
- Sign in as `admin` with `SIEM_DEMO_PASSWORD`.
- `http://localhost:18080/actuator/health` returns gateway health; `GET /api/events` returns `401` without a token.
- After `scripts/ingest-demo-events.sh`: `GET /api/events`, `/api/detection/summary`, `/api/rules`, `/api/alerts`, and `/api/incidents` return data.
- PostgreSQL persistence: restart a service (e.g. `docker compose restart alert-service`) — alerts/incidents remain listed because they are rehydrated from the DB on startup.
- Alert workflow endpoints return `200`: `/api/alerts/{id}/acknowledge|investigate|resolve|reopen|assign|notes`, `/api/alerts/{id}/workflow`.
- Incident endpoints return `200`: `GET /api/incidents`, `GET /api/incidents/{id}`, `PATCH`, `POST /{id}/notes`, `POST /{id}/alerts`.
- `http://localhost:18090` (Kafka UI, `docker compose --profile tools up -d kafka-ui`) shows topics `siem.events`, `siem.alerts`, `siem.incidents`, `siem.rules`.
- Rate limiting: burst a routed endpoint (e.g. 60 parallel `GET /api/detection/summary`) and confirm the excess returns `429` with `X-RateLimit-*` headers (default replenish 20/s, burst 40; override via `SIEM_RATE_LIMIT_REPLENISH` / `SIEM_RATE_LIMIT_BURST`).
- Rule updates: `POST /api/rules/{id}/disable` flips the rule to `enabled:false` in `GET /api/rules`; unknown id → `404`, bad severity → `400`.
- Search: after ingest, `GET /api/search/summary` returns `eventsCount`/`alertsCount` plus `eventsBySeverity`/`alertsBySeverity` buckets; `GET /api/search/events?q=ransomware` returns matches; `http://localhost:19200/_cat/indices` shows `siem-events` and `siem-alerts`.
- Observability: `http://localhost:19090/targets` shows all 9 services `up`; `http://localhost:13000` opens the provisioned "SIEM Overview" Grafana dashboard (sign in with `GF_SECURITY_ADMIN_*`).
- `http://localhost:18088` opens Keycloak; PostgreSQL, Redis, Kafka, and OpenSearch report healthy.
- Injected rows survive restarts: `docker exec -it siem_dashboard-postgres-1 psql -U siem_app -d siem -c "SELECT COUNT(*) FROM siem_event"` matches the number of ingested events.

## Troubleshooting

**Services come back with empty lists after restart.** Events, alerts, and incidents are now persisted in PostgreSQL and hydrated on startup, so these stores survive restarts. Detection-service still keeps a bounded in-memory recent-alert window, and Kafka consumer groups commit offsets, so a restarted service only receives new messages. Replay the topics by resetting the consumer-group offsets while the services are stopped:

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

**Search returns empty results or empty severity bars.** With the OpenSearch index, terms aggregations must target `severity.keyword` (analyzed `text` fields cannot be aggregated) and free-text search is a wildcard `query_string` so `ransomware` matches `RANSOMWARE_ACTIVITY`. Verify documents landed via `curl localhost:19200/_cat/indices`.
