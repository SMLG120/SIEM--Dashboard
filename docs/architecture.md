# Architecture

Phase 1 establishes the monorepo, service boundaries, API Gateway, local infrastructure, and frontend shell. Phase 2 adds Keycloak authentication, JWT validation, and RBAC. Phase 3 implements the event ingestion API, Kafka event backbone, detection rules engine, and alert lifecycle. Phase 4 wires the gateway to OIDC for routes and phase 5 continues alert management. Phase 6 implements alert correlation into incidents with a full investigation UI. Phase 7 adds durable PostgreSQL storage for events, alerts, and incidents. Phase 8 puts a Redis token-bucket rate limiter on every gateway route. Phase 9 streams rule changes over Kafka so edits apply on every detection instance. Phase 10 adds a search service with OpenSearch aggregation. Phase 11 adds Prometheus/Grafana observability and Kubernetes/Helm deployment.

## Services

- API Gateway: central HTTP entry point, route owner, OIDC resource-server enforcement, and Redis-backed rate limiting (token bucket applied as a default filter on every route).
- Auth Service: identity integration facade for Keycloak/OIDC.
- Ingestion Service: event ingestion API (`POST /api/events`) and Kafka producer (`siem.events`).
- Detection Service: Kafka consumer (`siem.events`), packaged rule evaluation, alert producer (`siem.alerts`), and rule-change consumer (`siem.rules`).
- Alert Service: alert lifecycle API (`GET /api/alerts`, workflow, assign, notes) backed by `siem.alerts`.
- Incident Service: Kafka consumer (`siem.alerts`) that correlates alerts into incidents; incident API (`/api/incidents`) with timeline, notes, and status lifecycle; publishes lifecycle events to `siem.incidents`.
- Search Service: Kafka consumers for `siem.events` and `siem.alerts` that index documents into OpenSearch and serve full-text search and severity aggregations (`/api/search`).
- Threat Intelligence Service: future indicator management and lookups.
- Audit Service: future append-only audit API and event sink.

## Event Flow

```text
POST /api/events (ingestion-service)
        |
        v
  Kafka siem.events
        |
        v
  detection-service rules engine  ------>  Kafka siem.alerts
        |                                      |        |
        |                                      |        +--> incident-service
 GET /api/detection/summary            alert-service     (correlation engine)
 GET /api/rules                        (workflow API)          |
                                                              v
                                                       GitHub incidents API
                                                       (status, notes, timeline)

  POST /api/rules/{id}/(enable|disable|severity) (detection-service)
        |
        v
  Kafka siem.rules  ------>  every detection instance applies the change live

  Kafka siem.events / siem.alerts
        |
        v
  search-service  ------>  OpenSearch (indices siem-events, siem-alerts)
        |
        v
  GET /api/search/summary | /events?q= | /alerts?q=
```

## Edge Protection (Phase 8)

- `RequestRateLimiter` is a gateway `default-filters` entry, so every routed request is metered; the gateway's own `/actuator/*` endpoints are not routed and therefore not metered.
- The `KeyResolver` keys the bucket on the authenticated principal name, falling back to a shared `anonymous` bucket for unauthenticated traffic.
- The limiter is a Redis token bucket, so limits are shared across gateway replicas. Defaults: `SIEM_RATE_LIMIT_REPLENISH=20` requests/s, `SIEM_RATE_LIMIT_BURST=40`; responses carry `X-RateLimit-Replenish-Rate`, `X-RateLimit-Burst-Capacity`, `X-RateLimit-Requested-Tokens`, `X-RateLimit-Remaining`, and excess requests get `429`.

## Streaming Rule Updates (Phase 9)

- `POST /api/rules/{id}/enable|disable|severity` applies the change to the local in-memory rule set, then publishes a `RuleChange` record to `siem.rules`.
- Every detection instance consumes `siem.rules` (group `detection-rules`) and applies the same change, so toggles are consistent cluster-wide; consumers ignore their own already-applied state and unknown rule ids.

## Incident Correlation

- Alerts are consumed from `siem.alerts` by the incident-service (`@KafkaListener`, group `incident-service`).
- Unresolved alerts sharing a `sourceIp` are grouped into one incident; a new `sourceIp` (or an incident-store miss) creates a new incident.
- Incident lifecycle: `OPEN -> INVESTIGATING -> CONTAINED -> RESOLVED -> CLOSED` (plus manual reopen for alerts via `RESOLVED -> OPEN`).
- Every state change, assignment, note, and linked alert appends a `TimelineEntry`; notes and related alerts are first-class collections on the incident.
- Incidents can be created manually via the API or UI and then linked to open alerts.
- Alert lifecycle (`OPEN -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED` plus reopen) tracks assignment and analyst notes on the alert detail.

## Data Stores

- PostgreSQL: durable write-behind storage (Phase 7). `ingestion-service` owns `siem_event`; `alert-service` owns `siem_alert` + `siem_alert_note`; `incident-service` owns `siem_incident` (child collections `related_alerts`, `timeline`, `notes` serialized into a `payload` JSON column). Each service applies its own idempotent `schema.sql` on startup against the shared `siem` database.
- Redis: gateway rate-limit token buckets (Phase 8), shared across gateway replicas.
- Kafka: event, alert, incident, and rule backbone (topics `siem.events`, `siem.alerts`, `siem.incidents`, `siem.rules`, 3 partitions each).
- OpenSearch: search/aggregation index for the search service (Phase 10). Indices `siem-events` and `siem-alerts` are auto-created on first document; severity aggregations use the `severity.keyword` sub-field and free-text queries are wildcard `query_string` searches. `SIEM_SEARCH_STORAGE=memory` swaps in a bounded in-memory index for environments without OpenSearch.
- Prometheus/Grafana: metric scraping and dashboards (Phase 11). Every service exposes `/actuator/prometheus` (public); detection publishes cumulative counters `siem_detection_events_evaluated_total` and `siem_detection_alerts_generated_total`. `infrastructure/prometheus/prometheus.yml` scrapes all nine services and relabels `job` into an `application` label for the provisioned Grafana dashboard.
- In-memory stores: ingestion keeps a bounded recent-event window (1000); alert-service keeps a bounded alert window (1000); incident-service keeps a bounded incident window (100). These remain the low-latency read model and are rehydrated from PostgreSQL on startup (`*Hydrator` components listening for `ApplicationReadyEvent`), so lists survive service restarts.

Every mutation writes through to the owning table before the API responds; Kafka replays are idempotent (insert if absent, silent update WHERE EXISTS).