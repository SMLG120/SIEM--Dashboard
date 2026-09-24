# Architecture

Phase 1 establishes the monorepo, service boundaries, API Gateway, local infrastructure, and frontend shell. Phase 2 adds Keycloak authentication, JWT validation, and RBAC. Phase 3 implements the event ingestion API, Kafka event backbone, detection rules engine, and alert lifecycle. Phase 4 wires the gateway to OIDC for routes and phase 5 continues alert management. Phase 6 implements alert correlation into incidents with a full investigation UI.

## Services

- API Gateway: central HTTP entry point, route owner, and OIDC resource-server enforcement.
- Auth Service: identity integration facade for Keycloak/OIDC.
- Ingestion Service: event ingestion API (`POST /api/events`) and Kafka producer (`siem.events`).
- Detection Service: Kafka consumer (`siem.events`), packaged rule evaluation, and alert producer (`siem.alerts`).
- Alert Service: alert lifecycle API (`GET /api/alerts`, workflow, assign, notes) backed by `siem.alerts`.
- Incident Service: Kafka consumer (`siem.alerts`) that correlates alerts into incidents; incident API (`/api/incidents`) with timeline, notes, and status lifecycle; publishes lifecycle events to `siem.incidents`.
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
```

## Incident Correlation

- Alerts are consumed from `siem.alerts` by the incident-service (`@KafkaListener`, group `incident-service`).
- Unresolved alerts sharing a `sourceIp` are grouped into one incident; a new `sourceIp` (or an incident-store miss) creates a new incident.
- Incident lifecycle: `OPEN -> INVESTIGATING -> CONTAINED -> RESOLVED -> CLOSED` (plus manual reopen for alerts via `RESOLVED -> OPEN`).
- Every state change, assignment, note, and linked alert appends a `TimelineEntry`; notes and related alerts are first-class collections on the incident.
- Incidents can be created manually via the API or UI and then linked to open alerts.
- Alert lifecycle (`OPEN -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED` plus reopen) tracks assignment and analyst notes on the alert detail.

## Data Stores

- PostgreSQL: transactional records in later phases.
- Redis: rate limit and short-lived state in later phases.
- Kafka: event, alert, and incident backbone (topics `siem.events`, `siem.alerts`, `siem.incidents`, 3 partitions each).
- In-memory stores: ingestion keeps a bounded recent-event window (1000); alert-service keeps a bounded alert window (1000); incident-service keeps a bounded incident window (100). Persistence is deferred to Phase 4+.

Note: in-memory state resets on service restart. Consumer groups commit offsets, so a restarted service that already consumed a topic will only receive new messages. To replay an empty store, reset the consumer-group offsets to earliest (e.g. Kafka consumer-groups `--reset-offsets --to-earliest` while the service is stopped).