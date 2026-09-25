# Enterprise SIEM Platform

A phased, production-style monorepo for an enterprise Security Information and Event Management (SIEM) platform. Events are ingested through a gateway, streamed over Kafka, evaluated by a detection rules engine, triaged as alerts, and correlated into incidents — all managed through an authenticated SOC dashboard.

## Build Status

Implemented phases (start to end):

| Phase | Delivered |
|-------|-----------|
| 1 | Monorepo foundation, service boundaries, Spring Cloud Gateway, local infrastructure (PostgreSQL, Redis, Kafka, Keycloak), React/Vite dashboard shell |
| 2 | Keycloak-backed OIDC authentication, JWT validation, role-based access control (gateway + downstream), frontend login/logout |
| 3 | Event ingestion API, `siem.events` Kafka backbone, packaged detection rules engine, alert generation and `siem.alerts` stream |
| 4 | Gateway OIDC resource-server wiring, route-level RBAC, cross-service token propagation |
| 5 | Alert management hardening: full lifecycle (`OPEN → ACKNOWLEDGED → INVESTIGATING → RESOLVED` + reopen), assignment, analyst notes, alert workflow API |
| 6 | Incident management: `siem.alerts` correlation into incidents (`siem.incidents` stream), incident lifecycle, timeline, notes, manual alert linking, dedicated dashboard pages |
| 7 | PostgreSQL persistence: write-behind stores for events, alerts, and incidents (incl. assignments, notes, timelines) with startup hydration of the in-memory hot stores |
| 8 | Redis-backed distributed rate limiting at the gateway (`RequestRateLimiter` + user key resolver, token bucket, tunable replenish/burst), Redis cluster shims |
| 9 | Streaming rule management: rules are versioned in a `siem.rules` Kafka topic, toggles (enable/disable/severity) apply live across detection instances and the dashboard |
| 10 | Search & analytics: `OpenSearchSearchIndex` (full-text + severity aggregation), `SEARCH` role and `search-service` on `siem.events`/`siem.alerts` topics with OpenSearch persistence |
| 11 | Observability & delivery: Prometheus + Grafana (pre-provisioned SIEM dashboard), Micrometer counters, `/actuator/prometheus` per service, Prometheus relabeling, and Kubernetes / Helm deployment assets |

## Architecture

```text
React/Vite Dashboard :5173
        |
        v
API Gateway :8080  (OIDC + RBAC + Redis rate limiting, default filter on all routes)
        |
        +-- Auth Service :8081
        +-- Ingestion Service :8082
        +-- Detection Service :8083
        +-- Alert Service :8084
        +-- Incident Service :8085
        +-- Threat Intelligence Service :8086
        +-- Audit Service :8087
        +-- Search Service :8088

Platform dependencies:
PostgreSQL :5432
Redis :6379
Kafka :9092 (Kafka UI :8090)
Keycloak :8088
OpenSearch :9200
Prometheus :9090
Grafana :3000
```

Event flow:

```text
POST /api/events -> ingestion-service -> Kafka (siem.events)
                    -> detection-service (rules engine) -> Kafka (siem.alerts)
                    -> alert-service            -> GET /api/alerts (workflow, assign, notes)
                    -> incident-service (correlation)  -> Kafka (siem.incidents)
                                                       -> GET /api/incidents (timeline, notes, status)
                    -> search-service           -> OpenSearch (siem-events, siem-alerts)
                                                  -> GET /api/search (full-text + severity aggregation)

POST /api/rules/{id}/(enable|disable|severity) -> detection-service -> Kafka (siem.rules)
                    -> all detection instances apply the change live
```

Persistence: PostgreSQL (Phase 7) write-behind + startup hydration for the three domain stores; OpenSearch (Phase 10) for the search index; Redis (Phase 8) for distributed rate-limit state; Prometheus/Grafana (Phase 11) for metrics and dashboards.

## Technology Versions

- Java 21, Maven 3.9+
- Spring Boot 3.4.5, Spring Cloud 2024.0.3
- Spring Cloud Gateway 4.x (classic `spring.cloud.gateway.*` configuration prefix)
- Spring Security + Keycloak 26.7
- Kafka 3.7, PostgreSQL 16, Redis 7
- OpenSearch 2.15, Prometheus 2.53, Grafana 11.1
- React 19, TypeScript 5, Vite 7, TanStack Query

## Repository Structure

```text
backend/
  api-gateway/            Spring Cloud Gateway edge, OIDC + route-level RBAC
  auth-service/           Keycloak/OIDC integration facade
  ingestion-service/      POST /api/events, Kafka producer (siem.events)
  detection-service/      Kafka consumer (siem.events), rules engine, alert producer
  alert-service/          Alert lifecycle API, workflow/assign/notes
  incident-service/       Alert correlation, incident API, timeline/notes
  threat-intelligence-service/   stub service
  audit-service/          stub service
  search-service/         Kafka consumer (siem.events/siem.alerts), full-text search + aggregation API over OpenSearch
  common/                 Shared model, Kafka serialization, status helpers
frontend/
  siem-dashboard/         React + Vite + TanStack Query dashboard
infrastructure/
  docker/                 compose + Dockerfiles
  keycloak/               realm import template (enterprise-siem)
  kubernetes/ helm/ prometheus/ grafana/   Kubernetes manifests, Helm chart, Prometheus scrape config, Grafana provisioning
detection-rules/          (rules live in detection-service resources)
sample-data/security-events.json   38 demo events
scripts/ingest-demo-events.sh      token + ingest automation
docs/                     architecture, api, deployment, security, threat-model
```

## Dependency Choices

- **Spring Boot** — service runtime, Actuator, validation, testing conventions.
- **Spring Cloud Gateway** — central edge and route composition (7 routes).
- **Spring Security** — validates Keycloak JWTs, enforces RBAC at gateway and downstream.
- **Keycloak** — OAuth2/OIDC identity instead of custom authentication.
- **Kafka** — event backbone between ingestion → detection → alerts → incidents.
- **PostgreSQL** — durable write-behind storage for events, alerts, and incidents (Phase 7).
- **Redis** — distributed token-bucket state for the gateway rate limiter (Phase 8).
- **OpenSearch** — search/aggregation index for events and alerts (Phase 10); switchable to an in-memory index for local runs without Docker.
- **Prometheus + Grafana** — metrics scraping and the pre-provisioned SIEM dashboard (Phase 11).
- **React + Vite + TanStack Query** — TypeScript SOC workflows with server-state caching.

## Local Setup

Prerequisites: Java 21, Maven 3.9+, Node 20+, Docker.

```bash
cp .env.example .env

# Build all backend modules (unit + integration tests)
mvn clean verify

# Run infrastructure + services
docker compose up --build

# Frontend (optional; a dev container also runs on :5173)
cd frontend/siem-dashboard && npm install && npm run dev
```

The Keycloak realm `enterprise-siem` is imported automatically from `infrastructure/keycloak/enterprise-siem-realm.json.template`.

### Default Credentials

- Keycloak admin console (`http://localhost:8088/admin`): `admin` / `admin123`
- Dashboard sign-in (`admin` or any `sam.*` user): password from `SIEM_DEMO_PASSWORD` in `.env` (default `admin123`)

### Roles and Capabilities

| Role | Capabilities |
|------|--------------|
| `ADMIN` | Everything |
| `SOC_MANAGER` | Event ingress, alert/incident/rule workflows |
| `SECURITY_ANALYST` | Event ingress, alert/incident investigation workflows |
| `VIEWER` | Dashboard read visibility (alerts/events); **no** incident access, **no** writes |

Access is enforced twice: route-level RBAC at the gateway and role checks inside every downstream service.

## Data Model and Kafka Topics

| Topic | Producer | Consumers | Notes |
|-------|----------|-----------|-------|
| `siem.events` | ingestion-service | detection-service, search-service | Raw ingested events, 3 partitions |
| `siem.alerts` | detection-service | alert-service, incident-service, search-service | Generated alerts (JSON via type headers), 3 partitions |
| `siem.incidents` | incident-service | (future consumers / audit) | Incident lifecycle events, 3 partitions |
| `siem.rules` | detection-service | detection-service (`detection-rules` group) | Rule enable/disable/severity changes, fanned out to every detection instance, 3 partitions |

Realm/test client `siem-demo` uses password-grant (Direct Access) for script automation.

### PostgreSQL Persistence (Phase 7)

Events, alerts, and incidents are durably stored in the shared `siem` database (owned tables per service, idempotent `schema.sql` applied on startup):

| Table | Owner | Persisted data |
|-------|-------|----------------|
| `siem_event` | ingestion-service | Full security events |
| `siem_alert` | alert-service | Alerts + `assigned_to` |
| `siem_alert_note` | alert-service | Analyst notes per alert |
| `siem_incident` | incident-service | Incident envelope + JSON child collection (`related_alerts`, `timeline`, `notes` in `payload`) |

Each service keeps its bounded in-memory store as the low-latency read model, writes through to PostgreSQL on every mutation, and rehydrates the store from the database at startup. This removes the "empty lists after restart" behavior for the three domain stores. (Detection-service keeps only a bounded in-memory recent-alert window; that one still uses the offset-reset procedure below if you replay.)

## Demo Walkthrough (start to end)

```bash
cp .env.example .env
docker compose up --build
scripts/ingest-demo-events.sh
```

The script requests an access token (password grant) and pushes the 38 sample events through `/api/events`. The pipeline then runs:

1. **Ingestion → Events.** Sample events appear live on the **Overview** strip and **Events** page (`GET /api/events`).
2. **Detection → Alerts.** The rules engine evaluates each event against `SIEM-1001` … `SIEM-1007` (malware, brute-force login, privilege escalation, port scan, exfiltration, critical-any, shell/payload). Matches become alerts on the **Alerts** page (`GET /api/alerts`).
3. **Alert workflow.** Acknowledge → Investigate → Resolve, Reopen on resolved alerts, plus per-alert assignment and analyst notes (`GET /api/alerts/{id}/workflow`).
4. **Correlation → Incidents.** The incident-service groups unresolved alerts that share a `sourceIp` into incidents. **Incidents** page lists them with severity, alert count, status, and assignee.
5. **Incident investigation.** Open an incident: transition status (`OPEN → INVESTIGATING → CONTAINED → RESOLVED → CLOSED`), assign an analyst, add notes, and link additional open alerts. Every action appends to the incident **timeline**. Manually create an incident from the page header if desired.

Detection rules (`backend/detection-service/src/main/resources/detection-rules.json`):

| Rule | Name | Triggers |
|------|------|----------|
| `SIEM-1001` | Critical Malware Detected | `MALWARE_DETECTED`, `RANSOMWARE_ACTIVITY` ≥ HIGH |
| `SIEM-1002` | Repeated Login Failures | `LOGIN_FAILURE` ≥ HIGH |
| `SIEM-1003` | Privilege Escalation Attempt | `PRIVILEGE_ESCALATION`, `TOR_UNKNOWN` ≥ HIGH |
| `SIEM-1004` | Network Reconnaissance Activity | `PORT_SCAN` ≥ MEDIUM |
| `SIEM-1005` | Data Exfiltration Attempt | `DATA_EXFILTRATION` |
| `SIEM-1006` | Suspicious Activity on Sensitive Asset | any event ≥ CRITICAL |
| `SIEM-1007` | Command Shell or Payload Activity | `COMMAND_SHELL`, `C2_BEACON`, `WEBSHELL` |

## Dashboard Pages

- **Command Overview** (`/`) — service health, platform readiness, recent alerts.
- **Security Events** (`/events`) — live event stream + manual event ingestion form.
- **Security Alerts** (`/alerts`) — status-filtered triage with lifecycle actions.
- **Incidents** (`/incidents`) — correlated/manual incidents, create form.
- **Incident Detail** (`/incidents/:id`) — timeline, related alerts, status/assignment, notes, alert linking.
- **Threat Intelligence** (`/intelligence`) — detection rules view (enable/disable/severity controls).
- **Search** (`/search`) — full-text search across ingested events and generated alerts with severity aggregation (backed by OpenSearch).
- **Platform** (`/platform`) — service status matrix.

## API Summary

All domain routes require a Keycloak bearer token. Full signatures in [`docs/api.md`](docs/api.md).

- `GET /api/events`, `POST /api/events` (+ `/batch`), `GET /api/events/{id}`
- `GET /api/rules`, `GET /api/rules/{id}`, `POST /api/rules/{id}/enable|disable|severity`
- `GET /api/detection/summary`, `GET /api/detection/alerts/{id}`
- `GET /api/alerts`, `GET /api/alerts/{id}`, `GET /api/alerts/{id}/workflow`
- `POST /api/alerts/{id}/acknowledge|investigate|resolve|reopen|assign|notes`
- `GET /api/incidents`, `GET /api/incidents/{id}`, `POST /api/incidents`, `PATCH /api/incidents/{id}`, `POST /api/incidents/{id}/notes`, `POST /api/incidents/{id}/alerts`
- `GET /api/search/summary`, `GET /api/search/events?q=&limit=`, `GET /api/search/alerts?q=&limit=` (OpenSearch-backed; `ADMIN`/`SOC_MANAGER`/`SECURITY_ANALYST`)
- `GET /api/{service}/internal/status` per service (`auth`, `events`, `detection`, `alerts`, `incidents`, `threat-intel`, `audit`, `search`)
- `GET /actuator/health`, `GET /actuator/prometheus` (public, for orchestration/scraping), `GET /actuator/gateway/routes` (protected)

## Verification Checklist

- `http://localhost:5173` opens the SOC dashboard.
- Sign in as `admin` / `admin123`.
- `http://localhost:8080/actuator/health` returns gateway health; `GET /api/events` returns `401` without a token.
- After `scripts/ingest-demo-events.sh`: `GET /api/events`, `/api/detection/summary`, `/api/rules`, `/api/alerts`, and `/api/incidents` return data.
- PostgreSQL persistence: restart a service (e.g. `docker compose restart alert-service`) — alerts/incidents remain listed because they are rehydrated from the DB on startup.
- Alert workflow endpoints return `200`: `/api/alerts/{id}/acknowledge|investigate|resolve|reopen|assign|notes`, `/api/alerts/{id}/workflow`.
- Incident endpoints return `200`: `GET /api/incidents`, `GET /api/incidents/{id}`, `PATCH`, `POST /{id}/notes`, `POST /{id}/alerts`.
- `http://localhost:8090` (Kafka UI) shows topics `siem.events`, `siem.alerts`, `siem.incidents`, `siem.rules`.
- Rate limiting: burst a routed endpoint (e.g. 60 parallel `GET /api/detection/summary`) and confirm the excess returns `429` with `X-RateLimit-*` headers (default replenish 20/s, burst 40; override via `SIEM_RATE_LIMIT_REPLENISH` / `SIEM_RATE_LIMIT_BURST`).
- Rule updates: `POST /api/rules/{id}/disable` flips the rule to `enabled:false` in `GET /api/rules`; unknown id → `404`, bad severity → `400`.
- Search: after ingest, `GET /api/search/summary` returns `eventsCount`/`alertsCount` plus `eventsBySeverity`/`alertsBySeverity` buckets; `GET /api/search/events?q=ransomware` returns matches; `http://localhost:9200/_cat/indices` shows `siem-events` and `siem-alerts`.
- Observability: `http://localhost:9090/targets` shows all 9 services `up`; `http://localhost:3000` opens the provisioned "SIEM Overview" Grafana dashboard (anonymous Viewer; `admin`/`admin123` to edit).
- `http://localhost:8088` opens Keycloak; PostgreSQL, Redis, Kafka, and OpenSearch report healthy.
- Injected rows survive restarts: `docker exec -it siemdashboard-postgres-1 psql -U siem_app -d siem -c "SELECT COUNT(*) FROM siem_event"` matches the number of ingested events.

## Troubleshooting

**Services come back with empty lists after restart.** Events, alerts, and incidents are now persisted in PostgreSQL and hydrated on startup, so these stores survive restarts. Detection-service still keeps a bounded in-memory recent-alert window, and Kafka consumer groups commit offsets, so a restarted service only receives new messages. Replay the topics by resetting the consumer-group offsets while the services are stopped:

```bash
docker compose stop alert-service incident-service
docker exec siemdashboard-kafka-1 /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 --group alert-service --reset-offsets --to-earliest --all-topics --execute
docker exec siemdashboard-kafka-1 /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 --group incident-service --reset-offsets --to-earliest --all-topics --execute
docker compose start alert-service incident-service
```

**`@PathVariable` mappings return HTTP 400.** The root `pom.xml` must keep `<maven.compiler.parameters>true</maven.compiler.parameters>` (there is no `spring-boot-starter-parent`), otherwise Spring cannot resolve parameter names.

**Kafka consumer sees no messages.** Kafka YAML must be nested under `spring.kafka.*`; a root-level `kafka:` block is silently ignored and consumers fall back to `localhost:9092`. Compose overrides `KAFKA_BOOTSTRAP_SERVERS` to `kafka:9092` at runtime.

**Tests crash mocking `KafkaTemplate`.** On JDK 27, Byte Buddy cannot proxy `KafkaTemplate`; tests subclass it and override `send()` instead of using Mockito.

**Gateway returns `500` on every routed request.** A `RequestRateLimiter` default filter must use the explicit `name`/`args` form with `redis-rate-limiter.replenishRate` / `redis-rate-limiter.burstCapacity`. The shortcut form (`RequestRateLimiter=replenishRate=${...:20},…`) binds the raw placeholder string and fails at runtime with `No Configuration found for route … or defaultFilters`.

**No `429`s under a burst.** The rate limiter applies to *routed* requests only — the gateway's own `/actuator/*` endpoints bypass it. Also confirm Redis is healthy (`docker compose ps redis`) and the key resolver is finding your principal (anonymous clients share the `anonymous` bucket).

**Prometheus targets are `down`.** Scraping needs `/actuator/prometheus` to be `permitAll` in each service `SecurityConfig` (401 responses mark targets down). The bundled `prometheus.yml` also relabels `job` into an `application` label so the Grafana dashboard panels resolve.

**Search returns empty results or empty severity bars.** With the OpenSearch index, terms aggregations must target `severity.keyword` (analyzed `text` fields cannot be aggregated) and free-text search is a wildcard `query_string` so `ransomware` matches `RANSOMWARE_ACTIVITY`. Verify documents landed via `curl localhost:9200/_cat/indices`.

## Phase 12 Preparation

Phases 8–11 are delivered and verified end-to-end: gateway rate limiting, streaming rule updates, the OpenSearch-backed search service, and Prometheus/Grafana observability plus Kubernetes/Helm assets. Natural next steps: external threat-intel feeds (TI service), append-only audit trail (audit service), alert/incident ML triage, and multi-region Kafka replication. See `docs/deployment.md`, `docs/security.md`, and `docs/threat-model.md`.