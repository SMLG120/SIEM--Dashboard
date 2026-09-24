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

## Architecture

```text
React/Vite Dashboard :5173
        |
        v
API Gateway :8080
        |
        +-- Auth Service :8081
        +-- Ingestion Service :8082
        +-- Detection Service :8083
        +-- Alert Service :8084
        +-- Incident Service :8085
        +-- Threat Intelligence Service :8086
        +-- Audit Service :8087

Platform dependencies:
PostgreSQL :5432
Redis :6379
Kafka :9092 (Kafka UI :8090)
Keycloak :8088
```

Event flow:

```text
POST /api/events -> ingestion-service -> Kafka (siem.events)
                    -> detection-service (rules engine) -> Kafka (siem.alerts)
                    -> alert-service            -> GET /api/alerts (workflow, assign, notes)
                    -> incident-service (correlation)  -> Kafka (siem.incidents)
                                                       -> GET /api/incidents (timeline, notes, status)
```

Real event persistence and observability dashboards are intentionally deferred to later phases. All service stores are in-memory (bounded windows).

## Technology Versions

- Java 21, Maven 3.9+
- Spring Boot 3.4.5, Spring Cloud 2024.0.3
- Spring Cloud Gateway 4.x (classic `spring.cloud.gateway.*` configuration prefix)
- Spring Security + Keycloak 26.7
- Kafka 3.7, PostgreSQL 16, Redis 7
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
  common/                 Shared model, Kafka serialization, status helpers
frontend/
  siem-dashboard/         React + Vite + TanStack Query dashboard
infrastructure/
  docker/                 compose + Dockerfiles
  keycloak/               realm import template (enterprise-siem)
  kubernetes/ helm/ prometheus/ grafana/   future deployment targets
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
- **PostgreSQL / Redis** — reserved for later phases (persistence, rate limiting, caching).
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
| `siem.events` | ingestion-service | detection-service | Raw ingested events, 3 partitions |
| `siem.alerts` | detection-service | alert-service, incident-service | Generated alerts (JSON via type headers), 3 partitions |
| `siem.incidents` | incident-service | (future consumers / audit) | Incident lifecycle events, 3 partitions |

Realm/test client `siem-demo` uses password-grant (Direct Access) for script automation.

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
- **Threat Intelligence** (`/intelligence`) — detection rules view.
- **Platform** (`/platform`) — service status matrix.

## API Summary

All domain routes require a Keycloak bearer token. Full signatures in [`docs/api.md`](docs/api.md).

- `GET /api/events`, `POST /api/events` (+ `/batch`), `GET /api/events/{id}`
- `GET /api/rules`, `GET /api/rules/{id}`
- `GET /api/detection/summary`, `GET /api/detection/alerts/{id}`
- `GET /api/alerts`, `GET /api/alerts/{id}`, `GET /api/alerts/{id}/workflow`
- `POST /api/alerts/{id}/acknowledge|investigate|resolve|reopen|assign|notes`
- `GET /api/incidents`, `GET /api/incidents/{id}`, `POST /api/incidents`, `PATCH /api/incidents/{id}`, `POST /api/incidents/{id}/notes`, `POST /api/incidents/{id}/alerts`
- `GET /api/{service}/internal/status` per service (`auth`, `events`, `detection`, `alerts`, `incidents`, `threat-intel`, `audit`)
- `GET /actuator/health`, `GET /actuator/gateway/routes` (protected)

## Verification Checklist

- `http://localhost:5173` opens the SOC dashboard.
- Sign in as `admin` / `admin123`.
- `http://localhost:8080/actuator/health` returns gateway health; `GET /api/events` returns `401` without a token.
- After `scripts/ingest-demo-events.sh`: `GET /api/events`, `/api/detection/summary`, `/api/rules`, `/api/alerts`, and `/api/incidents` return data.
- Alert workflow endpoints return `200`: `/api/alerts/{id}/acknowledge|investigate|resolve|reopen|assign|notes`, `/api/alerts/{id}/workflow`.
- Incident endpoints return `200`: `GET /api/incidents`, `GET /api/incidents/{id}`, `PATCH`, `POST /{id}/notes`, `POST /{id}/alerts`.
- `http://localhost:8090` (Kafka UI) shows topics `siem.events`, `siem.alerts`, `siem.incidents`.
- `http://localhost:8088` opens Keycloak; PostgreSQL and Redis report healthy.

## Troubleshooting

**Services come back with empty lists after restart.** Kafka consumer groups commit offsets, so a restarted service only receives new messages. The in-memory stores then start empty. Replay the topics by resetting the consumer-group offsets while the services are stopped:

```bash
docker compose stop alert-service incident-service
docker exec siemdashboard-kafka-1 /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 --group alert-service --reset-offsets --to-earliest --all-topics --execute
docker exec siemdashboard-kafka-1 /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 --group incident-service --reset-offsets --to-earliest --all-topics --execute
docker compose start alert-service incident-service
```

**`@PathVariable` mappings return HTTP 400.** The root `pom.xml` must keep `<maven.compiler.parameters>true</maven.compiler.parameters>` (there is no `spring-boot-starter-parent`), otherwise Spring cannot resolve parameter names.

**Kafka consumer sees no messages.** Kafka YAML must be nested under `spring.kafka.*`; a root-level `kafka:` block is silently ignored and consumers fall back to `localhost:9092`. Compose overrides `KAFKA_BOOTSTRAP_SERVERS` to `kafka:9092` at runtime.

**Tests crash mocking `KafkaTemplate`.** On JDK 27, Byte Buddy cannot proxy `KafkaTemplate`; tests subclass it and override `send()` instead of using Mockito.

## Phase 7 Preparation

Future phases can add persistent stores (PostgreSQL write-behind for events, alerts, incidents), streaming rule updates, OpenSearch aggregation, and observability dashboards. Deployment targets already scaffolded under `infrastructure/` (Kubernetes, Helm, Prometheus, Grafana); see `docs/deployment.md`, `docs/security.md`, and `docs/threat-model.md`.