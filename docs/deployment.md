# Deployment

The local stack is Docker Compose based. It brings up all nine backend services, the React dashboard, and the platform dependencies (PostgreSQL, Redis, Kafka, Keycloak, OpenSearch) plus observability (Prometheus, Grafana):

```bash
cp .env.example .env
docker compose up --build
```

## Host Ports

| Port | Service |
|------|---------|
| 8080 | API Gateway |
| 8088 | Keycloak (host) |
| 5173 | SOC Dashboard |
| 8090 | Kafka UI |
| 9200 | OpenSearch |
| 9090 | Prometheus |
| 3000 | Grafana |

Backend services other than the gateway are internal to the Compose network and are reached through the gateway only.

## Configuration

Replace the placeholder values in `.env`, especially:

- `KEYCLOAK_ADMIN_PASSWORD`
- `SIEM_DEMO_PASSWORD`
- `POSTGRES_PASSWORD` (`ingestion-service`, `alert-service`, and `incident-service` connect with `POSTGRES_USER` / `POSTGRES_PASSWORD` against `POSTGRES_DB`)
- `GF_SECURITY_ADMIN_PASSWORD` (Grafana; defaults to `admin123`)

The repository ships test-friendly defaults (`admin` / `admin123` for Keycloak, Grafana, and the realm demo users) so the stack boots and the demo script works without edits. Change them for any shared environment.

Useful runtime knobs:

- `SIEM_RATE_LIMIT_REPLENISH` / `SIEM_RATE_LIMIT_BURST` — gateway token-bucket defaults (20 req/s, burst 40).
- `SIEM_SEARCH_STORAGE` — `opensearch` (default in Compose) or `memory` for the bounded in-memory search index.

Services connect to PostgreSQL through `SPRING_DATASOURCE_*` (overridable locally via `DB_URL` / `DB_USERNAME` / `DB_PASSWORD`). If you run the three domain services outside Docker, point these at a reachable PostgreSQL with an empty `siem` database; the idempotent `schema.sql` initializes the tables on startup.

## Observability

- Prometheus scrapes every service's `/actuator/prometheus` on its internal port (`infrastructure/prometheus/prometheus.yml`). Those endpoints are `permitAll` in every service `SecurityConfig`; the scrape config relabels `job` into an `application` label so the dashboard panels resolve.
- Grafana is provisioned from `infrastructure/grafana/provisioning` with a Prometheus datasource and a "SIEM Overview" dashboard (service up, HTTP request rate, detection throughput, process uptime). Anonymous access is enabled as Viewer; sign in with `admin` / `admin123` to edit.
- Detection publishes cumulative counters `siem_detection_events_evaluated_total` and `siem_detection_alerts_generated_total`.

## Kubernetes / Helm

- Raw manifests: `infrastructure/kubernetes/namespace.yaml` (create namespace, then apply your own workloads) and `infrastructure/kubernetes/README.md`.
- Helm chart: `infrastructure/helm/siem` — one Deployment + Service per backend service, dependency Deployments for PostgreSQL, Redis, single-node Kafka (KRaft), Keycloak (dev import), OpenSearch, and an Nginx frontend.

```bash
helm lint infrastructure/helm/siem
helm template siem infrastructure/helm/siem | kubectl apply -f -
```

The chart uses test defaults; override `postgresql.password` and the Keycloak credentials in values before any shared use. Helm templates and the Compose file keep service names aligned because the gateway routes by service name.
