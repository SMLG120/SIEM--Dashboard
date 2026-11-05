# Deployment

The local stack is Docker Compose based. It brings up all nine backend services, the React dashboard, and the platform dependencies (PostgreSQL, Redis, Kafka, Keycloak, OpenSearch) plus observability (Prometheus, Grafana):

```bash
cp .env.example .env   # then replace every change-me value
docker compose up --build
docker compose --profile tools up -d kafka-ui   # optional, read-only Kafka UI with login
```

## Host Ports

Every port is published on `127.0.0.1` only and uses a dedicated range so the stack doesn't collide with a local PostgreSQL (5432), Vite (5173) or other dev servers. Each can be changed with the matching `SIEM_*_PORT` variable in `.env`.

| Port | Service | Variable |
|------|---------|----------|
| 15173 | SOC Dashboard | `SIEM_FRONTEND_PORT` |
| 18080 | API Gateway | `SIEM_GATEWAY_PORT` |
| 18088 | Keycloak | `SIEM_KEYCLOAK_PORT` |
| 15432 | PostgreSQL | `SIEM_POSTGRES_PORT` |
| 16379 | Redis (password required) | `SIEM_REDIS_PORT` |
| 19092 | Kafka (host listener) | `SIEM_KAFKA_PORT` |
| 19200 | OpenSearch | `SIEM_OPENSEARCH_PORT` |
| 19090 | Prometheus | `SIEM_PROMETHEUS_PORT` |
| 13000 | Grafana | `SIEM_GRAFANA_PORT` |
| 18090 | Kafka UI (`tools` profile) | `SIEM_KAFKA_UI_PORT` |
| 18025 | Mailpit inbox for Keycloak emails (password reset) | `SIEM_MAILPIT_PORT` |

Backend services other than the gateway are internal to the Compose network and are reached through the gateway only.

## Configuration

There are no built-in passwords: Compose refuses to start until these are set in `.env`:

- `POSTGRES_PASSWORD` (`ingestion-service`, `alert-service`, and `incident-service` connect with `POSTGRES_USER` / `POSTGRES_PASSWORD` against `POSTGRES_DB`)
- `REDIS_PASSWORD` (gateway rate limiter)
- `KEYCLOAK_ADMIN_PASSWORD`
- `SIEM_DEMO_PASSWORD` (shared by the realm demo users; at least 12 characters)
- `GF_SECURITY_ADMIN_PASSWORD` (Grafana; anonymous access is disabled)
- `KAFKA_UI_PASSWORD`

The realm enables brute-force lockout and adds an `api-gateway` audience to tokens issued to `siem-dashboard` and `siem-demo`; every service rejects tokens without that audience (`OIDC_AUDIENCE`).

Keycloak sends email (password reset) through the bundled Mailpit catcher; open http://localhost:18025 to read it. For a real deployment, replace `smtpServer` in the realm template with your SMTP relay.

Local-only caveats: Kafka uses PLAINTEXT, OpenSearch runs with its security plugin disabled, and Keycloak runs `start-dev`. They are only reachable from this machine; enable SASL/TLS, the OpenSearch security plugin and Keycloak production mode before exposing the stack anywhere else.

Useful runtime knobs:

- `SIEM_RATE_LIMIT_REPLENISH` / `SIEM_RATE_LIMIT_BURST` — gateway token-bucket defaults (20 req/s, burst 40).
- `SIEM_SEARCH_STORAGE` — `opensearch` (default in Compose) or `memory` for the bounded in-memory search index.

Services connect to PostgreSQL through `SPRING_DATASOURCE_*` (overridable locally via `DB_URL` / `DB_USERNAME` / `DB_PASSWORD`). If you run the three domain services outside Docker, they default to the Compose PostgreSQL on `localhost:15432` (set `DB_PASSWORD`); otherwise point them at a reachable PostgreSQL with an empty `siem` database; the idempotent `schema.sql` initializes the tables on startup.

## Observability

- Prometheus scrapes every service's `/actuator/prometheus` on its internal port (`infrastructure/prometheus/prometheus.yml`). Those endpoints are `permitAll` in every service `SecurityConfig`; the scrape config relabels `job` into an `application` label so the dashboard panels resolve.
- Grafana is provisioned from `infrastructure/grafana/provisioning` with a Prometheus datasource and a "SIEM Overview" dashboard (service up, HTTP request rate, detection throughput, process uptime). Sign in with `GF_SECURITY_ADMIN_USER` / `GF_SECURITY_ADMIN_PASSWORD`.
- Detection publishes cumulative counters `siem_detection_events_evaluated_total` and `siem_detection_alerts_generated_total`.

## Kubernetes / Helm

- Raw manifests: `infrastructure/kubernetes/namespace.yaml` (create namespace, then apply your own workloads) and `infrastructure/kubernetes/README.md`.
- Helm chart: `infrastructure/helm/siem` — one Deployment + Service per backend service, dependency Deployments for PostgreSQL, Redis, single-node Kafka (KRaft), Keycloak (dev import), OpenSearch, and an Nginx frontend.

```bash
helm lint infrastructure/helm/siem
helm template siem infrastructure/helm/siem | kubectl apply -f -
```

The chart uses test defaults; override `postgresql.password` and the Keycloak credentials in values before any shared use. Helm templates and the Compose file keep service names aligned because the gateway routes by service name.
