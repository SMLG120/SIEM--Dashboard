# v2 Baseline Audit

Audit of `main` at `2d16cad` (2026-11-18) before any v2 change. Every finding below was confirmed by
reading the source, running the build, or querying the running local stack; nothing is inferred from the
README alone. Severity uses Critical / High / Medium / Low from the perspective of a shared or public
deployment.

## How the baseline was measured

| Check | Command | Result |
|---|---|---|
| Backend build + tests | `mvn -B clean verify` (JDK 21.0.12, Maven 3.9.16) | BUILD SUCCESS, 11 modules, **35 tests, 0 failures** |
| Frontend build | `npm ci && npm run build` (Node 24) | Success; single 732 kB JS chunk (Vite warns > 500 kB) |
| Frontend dependency audit | `npm audit --omit=dev` | **1 high**: `zod` 3.x |
| Secrets in git history | `gitleaks detect` | 0 findings in 7 commits |
| Secrets in working tree | `gitleaks dir .` | 6 findings, all in the gitignored local `.env` (never committed) |
| Compose validation | `docker compose config -q` (local and prod overlay) | Both valid |
| Helm | `helm lint infrastructure/helm/siem` | 0 failures (1 info: missing icon) |
| Live stack (read-only) | curl against the running local stack as `demo` (VIEWER) | see findings below |

Not available at baseline: CI workflows (none exist), frontend tests, linting, Testcontainers tests,
dependency scanning, image scanning.

## README claims vs. reality

| Claim | Verified? | Notes |
|---|---|---|
| Java 21 | Yes | `maven.compiler.release=21` |
| Spring Boot 3.4.x | Yes (3.4.5) | **3.4 OSS support ended 2025-12-31**; 3.5 ended 2026-06-30. Only Boot 4.0/4.1 are supported today. |
| Spring Cloud | 2024.0.3 | Matches Boot 3.4 only; EOL with it. |
| Kafka, PostgreSQL, Redis, OpenSearch, Keycloak | Yes | Kafka 3.7 KRaft single broker, Postgres 16, Redis 7, OpenSearch 2.15, Keycloak 26.7.4 |
| React 19 + Vite + TanStack Query + Recharts | Yes | No Tailwind/shadcn; 1,100-line hand-written CSS |
| "7 packaged rules" | Yes | All are single-event matchers (see D-1) |
| "Kafka redeliveries are idempotent" (threat-model.md) | **No** | Detection assigns a random alert ID per evaluation (D-2) |
| "35 backend tests" | Yes | |
| auth / audit / threat-intel services | Scaffolds | Each exposes only `GET .../internal/status` |

## Service completeness

| Service | State | Persistence | Endpoints that work |
|---|---|---|---|
| api-gateway | Complete | Redis (rate-limit buckets) | Routing for 8 services, JWT + RBAC, CORS |
| ingestion-service | Complete | PostgreSQL `siem_event` | `POST /api/events`, `POST /api/events/batch` (≤500), `GET /api/events` (last 200 from memory), `GET /api/events/{id}` (memory only) |
| detection-service | Complete, simplistic | **None** (rule state lives only in the `siem.rules` topic) | `GET /api/rules`, `GET /api/rules/{id}`, rule enable/disable/severity, `GET /api/detection/summary` |
| alert-service | Complete | PostgreSQL `siem_alert`, `siem_alert_note` | list (+status filter), get, workflow, 4 transitions, assign, notes |
| incident-service | Complete | PostgreSQL `siem_incident` (JSON payload column) | list, get, create, patch, notes, link alert |
| search-service | Complete | OpenSearch (dynamic mappings) | summary, `events?q=`, `alerts?q=` |
| auth-service | Scaffold | — | status only |
| audit-service | Scaffold | — | status only |
| threat-intelligence-service | Scaffold | — | status only |

## Findings

### Data consistency and Kafka processing

| ID | Severity | Finding | Impact | Proposed fix |
|---|---|---|---|---|
| K-1 | **High** | `EventIngestService.ingest` inserts into PostgreSQL then calls `kafkaTemplate.send(...)` without awaiting the future. | A broker outage after the DB commit silently loses the event for detection, alerts and search, yet the API returns `201`. Classic dual-write. | Transactional outbox: insert event + outbox row in one DB transaction; a relay publishes and marks rows sent only after the broker acknowledges. |
| K-2 | **High** | Detection consumer publishes alerts with fire-and-forget `send()`; the listener returns and the offset is committed regardless of the outcome. | Alerts lost on broker/producer failure with no retry. | Await the send inside the listener so failures throw and the error handler retries; DLT after retries. |
| D-2 | **High** | `DetectionEngine` gives every alert `UUID.randomUUID()`. | Any redelivery of `siem.events` (rebalance, restart before commit) creates duplicate alerts and duplicate incident links. The idempotency claim in threat-model.md is false. (No duplicates exist in the current local data: 64 alerts / 64 distinct `(rule_id, event_id)`.) | Deterministic alert ID = name-based UUID of `(ruleId, eventId)` (or `(ruleId, groupKey, window)` for correlation rules); alert-service insert is already idempotent on ID. |
| K-3 | Medium | No dead-letter topics. Spring's default error handler retries 10 times then **logs and skips**. | Poison or repeatedly failing records are dropped with only a log line. | `DefaultErrorHandler` + `DeadLetterPublishingRecoverer` to `<topic>.DLT`, exponential backoff, non-retryable exceptions classified. |
| K-4 | Medium | Search indexing swallows OpenSearch `IOException`s. | Offset commits even though the document was never indexed; search silently diverges. | Throw so the error handler retries, then DLT. |
| K-5 | Medium | Rule changes are applied to memory, then published fire-and-forget; each instance joins a **random** consumer group (`detection-rules-<uuid>`) on every start. | Publish failure means the change is reverted on next restart; an unbounded number of orphaned consumer groups accumulate on the broker. | Persist rule state and versions; keep `siem.rules` as the broadcast. |
| K-6 | Low | Producer acks/idempotence and consumer offset policy are left implicit. | Behaviour depends on client defaults that changed across Kafka versions. | Set `acks=all`, `enable.idempotence=true`, explicit `delivery.timeout.ms`, `AckMode.RECORD`. |
| P-1 | **High** | Alert (1,000), incident (100) and event (1,000) read models are in-memory; the APIs read **only** from memory. | Older alerts and incidents become invisible to the API and to correlation once evicted. State diverges across replicas, so the services can't scale horizontally. | Serve reads from PostgreSQL with indexed, paginated queries; drop the memory stores. |
| P-2 | Medium | Schema created with `spring.sql.init.mode: always` + `CREATE TABLE IF NOT EXISTS`. | No migration history; column changes can't be rolled out safely. | Flyway, with V1 equal to the current schema and `baselineOnMigrate` for existing databases. |
| P-3 | Low | Incidents are stored as an opaque JSON `payload` column. | Can't query by alert, assignee or timeline. | Keep the payload for compatibility; add indexed columns and a link table later. |

### Detection quality

| ID | Severity | Finding | Fix |
|---|---|---|---|
| D-1 | Medium | All 7 rules are single-event matchers. "Repeated Login Failures" fires on **one** HIGH `LOGIN_FAILURE` and never on many LOW/MEDIUM failures, which is the actual brute-force signal. | Add threshold (count-within-window, grouped by field) and sequence rules with bounded state. |
| D-3 | Medium | No MITRE ATT&CK mapping, rule versions, false-positive notes, test examples or explanation of why an alert fired. | Extend the rule model and the alert payload (matched conditions, triggering event IDs). |
| D-4 | Low | `SIEM-1003` matches `TOR_UNKNOWN` under "Privilege Escalation". | Keep for backwards compatibility; document it. |

### Security

| ID | Severity | Finding | Impact | Fix |
|---|---|---|---|---|
| S-1 | **High** | Spring Boot 3.4.5 / Spring Cloud 2024.0.3 are past OSS end of life. | No further OSS security patches. | Upgrade to Boot 4.1.x + Spring Cloud 2025.1.x (the supported pair). |
| S-2 | **High** | All services connect to PostgreSQL as the bootstrap **superuser** (`rolsuper = true`, verified on the running stack). | SQL injection or credential theft in any service gives full cluster control, including the Keycloak database. | Separate least-privilege runtime role; superuser only for bootstrap. |
| S-3 | Medium | `siem-demo` client with the OAuth password grant (ROPC) is imported in **production** too. | A dev-only flow is enabled on the public deployment and bypasses the browser login UX. | Strip the client from the production realm import. |
| S-4 | Medium | `/actuator/gateway/**` is readable by any authenticated user (verified: VIEWER → `200` on `/actuator/gateway/routes`). | Internal service topology disclosed to the read-only public demo account. | Remove the gateway actuator endpoint from exposure. |
| S-5 | Medium | Alert status changes and assignments are not attributed. Assignment accepts any free-text name. | Weak repudiation controls; the audit service is a scaffold. | Append-only alert history with actor; central audit service. |
| S-6 | Medium | Incident status changes are unrestricted (e.g. `CLOSED → OPEN`, `RESOLVED → CONTAINED`). | Lifecycle integrity. | Explicit transition table. |
| S-7 | Medium | Search uses `query_string` with a leading wildcard (`*term*`). | Expensive queries on large indices; the escaping approach is fragile. | `simple_query_string`/`multi_match` with explicit mappings; cap length. |
| S-8 | Medium | No request body size limit at the gateway or in services (Tomcat default 2 MB form, unlimited JSON). | Memory-pressure DoS from large bodies. | Gateway limit + per-service limit. |
| S-9 | Low | Client-supplied `X-Correlation-Id` is propagated unvalidated into logs and headers. | Log injection or forging. | Validate format and length; regenerate otherwise. |
| S-10 | Low | `/actuator/prometheus` is unauthenticated on every service (verified on the gateway). | Not routed publicly by Caddy, so exposure is limited to the internal network or loopback. | Keep internal-only; document. |
| S-11 | Low | No Content-Security-Policy on the frontend. | XSS blast radius. | **In progress in the working tree** (uncommitted CSP change); finish and commit. |
| S-12 | Low | Kafka PLAINTEXT, OpenSearch security plugin disabled, also in the production overlay. | Acceptable only while those services stay on the private Compose network (true today). | Document as a residual risk; SASL/TLS for multi-host. |

### Frontend

| ID | Severity | Finding |
|---|---|---|
| F-1 | Medium | `initializeAuth()` has no error path. If Keycloak is unreachable the app stays on the splash screen forever. |
| F-2 | Medium | Platform page hard-codes `http://localhost:*` URLs; it's wrong in production and shows no live health. |
| F-3 | Medium | "Intelligence" page only lists rules; there's no threat-intel or rule-testing UI. |
| F-4 | Low | No tests, no lint, no accessibility checks. 732 kB single bundle. `zod` high advisory. |
| F-5 | Low | `useAddIncidentNote` is typed as returning `Incident` but the API returns `IncidentNote`. |

### CI/CD and deployment

| ID | Severity | Finding |
|---|---|---|
| C-1 | **High** | No GitHub Actions workflows at all. `.github/` holds only untracked output from an app-modernization assessment tool. |
| C-2 | Medium | `deploy.sh` rsyncs the developer's working tree and builds on the server: not reproducible, not tied to a commit, no rollback. |
| C-3 | Medium | Spring services have no container health checks; the gateway starts on `service_started`. |
| C-4 | Low | `IngestionServiceApplicationTest` and `IncidentServiceApplicationTest` spend ~43 s each timing out against a non-existent Kafka broker. |
| C-5 | Info | No live deployment URL is recorded anywhere in the repo; production deployment status can't be verified from here. |

## Proposed order (smallest safe sequence)

1. Platform upgrade to a supported Spring Boot/Cloud pair (S-1). Everything after builds on it.
2. Flyway with baseline-compatible V1 (P-2), verified against a dump of the existing database.
3. Reliability vertical slice: outbox (K-1), awaited alert publishing + deterministic IDs (K-2, D-2), DLTs (K-3, K-4), DB-backed reads (P-1).
4. Detection v2: threshold/sequence rules, MITRE, evidence, rule tester (D-1, D-3).
5. Security fixes S-3…S-9 and an attributed alert history (S-5); audit service.
6. Tests: authorization matrix, Testcontainers pipeline test; CI workflows (C-1).
7. Frontend: auth error state, real platform health, rules and threat-intel pages, redesign.
8. Deployment automation by commit SHA (C-2) and health checks (C-3). Live deployment needs a VM, which costs money and requires owner approval.
