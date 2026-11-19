# API

All domain routes require a Keycloak-issued bearer token. The API Gateway performs route-level RBAC and every downstream service re-validates the JWT and applies its own role checks.

## Roles

- `ADMIN`: full administrative access.
- `SOC_MANAGER`: event writes plus alert, incident, rule, threat-intel, and audit workflows.
- `SECURITY_ANALYST`: event and alert investigation workflows, including event ingestion.
- `VIEWER`: read-only (`GET`) access to events, alerts, incidents, rules, detection, search and threat intel. No writes, and no access to the audit log.

Errors use RFC 9457 problem details (`{ "title", "status", "detail" }`). Every response carries `X-Correlation-Id`. Request bodies over 2 MB return `413`.

## Actuator

- `GET /actuator/health`, `GET /actuator/info`, `GET /actuator/prometheus` are public for orchestration checks and metrics scraping.
- All other actuator endpoints are not exposed (the gateway denies `/actuator/**`).

## Rate Limiting

Routed requests through the gateway are metered by a Redis token bucket (per-user, default 20 req/s with burst 40; `SIEM_RATE_LIMIT_REPLENISH` / `SIEM_RATE_LIMIT_BURST`). Exceeding the bucket returns `429 Too Many Requests`; every metered response includes `X-RateLimit-Replenish-Rate`, `X-RateLimit-Burst-Capacity`, `X-RateLimit-Requested-Tokens`, and `X-RateLimit-Remaining`.

## Readiness

- `GET /api/auth/internal/status`
- `GET /api/events/internal/status`
- `GET /api/detection/internal/status`
- `GET /api/alerts/internal/status`
- `GET /api/incidents/internal/status`
- `GET /api/threat-intel/internal/status`
- `GET /api/audit/internal/status`
- `GET /api/search/internal/status`

## Events

Roles: reads for `ADMIN`, `SOC_MANAGER`, `SECURITY_ANALYST`, `VIEWER`; ingestion for `ADMIN`, `SOC_MANAGER`, `SECURITY_ANALYST`.

- `GET /api/events` — recent ingested events (bounded window).
- `GET /api/events/{id}` — a single event.
- `POST /api/events` — ingest one event. Body: `{ eventType, severity, category?, sourceIp?, sourceHost?, destinationIp?, destinationPort?, userName?, message?, attributes? }`. `attributes` is a flat string map (at most 32 keys matching `[A-Za-z0-9_.-]{1,64}`, values up to 512 characters), used by rules such as `fileHash`, `bytesOut`, `process`. Timestamp is assigned by the service.
- `POST /api/events/batch` — ingest a list of events.

## Rules

Roles: reads for `ADMIN`, `SOC_MANAGER`, `SECURITY_ANALYST`, `VIEWER`; writes for `ADMIN`, `SOC_MANAGER`.

- `GET /api/rules` — packaged detection rules.
- `GET /api/rules/{id}` — a single rule.
- `POST /api/rules/{id}/enable` / `POST /api/rules/{id}/disable` — toggle a rule live across all detection instances (published to the `siem.rules` topic).
- `POST /api/rules/{id}/severity` — body `{ "severity": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL" }`; applies live. Writes restricted to `ADMIN`, `SOC_MANAGER`; unknown rule → `404`, invalid severity → `400`, Kafka unavailable → `503` (the change is not applied).
- `GET /api/rules/{id}/history` — runtime changes to the rule (`action`, `severity`, `actor`, `changedAt`, `resultingVersion`).
- `POST /api/rules/test` — sandbox (`ADMIN`, `SOC_MANAGER`, `SECURITY_ANALYST`). Body `{ ruleId, events? }`: replays up to 500 events through the rule in an isolated engine and returns the alerts (with evidence) that would fire. Omit `events` to verify the packaged examples (`examplesPassed`, `checks`). Nothing is published or stored.

Each rule includes `version`, `type` (`SINGLE`/`THRESHOLD`/`SEQUENCE`), `condition`, `threshold?`, `sequence?`, `suppressionSeconds?`, `mitre[]`, `falsePositives[]` and `examples`. See [detection-rules.md](detection-rules.md).

## Detection

Roles: `ADMIN`, `SOC_MANAGER`, `SECURITY_ANALYST`, `VIEWER`.

- `GET /api/detection/summary` — counters since start (`eventsEvaluated`, `alertsGenerated`, `rulesEnabled`, `rulesTotal`, `alertsByRule`, `detectionLatencyMeanMs`, `detectionLatencyP95Ms`) plus recent alerts. Latency runs from event timestamp to alert publication. The mean covers everything since start; the p95 covers a sliding window of about 2 minutes and is `0` when no alert fired in it.
- `GET /api/detection/alerts/{id}` — a recent detection-generated alert.

## Alerts

Roles: reads for `ADMIN`, `SOC_MANAGER`, `SECURITY_ANALYST`, `VIEWER`; status transitions for `ADMIN`, `SOC_MANAGER`, `SECURITY_ANALYST`.

- `GET /api/alerts` — most recent alerts, optionally filtered by `?status=`.
- `GET /api/alerts/search?status=&severity=&ruleId=&assignedTo=&sourceIp=&from=&sort=created|severity&page=0&size=50` — filtered, paged (`size` ≤ 200) query; `status` and `severity` may repeat. Returns `{ items, total, page, size }`.
- `GET /api/alerts/summary` — `{ total, byStatus, openBySeverity, topRules }` from the database.
- `GET /api/alerts/{id}/history` — append-only workflow history (`action`, `fromStatus`, `toStatus`, `actor`, `detail`, `occurredAt`).
- `GET /api/alerts/{id}` — a single alert.
- `GET /api/alerts/{id}/workflow` — alert detail with `assignedTo` and `notes`.
- `POST /api/alerts/{id}/acknowledge` — move an alert from `OPEN` to `ACKNOWLEDGED`.
- `POST /api/alerts/{id}/investigate` — move an alert to `INVESTIGATING` (forbidden once `RESOLVED`).
- `POST /api/alerts/{id}/resolve` — move an alert to `RESOLVED`.
- `POST /api/alerts/{id}/reopen` — move a `RESOLVED` alert back to `OPEN`.
- `POST /api/alerts/{id}/assign` — body `{ assignedTo }`; assigns the alert to an analyst.
- `POST /api/alerts/{id}/notes` — body `{ text }`; appends an analyst note and returns it.

Alerts carry `ruleVersion`, `mitre[]` and `evidence` (`ruleType`, `matchedConditions`, `eventIds` ≤ 50, `eventCount`, `groupKey`, `windowSeconds`, `firstSeen`, `lastSeen`). Alerts from v1 have no evidence. An invalid transition returns `409`. The actor is always taken from the token, never from the body.

## Incidents

Roles: reads for `ADMIN`, `SOC_MANAGER`, `SECURITY_ANALYST`, `VIEWER`; writes for `ADMIN`, `SOC_MANAGER`, `SECURITY_ANALYST`.

- `GET /api/incidents?status=&limit=100` — list incidents, newest first.
- `GET /api/incidents/summary` — counts by status.
- `GET /api/incidents/{id}` — full incident: `title`, `description`, `severity`, `status`, `assignedTo`, `relatedAlerts`, `timeline`, `notes`.
- `POST /api/incidents` — create manually. Body: `{ title, description?, severity }`.
- `PATCH /api/incidents/{id}` — update. Body: `{ title?, description?, severity?, status?, assignedTo? }`; records a timeline entry per changed field.
- `POST /api/incidents/{id}/notes` — body `{ text }`; appends an analyst note and returns it.
- `POST /api/incidents/{id}/alerts` — body `{ alertId, ruleId?, ruleName?, eventType?, severity?, sourceIp?, description? }`; links an open alert and records a timeline entry (deduped by `alertId`).

Incidents are also created automatically: the incident-service consumes `siem.alerts` and groups unresolved alerts by matching `sourceIp`.

## Search

Roles: `ADMIN`, `SOC_MANAGER`, `SECURITY_ANALYST`, `VIEWER`. Backed by OpenSearch (`siem-events`, `siem-alerts`); the service indexes both Kafka streams as they are produced.

- `GET /api/search/summary` — `{ eventsCount, alertsCount, eventsBySeverity, alertsBySeverity }` where the two maps are severity → count.
- `GET /api/search/events?q=&limit=50` — indexed event hits, newest first. `q` (≤ 256 characters) uses simple query syntax: terms are ANDed; `|` is OR, `-` is NOT, `"…"` is a phrase and `*` is a prefix (`ransom*`). `limit` is clamped to 1–100; an empty `q` returns the most recent events. Returns `503` if OpenSearch is unavailable.
- `GET /api/search/alerts?q=&limit=50` — same contract for generated alerts.
- Each hit is `{ index, id, timestamp, fields }` where `fields` is the indexed document (e.g. `eventType`, `severity`, `sourceIp`, `ruleId`, `status`).

## Threat Intelligence

Roles: reads for all four roles; writes for `ADMIN`, `SOC_MANAGER`. No external feeds are connected; indicators are entered by analysts (`source: ANALYST`) or loaded by the optional demo seed (`source: SIMULATED_DEMO`).

- `GET /api/threat-intel/indicators?activeOnly=true&limit=` — indicators.
- `GET /api/threat-intel/indicators/{id}`
- `POST /api/threat-intel/indicators` — body `{ type: IP|DOMAIN|MD5|SHA1|SHA256, value, severity? (default MEDIUM), description?, expiresAt? }`. Values are validated and canonicalised (lower-case hashes/domains, normalised IPs); duplicates return `409`.
- `DELETE /api/threat-intel/indicators/{id}` — deactivates (history is kept); `204`.
- `GET /api/threat-intel/sightings?indicatorId=&limit=` — events whose `sourceIp`, `destinationIp`, or attributes `fileHash`, `sha256`, `sha1`, `md5`, `domain`, `dnsQuery`, `host` equal an active indicator.
- `GET /api/threat-intel/lookup?value=` — active indicators matching a value.

## Audit

Roles: `ADMIN`, `SOC_MANAGER`.

- `GET /api/audit/events?actor=&resourceType=RULE|ALERT|INCIDENT&resourceId=&from=&limit=100` — append-only audit trail (`limit` ≤ 500), newest first: rule changes, alert workflow history and incident timeline entries with the acting user.

## Authorization Rules

- Event, alert, and incident writes require `ADMIN`, `SOC_MANAGER`, or `SECURITY_ANALYST`.
- Event, alert, incident, rule, detection, and search reads also allow `VIEWER`. Every `VIEWER` write is refused with `403` by both the gateway and the owning service.
- Rule enable/disable/severity changes require `ADMIN` or `SOC_MANAGER`.
- Threat-intel writes and all audit access require `ADMIN` or `SOC_MANAGER`.
- The matrix is tested cell-by-cell in `AuthorizationMatrixTest` (gateway).