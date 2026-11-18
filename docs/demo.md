# Demo Walkthrough

About ten minutes, showing one simulated intrusion through the whole pipeline: **ingest → detect (with evidence) → triage → investigate → audit**. All telemetry is simulated: documentation IP ranges, `example` domains and the harmless EICAR test hash.

## 1. Start and seed

```bash
cp .env.example .env && $EDITOR .env          # replace every change-me value
docker compose up -d --build                  # wait until `docker compose ps` shows the services healthy
scripts/ingest-demo-events.sh                                   # 38 v1 events
scripts/ingest-demo-events.sh sample-data/v2-attack-scenario.json  # 42-event v2 attack scenario
```

The scenario is assembled from the rules' own `match` examples. When ingested as one batch it fires every v2 rule (`SIEM-1008`–`SIEM-1018`) except `SIEM-1013`. Beaconing needs real minutes between connections, so try it in the rule tester instead (step 4). `DemoScenarioTest` checks this on every build.

Compose seeds six threat-intel indicators labelled *simulated* (set `SIEM_THREAT_INTEL_SEED_DEMO=false` to skip). Three of them appear in the scenario.

## 2. Command Overview (sign in as `sam.analyst`)

- Open-alert counts by severity and alerts per rule come from the alert database, not a client-side sample.
- Service health is checked live through the gateway.

## 3. Alerts: why did this fire?

1. Filter **Severity = HIGH** and open *Successful Login After Repeated Failures* (`SIEM-1009`).
2. The drawer's **Why this alert fired** section shows:
   - the sequence that matched: failures ×3 → success, for the same `userName`;
   - the window, first and last seen;
   - the contributing event IDs.
3. The ATT&CK chips (T1110, T1078) link to MITRE.
4. **Investigate**, assign to `sam.analyst`, add a note, then **Resolve**. Every step appears under **History**.

Try an invalid move through the API, such as acknowledging a resolved alert. The server returns `409` with a readable reason, which the console displays.

## 4. Detection Rules

1. Pick `SIEM-1013 Command-and-Control Beaconing`. The detection logic reads: count ≥ 8 per sourceIp+destinationIp within 3600 s, interval jitter ≤ 15%.
2. **Test this rule → Verify packaged examples.** The sandbox replays the regular-interval `match` examples (one alert) and the irregular `noMatch` examples (none), with nothing published.
3. Edit an interval in the JSON so the cadence becomes irregular, then **Run test**: no alert.
4. As `sam.manager`, disable a rule. The change is versioned, appears under **Change history**, and reaches the audit log.

## 5. Threat Intel

- **Sightings** list scenario events whose IPs or file hash matched the simulated indicators.
- As `sam.manager`, add an indicator. Then ingest an event that contains it, and a sighting appears within seconds.

## 6. Incidents

The scenario's alerts are grouped into incidents by source IP. Open one to see the linked alerts and the timeline. Then move it `OPEN → INVESTIGATING → CONTAINED`.

## 7. Platform Health (as `sam.manager`)

- Detection latency (mean / p95), events evaluated and the Kafka topology.
- **Audit trail:** the rule toggle from step 4, the alert workflow from step 3 and the incident changes from step 6, each with the user who made them.

Sign in as `demo` (`VIEWER`) to show the read-only experience: every page is visible except the audit trail, and no workflow controls appear. The API refuses writes with `403` even if called directly.
