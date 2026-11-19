import { useQuery } from "@tanstack/react-query";
import type { AuthState } from "../auth";
import { fetchServiceHealth, serviceEndpoints } from "../api";
import { formatTime, hasAnyRole, MANAGER_ROLES } from "../components";
import { useAuditLog, useDetectionSummary } from "../hooks";

const topics = [
  { topic: "siem.events", producedBy: "ingestion (outbox relay)", consumedBy: "detection, search, threat-intel" },
  { topic: "siem.alerts", producedBy: "detection", consumedBy: "alert, incident, search" },
  { topic: "siem.incidents", producedBy: "incident (one record per timeline entry)", consumedBy: "audit" },
  { topic: "siem.rules", producedBy: "detection rule API (compacted, replayed on start)", consumedBy: "every detection instance, audit" },
  { topic: "siem.audit", producedBy: "alert workflow history", consumedBy: "audit" },
  { topic: "*.DLT", producedBy: "consumers, for poison records", consumedBy: "operators" }
];

// Developer conveniences only: these ports exist on a local `docker compose up`, not in production.
const localTools = [
  { name: "Grafana", url: "http://localhost:13000" },
  { name: "Keycloak admin", url: "http://localhost:18088" },
  { name: "Kafka UI (--profile tools)", url: "http://localhost:18090" },
  { name: "Mailpit", url: "http://localhost:18025" }
];

function isLocal() {
  return ["localhost", "127.0.0.1"].includes(window.location.hostname);
}

export function PlatformPage({ auth }: { auth: AuthState }) {
  const manager = hasAnyRole(auth.roles, MANAGER_ROLES);
  const summary = useDetectionSummary();
  const audit = useAuditLog(manager);
  const health = useQuery({
    queryKey: ["service-status"],
    queryFn: () =>
      Promise.all(serviceEndpoints.map(async (e) => ({ label: e.label, health: await fetchServiceHealth(e.path) }))),
    refetchInterval: 30_000
  });
  const s = summary.data;

  return (
    <div className="page-stack">
      <section className="metric-grid compact" aria-label="Pipeline metrics">
        <article className="metric-card low">
          <span>Events evaluated</span>
          <strong>{s?.eventsEvaluated ?? "-"}</strong>
          <small>since detection start</small>
        </article>
        <article className="metric-card high">
          <span>Alerts generated</span>
          <strong>{s?.alertsGenerated ?? "-"}</strong>
          <small>since detection start</small>
        </article>
        <article className="metric-card medium">
          <span>Detection latency</span>
          <strong>{s?.detectionLatencyMeanMs != null ? `${s.detectionLatencyMeanMs.toFixed(1)} ms` : "-"}</strong>
          {/* p95 is a sliding ~2 min window (Micrometer), so it reads 0 once alerts stop; the mean is since start. */}
          <small>
            mean since start · p95 last 2 min{" "}
            {s?.detectionLatencyP95Ms ? `${s.detectionLatencyP95Ms.toFixed(1)} ms` : "idle"}
          </small>
        </article>
        <article className="metric-card critical">
          <span>Rules enabled</span>
          <strong>
            {s?.rulesEnabled ?? "-"}
            {s?.rulesTotal ? <small> / {s.rulesTotal}</small> : null}
          </strong>
          <small>live in the engine</small>
        </article>
      </section>

      <article className="panel">
        <div className="panel-heading">
          <h2>Services</h2>
          <span>checked every 30 s through the gateway</span>
        </div>
        <div className="service-grid" aria-label="Service health">
          {(health.data ?? serviceEndpoints.map((e) => ({ label: e.label, health: undefined }))).map((item) => (
            <div key={item.label} className="service-tile">
              <span className={`status-dot ${item.health ?? "pending"}`} aria-hidden="true" />
              <strong>{item.label}</strong>
              <small>{item.health === "restricted" ? "up (not visible to your role)" : (item.health ?? "checking…")}</small>
            </div>
          ))}
        </div>
      </article>

      {manager ? (
        <article className="panel">
          <div className="panel-heading">
            <h2>Audit trail</h2>
            <span>append-only · latest 50</span>
          </div>
          {audit.isError ? <div className="empty-state error">{audit.error.message}</div> : null}
          {(audit.data ?? []).length === 0 && !audit.isLoading ? (
            <div className="empty-state">No audited changes yet.</div>
          ) : null}
          <div className="data-table" role="table" aria-label="Audit trail">
            {(audit.data ?? []).map((a) => (
              <div className="data-row audit-grid" role="row" key={a.id}>
                <span>{formatTime(a.occurredAt)}</span>
                <span>
                  <strong>{a.actor}</strong>
                </span>
                <span>
                  <code>{a.action}</code>
                </span>
                <span>
                  {a.resourceType} <code>{a.resourceId.length > 14 ? `${a.resourceId.slice(0, 10)}…` : a.resourceId}</code>
                </span>
                <span className="muted">{a.detail ?? ""}</span>
              </div>
            ))}
          </div>
        </article>
      ) : null}

      <article className="panel">
        <div className="panel-heading">
          <h2>Event backbone</h2>
          <span>Kafka topics</span>
        </div>
        <div className="data-table">
          <div className="data-row data-head topic-grid">
            <span>Topic</span>
            <span>Produced by</span>
            <span>Consumed by</span>
          </div>
          {topics.map((t) => (
            <div className="data-row topic-grid" key={t.topic}>
              <span>
                <code>{t.topic}</code>
              </span>
              <span>{t.producedBy}</span>
              <span>{t.consumedBy}</span>
            </div>
          ))}
        </div>
      </article>

      {isLocal() ? (
        <article className="panel">
          <div className="panel-heading">
            <h2>Local tools</h2>
            <span>docker compose only</span>
          </div>
          <ul className="plain-list">
            {localTools.map((t) => (
              <li key={t.name}>
                {t.name}: <code>{t.url}</code>
              </li>
            ))}
          </ul>
        </article>
      ) : null}
    </div>
  );
}
