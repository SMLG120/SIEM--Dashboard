import { useQuery } from "@tanstack/react-query";
import { Activity, AlertTriangle, Bell, Siren } from "lucide-react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { fetchServiceStatus, serviceEndpoints, type SecurityEvent, type SiemAlert } from "../api";
import { useAlerts, useDetectionSummary, useEvents } from "../hooks";

function formatTime(iso: string) {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

const severityRank = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const severityColor: Record<string, string> = {
  CRITICAL: "#ff6b7a",
  HIGH: "#ffb35c",
  MEDIUM: "#f5d66e",
  LOW: "#4dd4ac",
  INFO: "#7db4ee"
};

/** Alert volume per detection rule, coloured by the highest severity that rule produced. */
function alertsByRule(alerts: SiemAlert[]) {
  const byRule = new Map<string, { rule: string; name: string; alerts: number; severity: string }>();
  for (const alert of alerts) {
    const entry = byRule.get(alert.ruleId) ?? { rule: alert.ruleId, name: alert.ruleName, alerts: 0, severity: "INFO" };
    entry.alerts += 1;
    if (severityRank.indexOf(alert.severity) > severityRank.indexOf(entry.severity)) {
      entry.severity = alert.severity;
    }
    byRule.set(alert.ruleId, entry);
  }
  return [...byRule.values()].sort((a, b) => b.alerts - a.alerts).slice(0, 8);
}

export function DashboardPage() {
  const eventsQuery = useEvents();
  const alertsQuery = useAlerts();
  const summaryQuery = useDetectionSummary();

  const events = eventsQuery.data ?? [];
  const alerts = alertsQuery.data ?? [];
  const summary = summaryQuery.data;

  const statusesQuery = useQuery({
    queryKey: ["service-status"],
    queryFn: () =>
      Promise.all(
        serviceEndpoints.map(async (endpoint) => {
          const status = await fetchServiceStatus(endpoint.path);
          return { label: endpoint.label, ready: status?.status === "READY" };
        })
      ),
    refetchInterval: 30_000
  });
  const statuses = statusesQuery.data ?? [];
  const readyCount = statuses.filter((item) => item.ready).length;

  const countBySeverity = (severity: string) => alerts.filter((a) => a.severity === severity).length;
  const metrics = [
    { label: "Critical", value: String(countBySeverity("CRITICAL")), tone: "critical", icon: Siren },
    { label: "High", value: String(countBySeverity("HIGH")), tone: "high", icon: AlertTriangle },
    { label: "Medium", value: String(countBySeverity("MEDIUM")), tone: "medium", icon: Bell },
    { label: "Events", value: String(events.length), tone: "low", icon: Activity }
  ];

  const recentEvents = events.slice(0, 8);
  const chartData = alertsByRule(alerts);

  return (
    <div className="page-stack">
      <section className="metric-grid" aria-label="Security metrics">
        {metrics.map((metric) => (
          <article className={`metric-card ${metric.tone}`} key={metric.label}>
            <div className="metric-icon">
              <metric.icon size={20} />
            </div>
            <span>{metric.label}</span>
            <strong>{metric.value}</strong>
            <small>{metric.label === "Events" ? "ingested" : "alerts"}</small>
          </article>
        ))}
      </section>

      <section className="main-grid">
        <article className="panel chart-panel">
          <div className="panel-heading">
            <h2>Alerts by Detection Rule</h2>
            <span>{alerts.length} alerts · {chartData.length} rules firing</span>
          </div>
          {chartData.length === 0 ? (
            <div className="empty-state">
              No alerts yet. Ingest sample events with{" "}
              <code>scripts/ingest-demo-events.sh</code>.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={360}>
              <BarChart data={chartData} layout="vertical" margin={{ left: 8, right: 24 }}>
                <CartesianGrid stroke="#213046" horizontal={false} />
                <XAxis type="number" stroke="#7d8da8" tickLine={false} axisLine={false} allowDecimals={false} />
                <YAxis
                  type="category"
                  dataKey="name"
                  width={230}
                  stroke="#c3cee0"
                  tickLine={false}
                  axisLine={false}
                  tick={{ fontSize: 13 }}
                />
                <Tooltip
                  cursor={{ fill: "#182438" }}
                  contentStyle={{ background: "#111a29", border: "1px solid #263550", borderRadius: 8 }}
                  labelStyle={{ color: "#e8eef8" }}
                  formatter={(value, _name, item) => [`${value} alerts`, item.payload.rule]}
                />
                <Bar dataKey="alerts" radius={[0, 6, 6, 0]} barSize={18}>
                  {chartData.map((entry) => (
                    <Cell key={entry.rule} fill={severityColor[entry.severity]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </article>

        <article className="panel service-panel">
          <div className="panel-heading">
            <h2>Service Mesh</h2>
            <span>
              {statuses.length ? `${readyCount}/${serviceEndpoints.length}` : "loading"}
            </span>
          </div>
          <div className="service-list">
            {statuses.map((item) => (
              <div className="service-row" key={item.label}>
                <span>{item.label}</span>
                <strong className={`status-pill ${item.ready ? "ready" : "offline"}`}>
                  {item.ready ? "READY" : "OFFLINE"}
                </strong>
              </div>
            ))}
          </div>

          {summary && (
            <div className="summary-strip">
              <div>
                <strong>{summary.eventsEvaluated.toLocaleString()}</strong>
                <span>Evaluated</span>
              </div>
              <div>
                <strong>{summary.alertsGenerated.toLocaleString()}</strong>
                <span>Alerts</span>
              </div>
              <div>
                <strong>{summary.rulesEnabled}</strong>
                <span>Rules</span>
              </div>
            </div>
          )}
          {summary && <small className="summary-caption">Detection engine counters since last restart</small>}
        </article>
      </section>

      <section className="panel event-panel">
        <div className="panel-heading">
          <h2>Recent Security Events</h2>
          <span>{events.length} tracked</span>
        </div>
        {recentEvents.length === 0 ? (
          <div className="empty-state">
            No events yet. Push the pipeline with{" "}
            <code>scripts/ingest-demo-events.sh</code>.
          </div>
        ) : (
          <div className="event-table">
            <div className="event-row event-head">
              <span>Time</span>
              <span>Source</span>
              <span>Event</span>
              <span>Severity</span>
              <span>Source IP</span>
            </div>
            {recentEvents.map((event: SecurityEvent) => (
              <div className="event-row" key={event.id}>
                <span>{formatTime(event.timestamp)}</span>
                <span>{event.sourceHost || event.destinationIp || "-"}</span>
                <span>{event.eventType}</span>
                <strong className={`severity ${event.severity.toLowerCase()}`}>{event.severity}</strong>
                <span>{event.sourceIp || "-"}</span>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}