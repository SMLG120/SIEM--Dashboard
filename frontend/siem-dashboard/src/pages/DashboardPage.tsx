import { useQuery } from "@tanstack/react-query";
import { Activity, AlertTriangle, Bell, Siren } from "lucide-react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { fetchServiceStatus, serviceEndpoints, type SecurityEvent, type SiemAlert } from "../api";
import { useAlerts, useDetectionSummary, useEvents } from "../hooks";

function formatTime(iso: string) {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function alertsToEventVolume(alerts: SiemAlert[]) {
  const buckets = new Map<string, number>();
  for (const alert of alerts) {
    const label = new Date(alert.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    buckets.set(label, (buckets.get(label) ?? 0) + 1);
  }
  return [...buckets.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([time, events]) => ({ time, events }))
    .slice(-12);
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
  const chartData = alertsToEventVolume(alerts);

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
            <h2>Alerts Over Time</h2>
            <span>Live stream</span>
          </div>
          {chartData.length === 0 ? (
            <div className="empty-state">
              No alerts yet. Ingest sample events with{" "}
              <code>scripts/ingest-demo-events.sh</code>.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="eventFill" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stopColor="#4dd4ac" stopOpacity={0.62} />
                    <stop offset="100%" stopColor="#4dd4ac" stopOpacity={0.04} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#213046" vertical={false} />
                <XAxis dataKey="time" stroke="#7d8da8" tickLine={false} axisLine={false} />
                <YAxis stroke="#7d8da8" tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#111a29", border: "1px solid #263550" }} />
                <Area type="monotone" dataKey="events" stroke="#4dd4ac" fill="url(#eventFill)" strokeWidth={3} />
              </AreaChart>
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