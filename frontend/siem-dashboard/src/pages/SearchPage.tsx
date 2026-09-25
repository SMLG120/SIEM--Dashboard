import { useState } from "react";
import type { SearchHit } from "../api";
import { useSearchAlerts, useSearchEvents, useSearchSummary } from "../hooks";

function formatTime(iso?: string) {
  if (!iso) return "-";
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function SeverityBar({ bySeverity }: { bySeverity: Record<string, number> }) {
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const total = Object.values(bySeverity).reduce((sum, value) => sum + value, 0);
  if (total === 0) {
    return <span className="muted-block">No documents indexed yet.</span>;
  }
  return (
    <div className="severity-strip">
      {order.map((severity) => {
        const value = bySeverity[severity] ?? 0;
        if (value === 0) return null;
        return (
          <span
            key={severity}
            className={`severity-fraction ${severity.toLowerCase()}`}
            style={{ width: `${(value / total) * 100}%` }}
            title={`${severity}: ${value}`}
          >
            {severity}
          </span>
        );
      })}
    </div>
  );
}

function SearchPanel({
  title,
  placeholder,
  query,
  onQuery,
  hits,
  loading
}: {
  title: string;
  placeholder: string;
  query: string;
  onQuery: (value: string) => void;
  hits: SearchHit[];
  loading: boolean;
}) {
  return (
    <article className="panel">
      <div className="panel-heading">
        <h3>{title}</h3>
        <span>{hits.length} results</span>
      </div>
      <input
        className="search-input"
        type="search"
        value={query}
        placeholder={placeholder}
        onChange={(event) => onQuery(event.target.value)}
      />
      {loading ? (
        <div className="empty-state">Searching...</div>
      ) : query.trim().length === 0 ? (
        <div className="empty-state">Type a query to search {title.toLowerCase()}.</div>
      ) : (
        <div className="data-table search-results">
          <div className="data-row data-head search-grid">
            <span>Time</span>
            <span>Severity</span>
            <span>Type</span>
            <span>Details</span>
          </div>
          {hits.map((hit) => {
            const fields = hit.fields as Record<string, string>;
            return (
              <div className="data-row search-grid" key={`${hit.index}:${hit.id}`}>
                <span>{formatTime(hit.timestamp)}</span>
                <span>
                  <strong className={`severity ${String(fields.severity ?? "info").toLowerCase()}`}>
                    {fields.severity ?? "-"}
                  </strong>
                </span>
                <span>
                  <code>{fields.eventType ?? fields.ruleId ?? "-"}</code>
                </span>
                <span className="search-detail">
                  <span>
                    {fields.message ?? fields.description ?? fields.ruleName ?? fields.category ?? ""}
                  </span>
                  <small className="muted-block">
                    {fields.sourceIp ? `src ${fields.sourceIp}` : ""}
                    {fields.userName ? ` user ${fields.userName}` : ""}
                    {fields.status ? ` status ${fields.status}` : ""}
                  </small>
                </span>
              </div>
            );
          })}
        </div>
      )}
    </article>
  );
}

export function SearchPage() {
  const [eventQuery, setEventQuery] = useState("");
  const [alertQuery, setAlertQuery] = useState("");
  const summaryQuery = useSearchSummary();
  const eventsQuery = useSearchEvents(eventQuery);
  const alertsQuery = useSearchAlerts(alertQuery);

  const summary = summaryQuery.data;

  return (
    <div className="page-stack">
      <section className="metric-grid search-metrics" aria-label="Indexed document metrics">
        <div className="metric-card">
          <span className="metric-label">Indexed Events</span>
          <strong>{summary?.eventsCount ?? 0}</strong>
        </div>
        <div className="metric-card">
          <span className="metric-label">Indexed Alerts</span>
          <strong>{summary?.alertsCount ?? 0}</strong>
        </div>
        <div className="metric-card metric-wide">
          <span className="metric-label">Events by Severity</span>
          <SeverityBar bySeverity={summary?.eventsBySeverity ?? {}} />
        </div>
        <div className="metric-card metric-wide">
          <span className="metric-label">Alerts by Severity</span>
          <SeverityBar bySeverity={summary?.alertsBySeverity ?? {}} />
        </div>
      </section>

      <SearchPanel
        title="Event Search"
        placeholder="Search events: malware, port scan, 10.0.0.5, alice, ..."
        query={eventQuery}
        onQuery={setEventQuery}
        hits={eventsQuery.data ?? []}
        loading={eventsQuery.isLoading}
      />

      <SearchPanel
        title="Alert Search"
        placeholder="Search alerts: SIEM-1002, LOGIN_FAILURE, 203.0.113.9, critical, ..."
        query={alertQuery}
        onQuery={setAlertQuery}
        hits={alertsQuery.data ?? []}
        loading={alertsQuery.isLoading}
      />
    </div>
  );
}