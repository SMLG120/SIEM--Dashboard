import { useState } from "react";
import type { AuthState } from "../auth";
import type { AlertStatus, SiemAlert } from "../api";
import { useAlerts, useUpdateAlertStatus } from "../hooks";

const WRITE_ROLES = ["ADMIN", "SOC_MANAGER", "SECURITY_ANALYST"];
const ALL_STATUSES: AlertStatus[] = ["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"];

function canWrite(auth: AuthState) {
  return auth.roles.some((role) => WRITE_ROLES.includes(role));
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleString([], {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function statusClass(status: AlertStatus) {
  return status === "OPEN"
    ? "open"
    : status === "ACKNOWLEDGED"
      ? "acknowledged"
      : status === "INVESTIGATING"
        ? "investigating"
        : "resolved";
}

export function AlertsPage({ auth }: { auth: AuthState }) {
  const alertsQuery = useAlerts();
  const updateStatus = useUpdateAlertStatus();
  const [filter, setFilter] = useState<AlertStatus | "ALL">("ALL");

  const write = canWrite(auth);
  const alerts = (alertsQuery.data ?? []).filter((alert) => filter === "ALL" || alert.status === filter);

  const busy = (id: string) =>
    updateStatus.isPending && updateStatus.variables?.id === id;

  return (
    <div className="page-stack">
      <div className="filter-tabs" role="tablist" aria-label="Filter alerts by status">
        <button
          type="button"
          className={`filter-tab ${filter === "ALL" ? "active" : ""}`}
          onClick={() => setFilter("ALL")}
        >
          All
        </button>
        {ALL_STATUSES.map((status) => (
          <button
            type="button"
            key={status}
            className={`filter-tab ${filter === status ? "active" : ""}`}
            onClick={() => setFilter(status)}
          >
            {status}
          </button>
        ))}
      </div>

      <section className="panel">
        <div className="panel-heading">
          <h2>Detected Alerts</h2>
          <span>{(alertsQuery.data ?? []).length} total</span>
        </div>

        {alerts.length === 0 ? (
          <div className="empty-state">
            No alerts {filter !== "ALL" ? `with status ${filter.toLowerCase()}` : "yet"}. Ingest events that
            match a rule (e.g. <code>MALWARE_DETECTED</code>) to generate alerts.
          </div>
        ) : (
          <div className="data-table">
            <div className="data-row data-head alert-grid">
              <span>Created</span>
              <span>Rule</span>
              <span>Severity</span>
              <span>Event</span>
              <span>Source</span>
              <span>Status</span>
              <span>Actions</span>
            </div>
            {alerts.map((alert: SiemAlert) => (
              <div className="data-row alert-grid" key={alert.id}>
                <span>{formatTime(alert.createdAt)}</span>
                <span>
                  <strong>{alert.ruleName}</strong>
                  <small className="muted-block">{alert.ruleId}</small>
                </span>
                <span>
                  <strong className={`severity ${alert.severity.toLowerCase()}`}>{alert.severity}</strong>
                </span>
                <span>{alert.eventType}</span>
                <span>
                  {alert.sourceIp || "-"}
                  {alert.userName ? <small className="muted-block">{alert.userName}</small> : null}
                </span>
                <span>
                  <span className={`status-pill ${statusClass(alert.status)}`}>{alert.status}</span>
                </span>
                <span className="row-actions">
                  {write && (alert.status === "OPEN" || alert.status === "ACKNOWLEDGED") && (
                    <button
                      type="button"
                      className="secondary-action"
                      disabled={busy(alert.id)}
                      onClick={() =>
                        updateStatus.mutate({ id: alert.id, action: "investigate" })
                      }
                    >
                      Investigate
                    </button>
                  )}
                  {write && (alert.status === "OPEN" || alert.status === "ACKNOWLEDGED") && (
                    <button
                      type="button"
                      className="ghost-action"
                      disabled={busy(alert.id)}
                      onClick={() =>
                        updateStatus.mutate({ id: alert.id, action: "acknowledge" })
                      }
                    >
                      Ack
                    </button>
                  )}
                  {write && alert.status !== "RESOLVED" && (
                    <button
                      type="button"
                      className="ghost-action"
                      disabled={busy(alert.id)}
                      onClick={() => updateStatus.mutate({ id: alert.id, action: "resolve" })}
                    >
                      Resolve
                    </button>
                  )}
                  {write && alert.status === "RESOLVED" && (
                    <button
                      type="button"
                      className="ghost-action"
                      disabled={busy(alert.id)}
                      onClick={() => updateStatus.mutate({ id: alert.id, action: "reopen" })}
                    >
                      Reopen
                    </button>
                  )}
                </span>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}