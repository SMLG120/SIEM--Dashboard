import { useState } from "react";
import { Link } from "react-router-dom";
import type { AuthState } from "../auth";
import type { EventSeverity, IncidentStatus } from "../api";
import { eventSeverities, incidentStatuses } from "../api";
import { useCreateIncident, useIncidents } from "../hooks";

const WRITE_ROLES = ["ADMIN", "SOC_MANAGER", "SECURITY_ANALYST"];

function canWrite(auth: AuthState) {
  return auth.roles.some((role) => WRITE_ROLES.includes(role));
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleString([], {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function statusClass(status: IncidentStatus) {
  return status === "OPEN"
    ? "open"
    : status === "INVESTIGATING"
      ? "investigating"
      : status === "CONTAINED"
        ? "acknowledged"
        : "resolved";
}

export function IncidentsPage({ auth }: { auth: AuthState }) {
  const incidentsQuery = useIncidents();
  const createIncident = useCreateIncident();
  const [filter, setFilter] = useState<IncidentStatus | "ALL">("ALL");
  const [form, setForm] = useState({
    title: "",
    description: "",
    severity: "HIGH" as EventSeverity
  });

  const write = canWrite(auth);
  const incidents = (incidentsQuery.data ?? []).filter(
    (incident) => filter === "ALL" || incident.status === filter
  );

  const creating = createIncident.isPending;

  return (
    <div className="page-stack">
      {write && (
        <section className="panel">
          <div className="panel-heading">
            <h2>Create Incident</h2>
          </div>
          <form
            className="inline-form"
            onSubmit={(event) => {
              event.preventDefault();
              if (!form.title.trim()) {
                return;
              }
              createIncident.mutate(
                {
                  title: form.title.trim(),
                  description: form.description.trim() || undefined,
                  severity: form.severity
                },
                {
                  onSuccess: () => {
                    setForm({ title: "", description: "", severity: "HIGH" });
                  }
                }
              );
            }}
          >
            <input
              className="text-input"
              placeholder="Incident title"
              value={form.title}
              disabled={creating}
              onChange={(event) => setForm({ ...form, title: event.target.value })}
            />
            <input
              className="text-input"
              placeholder="Description (optional)"
              value={form.description}
              disabled={creating}
              onChange={(event) => setForm({ ...form, description: event.target.value })}
            />
            <select
              className="text-input"
              value={form.severity}
              disabled={creating}
              onChange={(event) => setForm({ ...form, severity: event.target.value as EventSeverity })}
            >
              {eventSeverities.map((severity) => (
                <option key={severity} value={severity}>
                  {severity}
                </option>
              ))}
            </select>
            <button type="submit" className="primary-action" disabled={creating || !form.title.trim()}>
              {creating ? "Creating..." : "Create"}
            </button>
          </form>
        </section>
      )}

      <div className="filter-tabs" role="tablist" aria-label="Filter incidents by status">
        <button
          type="button"
          className={`filter-tab ${filter === "ALL" ? "active" : ""}`}
          onClick={() => setFilter("ALL")}
        >
          All
        </button>
        {incidentStatuses.map((status) => (
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
          <h2>Open Incidents</h2>
          <span>{(incidentsQuery.data ?? []).length} total</span>
        </div>

        {incidents.length === 0 ? (
          <div className="empty-state">
            No incidents {filter !== "ALL" ? `with status ${filter.toLowerCase()}` : ""}. Alerts sharing a
            source IP are correlated into incidents automatically.
          </div>
        ) : (
          <div className="data-table">
            <div className="data-row data-head incident-grid">
              <span>Severity</span>
              <span>Incident</span>
              <span>Alerts</span>
              <span>Status</span>
              <span>Assigned</span>
              <span>Updated</span>
            </div>
            {incidents.map((incident) => (
              <Link
                className="data-row incident-grid"
                key={incident.id}
                to={`/incidents/${incident.id}`}
              >
                <span>
                  <strong className={`severity ${incident.severity.toLowerCase()}`}>{incident.severity}</strong>
                </span>
                <span>
                  <strong>{incident.title}</strong>
                  <small className="muted-block">{incident.id}</small>
                </span>
                <span>{incident.relatedAlerts.length}</span>
                <span>
                  <span className={`status-pill ${statusClass(incident.status)}`}>{incident.status}</span>
                </span>
                <span>{incident.assignedTo || "Unassigned"}</span>
                <span>{formatTime(incident.updatedAt)}</span>
              </Link>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}