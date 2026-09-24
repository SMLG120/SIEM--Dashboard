import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import type { AuthState } from "../auth";
import type { IncidentStatus, SiemAlert } from "../api";
import { incidentStatuses } from "../api";
import {
  useAddIncidentNote,
  useAlerts,
  useIncident,
  useLinkAlertToIncident,
  useUpdateIncident
} from "../hooks";

const WRITE_ROLES = ["ADMIN", "SOC_MANAGER", "SECURITY_ANALYST"];

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

function statusClass(status: IncidentStatus) {
  return status === "OPEN"
    ? "open"
    : status === "INVESTIGATING"
      ? "investigating"
      : status === "CONTAINED"
        ? "acknowledged"
        : "resolved";
}

export function IncidentDetailPage({ auth }: { auth: AuthState }) {
  const { incidentId = "" } = useParams();
  const incidentQuery = useIncident(incidentId);
  const updateIncident = useUpdateIncident();
  const addNote = useAddIncidentNote(incidentId);
  const linkAlert = useLinkAlertToIncident(incidentId);
  const alertsQuery = useAlerts();

  const [assignee, setAssignee] = useState("");
  const [noteText, setNoteText] = useState("");
  const [selectedAlert, setSelectedAlert] = useState("");

  const write = canWrite(auth);

  const incident = incidentQuery.data;
  const linkedAlertIds = useMemo(
    () => new Set((incident?.relatedAlerts ?? []).map((alert) => alert.id)),
    [incident]
  );
  const linkableAlerts: SiemAlert[] = useMemo(
    () =>
      (alertsQuery.data ?? []).filter(
        (alert) => alert.status !== "RESOLVED" && !linkedAlertIds.has(alert.id)
      ),
    [alertsQuery.data, linkedAlertIds]
  );

  if (incidentQuery.isLoading || !incident) {
    return <div className="empty-state">Loading incident {incidentId}...</div>;
  }

  return (
    <div className="page-stack">
      <div className="panel">
        <div className="panel-heading">
          <div>
            <p className="muted-block">{incident.id}</p>
            <h2>{incident.title}</h2>
            {incident.description ? <p className="muted-block">{incident.description}</p> : null}
          </div>
          <div className="row-cluster">
            <strong className={`severity ${incident.severity.toLowerCase()}`}>{incident.severity}</strong>
            <span className={`status-pill ${statusClass(incident.status)}`}>{incident.status}</span>
          </div>
        </div>

        <div className="meta-grid">
          <div className="meta-cell">
            <label>Assigned To</label>
            <div className="row-cluster">
              <input
                className="text-input"
                placeholder="analyst username"
                value={assignee || incident.assignedTo || ""}
                disabled={!write}
                onChange={(event) => setAssignee(event.target.value)}
              />
              {write && (
                <button
                  type="button"
                  className="secondary-action"
                  disabled={!assignee.trim()}
                  onClick={() => {
                    updateIncident.mutate({
                      id: incident.id,
                      input: { assignedTo: assignee.trim() }
                    });
                    setAssignee("");
                  }}
                >
                  Assign
                </button>
              )}
            </div>
          </div>
          <div className="meta-cell">
            <label>Status</label>
            <div className="row-cluster">
              <select
                className="text-input"
                value={incident.status}
                disabled={!write}
                onChange={(event) => {
                  const status = event.target.value as IncidentStatus;
                  if (status !== incident.status) {
                    updateIncident.mutate({ id: incident.id, input: { status } });
                  }
                }}
              >
                {incidentStatuses.map((status) => (
                  <option key={status} value={status}>
                    {status}
                  </option>
                ))}
              </select>
              <span className="muted-block">Created {formatTime(incident.createdAt)}</span>
            </div>
          </div>
          <div className="meta-cell">
            <label>Related Alerts</label>
            <span className="pill-count">{incident.relatedAlerts.length}</span>
          </div>
        </div>
      </div>

      <div className="split-grid">
        <section className="panel">
          <div className="panel-heading">
            <h2>Timeline</h2>
          </div>
          {incident.timeline.length === 0 ? (
            <div className="empty-state">No timeline events yet.</div>
          ) : (
            <ol className="timeline">
              {[...incident.timeline].reverse().map((entry, index) => (
                <li className="timeline-item" key={`${entry.occurredAt}-${index}`}>
                  <span className="timeline-dot" />
                  <div className="timeline-body">
                    <span className="timeline-time">{formatTime(entry.occurredAt)}</span>
                    <strong>{entry.action.replaceAll("_", " ")}</strong>
                    <span className="muted-block">
                      by {entry.actor}
                      {entry.detail ? ` — ${entry.detail}` : ""}
                    </span>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </section>

        <section className="panel">
          <div className="panel-heading">
            <h2>Related Alerts</h2>
          </div>
          {incident.relatedAlerts.length === 0 ? (
            <div className="empty-state">No alerts linked. Alerts matching the same source IP are linked
              automatically.</div>
          ) : (
            <div className="data-table">
              <div className="data-row data-head related-grid">
                <span>Rule</span>
                <span>Severity</span>
                <span>Event</span>
                <span>Source</span>
              </div>
              {incident.relatedAlerts.map((alert) => (
                <div className="data-row related-grid" key={alert.id}>
                  <span>
                    <strong>{alert.ruleName}</strong>
                    <small className="muted-block">{alert.ruleId}</small>
                  </span>
                  <span>
                    <strong className={`severity ${alert.severity.toLowerCase()}`}>{alert.severity}</strong>
                  </span>
                  <span>{alert.eventType}</span>
                  <span>{alert.sourceIp || "-"}</span>
                </div>
              ))}
            </div>
          )}

          {write && linkableAlerts.length > 0 && (
            <form
              className="inline-form link-form"
              onSubmit={(event) => {
                event.preventDefault();
                const alert = alertsQuery.data?.find((item) => item.id === selectedAlert);
                if (!alert) {
                  return;
                }
                linkAlert.mutate(
                  {
                    alertId: alert.id,
                    ruleId: alert.ruleId,
                    ruleName: alert.ruleName,
                    eventType: alert.eventType,
                    severity: alert.severity,
                    sourceIp: alert.sourceIp,
                    description: alert.description
                  },
                  { onSuccess: () => setSelectedAlert("") }
                );
              }}
            >
              <select
                className="text-input"
                value={selectedAlert}
                onChange={(event) => setSelectedAlert(event.target.value)}
              >
                <option value="">Link an open alert…</option>
                {linkableAlerts.map((alert) => (
                  <option key={alert.id} value={alert.id}>
                    {alert.ruleName} · {alert.severity} · {alert.sourceIp || "-"}
                  </option>
                ))}
              </select>
              <button type="submit" className="secondary-action" disabled={!selectedAlert}>
                Link
              </button>
            </form>
          )}
        </section>
      </div>

      <section className="panel">
        <div className="panel-heading">
          <h2>Analyst Notes</h2>
        </div>
        {incident.notes.length === 0 ? (
          <div className="empty-state">No notes yet.</div>
        ) : (
          <ul className="note-list">
            {[...incident.notes].reverse().map((note) => (
              <li key={note.id}>
                <p>{note.text}</p>
                <small className="muted-block">
                  {note.author} · {formatTime(note.createdAt)}
                </small>
              </li>
            ))}
          </ul>
        )}
        {write && (
          <form
            className="inline-form"
            onSubmit={(event) => {
              event.preventDefault();
              if (!noteText.trim()) {
                return;
              }
              addNote.mutate(noteText.trim(), {
                onSuccess: () => setNoteText("")
              });
            }}
          >
            <input
              className="text-input"
              placeholder="Add an investigation note…"
              value={noteText}
              onChange={(event) => setNoteText(event.target.value)}
            />
            <button type="submit" className="secondary-action" disabled={!noteText.trim()}>
              Add Note
            </button>
          </form>
        )}
      </section>

      <p className="muted-block">
        <Link to="/incidents">← Back to incidents</Link>
      </p>
    </div>
  );
}