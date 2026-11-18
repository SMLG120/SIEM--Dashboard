import { useState } from "react";
import { X } from "lucide-react";
import type { AuthState } from "../auth";
import { eventSeverities, type AlertStatus, type EventSeverity, type SiemAlert } from "../api";
import { EvidencePanel, formatTime, hasAnyRole, MitreChips, SeverityBadge, WRITE_ROLES } from "../components";
import {
  useAddAlertNote,
  useAlertAssign,
  useAlertHistory,
  useAlertSearch,
  useAlertWorkflow,
  useUpdateAlertStatus,
  type AlertFilters
} from "../hooks";

const ALL_STATUSES: AlertStatus[] = ["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"];
const PAGE_SIZE = 25;

function statusClass(status: AlertStatus) {
  return status.toLowerCase();
}

function toggle<T>(list: T[], value: T) {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

export function AlertsPage({ auth }: { auth: AuthState }) {
  const [filters, setFilters] = useState<AlertFilters>({
    status: ["OPEN", "ACKNOWLEDGED", "INVESTIGATING"],
    severity: [],
    sort: "severity",
    page: 0,
    size: PAGE_SIZE
  });
  const [selected, setSelected] = useState<SiemAlert>();
  const query = useAlertSearch(filters);
  const update = (patch: Partial<AlertFilters>) => setFilters((f) => ({ ...f, page: 0, ...patch }));
  const page = query.data;
  const pages = page ? Math.max(1, Math.ceil(page.total / page.size)) : 1;

  return (
    <div className="page-stack">
      <section className="panel filter-bar" aria-label="Alert filters">
        <div className="filter-group" role="group" aria-label="Status">
          {ALL_STATUSES.map((status) => (
            <button
              type="button"
              key={status}
              aria-pressed={filters.status.includes(status)}
              className={`filter-tab ${filters.status.includes(status) ? "active" : ""}`}
              onClick={() => update({ status: toggle(filters.status, status) })}
            >
              {status}
            </button>
          ))}
        </div>
        <div className="filter-group" role="group" aria-label="Severity">
          {[...eventSeverities].reverse().map((sev) => (
            <button
              type="button"
              key={sev}
              aria-pressed={filters.severity.includes(sev)}
              className={`filter-tab sev-${sev.toLowerCase()} ${filters.severity.includes(sev) ? "active" : ""}`}
              onClick={() => update({ severity: toggle(filters.severity, sev as EventSeverity) })}
            >
              {sev}
            </button>
          ))}
        </div>
        <label className="inline-field">
          Source IP
          <input
            value={filters.sourceIp ?? ""}
            placeholder="any"
            onChange={(e) => update({ sourceIp: e.target.value.trim() || undefined })}
          />
        </label>
        <label className="inline-field">
          Rule
          <input
            value={filters.ruleId ?? ""}
            placeholder="SIEM-…"
            onChange={(e) => update({ ruleId: e.target.value.trim().toUpperCase() || undefined })}
          />
        </label>
        <label className="inline-field">
          Sort
          <select value={filters.sort} onChange={(e) => update({ sort: e.target.value as AlertFilters["sort"] })}>
            <option value="severity">Severity</option>
            <option value="created">Newest</option>
          </select>
        </label>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <h2>Triage Queue</h2>
          <span aria-live="polite">{page ? `${page.total} matching` : "loading…"}</span>
        </div>
        {query.isError ? (
          <div className="empty-state error">Could not load alerts: {query.error.message}</div>
        ) : page && page.items.length === 0 ? (
          <div className="empty-state">No alerts match these filters.</div>
        ) : (
          <div className="data-table" role="table" aria-label="Alerts">
            <div className="data-row data-head alert-grid" role="row">
              <span>Created</span>
              <span>Rule</span>
              <span>Severity</span>
              <span>ATT&CK</span>
              <span>Source</span>
              <span>Status</span>
            </div>
            {(page?.items ?? []).map((alert) => (
              <button
                type="button"
                role="row"
                className={`data-row alert-grid row-button ${selected?.id === alert.id ? "selected" : ""}`}
                key={alert.id}
                onClick={() => setSelected(alert)}
              >
                <span>{formatTime(alert.createdAt)}</span>
                <span>
                  <strong>{alert.ruleName}</strong>
                  <small className="muted-block">
                    {alert.ruleId}
                    {alert.ruleVersion ? ` v${alert.ruleVersion}` : ""}
                  </small>
                </span>
                <span>
                  <SeverityBadge severity={alert.severity} />
                </span>
                <span className="mitre-cell">
                  {(alert.mitre ?? []).map((m) => m.techniqueId).join(", ") || "-"}
                </span>
                <span>
                  {alert.sourceIp || "-"}
                  {alert.userName ? <small className="muted-block">{alert.userName}</small> : null}
                </span>
                <span>
                  <span className={`status-pill ${statusClass(alert.status)}`}>{alert.status}</span>
                </span>
              </button>
            ))}
          </div>
        )}
        <div className="pager">
          <button
            type="button"
            className="ghost-action"
            disabled={filters.page === 0}
            onClick={() => setFilters((f) => ({ ...f, page: f.page - 1 }))}
          >
            Previous
          </button>
          <span>
            Page {filters.page + 1} of {pages}
          </span>
          <button
            type="button"
            className="ghost-action"
            disabled={filters.page + 1 >= pages}
            onClick={() => setFilters((f) => ({ ...f, page: f.page + 1 }))}
          >
            Next
          </button>
        </div>
      </section>

      {selected ? <AlertDrawer alertId={selected.id} auth={auth} onClose={() => setSelected(undefined)} /> : null}
    </div>
  );
}

function AlertDrawer({ alertId, auth, onClose }: { alertId: string; auth: AuthState; onClose: () => void }) {
  const workflow = useAlertWorkflow(alertId);
  const history = useAlertHistory(alertId);
  const updateStatus = useUpdateAlertStatus();
  const assign = useAlertAssign();
  const addNote = useAddAlertNote(alertId);
  const [note, setNote] = useState("");
  const [assignee, setAssignee] = useState("");
  const write = hasAnyRole(auth.roles, WRITE_ROLES);
  const detail = workflow.data;
  const alert = detail?.alert;

  const act = (action: "acknowledge" | "investigate" | "resolve" | "reopen") =>
    updateStatus.mutate(
      { id: alertId, action },
      { onSettled: () => void workflow.refetch().then(() => history.refetch()) }
    );

  return (
    <aside className="drawer" role="dialog" aria-modal="false" aria-label="Alert details">
      <div className="drawer-head">
        <div>
          <p className="muted">{alertId}</p>
          <h2>{alert?.ruleName ?? "Loading…"}</h2>
        </div>
        <button type="button" className="icon-button" onClick={onClose} aria-label="Close alert details">
          <X size={18} />
        </button>
      </div>
      {alert ? (
        <div className="drawer-body">
          <div className="chip-row">
            <SeverityBadge severity={alert.severity} />
            <span className={`status-pill ${statusClass(alert.status)}`}>{alert.status}</span>
            <span className="muted">
              {alert.ruleId}
              {alert.ruleVersion ? ` v${alert.ruleVersion}` : ""} · assigned to {detail?.assignedTo ?? "nobody"}
            </span>
          </div>
          <p>{alert.description}</p>

          {write ? (
            <div className="row-actions">
              {(alert.status === "OPEN" || alert.status === "ACKNOWLEDGED") && (
                <button type="button" className="secondary-action" onClick={() => act("investigate")}>
                  Investigate
                </button>
              )}
              {alert.status === "OPEN" && (
                <button type="button" className="ghost-action" onClick={() => act("acknowledge")}>
                  Acknowledge
                </button>
              )}
              {alert.status !== "RESOLVED" ? (
                <button type="button" className="ghost-action" onClick={() => act("resolve")}>
                  Resolve
                </button>
              ) : (
                <button type="button" className="ghost-action" onClick={() => act("reopen")}>
                  Reopen
                </button>
              )}
            </div>
          ) : null}
          {updateStatus.isError ? <p className="form-error">{updateStatus.error.message}</p> : null}

          <h3>Why this alert fired</h3>
          <EvidencePanel evidence={alert.evidence} />

          <h3>MITRE ATT&CK</h3>
          <MitreChips mitre={alert.mitre} />

          {write ? (
            <form
              className="inline-form"
              onSubmit={(e) => {
                e.preventDefault();
                if (assignee.trim()) {
                  assign.mutate({ id: alertId, assignedTo: assignee.trim() }, {
                    onSuccess: () => {
                      setAssignee("");
                      void workflow.refetch().then(() => history.refetch());
                    }
                  });
                }
              }}
            >
              <label className="inline-field">
                Assign to
                <input value={assignee} onChange={(e) => setAssignee(e.target.value)} placeholder="username" />
              </label>
              <button type="submit" className="ghost-action" disabled={!assignee.trim() || assign.isPending}>
                Assign
              </button>
            </form>
          ) : null}

          <h3>Notes</h3>
          {(detail?.notes ?? []).length === 0 ? <p className="muted">No notes yet.</p> : null}
          <ul className="note-list">
            {(detail?.notes ?? []).map((n) => (
              <li key={n.id}>
                <strong>{n.author}</strong> <small className="muted">{formatTime(n.createdAt)}</small>
                <p>{n.text}</p>
              </li>
            ))}
          </ul>
          {write ? (
            <form
              className="inline-form"
              onSubmit={(e) => {
                e.preventDefault();
                if (note.trim()) {
                  addNote.mutate(note.trim(), {
                    onSuccess: () => {
                      setNote("");
                      void workflow.refetch().then(() => history.refetch());
                    }
                  });
                }
              }}
            >
              <textarea
                aria-label="New note"
                value={note}
                maxLength={4000}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Add an investigation note"
              />
              <button type="submit" className="primary-action" disabled={!note.trim() || addNote.isPending}>
                Add note
              </button>
            </form>
          ) : null}

          <h3>History</h3>
          <ol className="timeline">
            {(history.data ?? []).map((h, i) => (
              <li key={`${h.occurredAt}-${i}`}>
                <span className="timeline-time">{formatTime(h.occurredAt)}</span>
                <strong>{h.action}</strong> by {h.actor}
                {h.fromStatus && h.toStatus ? (
                  <small className="muted">
                    {" "}
                    {h.fromStatus} → {h.toStatus}
                  </small>
                ) : null}
                {h.detail ? <small className="muted-block">{h.detail}</small> : null}
              </li>
            ))}
          </ol>
        </div>
      ) : workflow.isError ? (
        <p className="form-error">{workflow.error.message}</p>
      ) : null}
    </aside>
  );
}
