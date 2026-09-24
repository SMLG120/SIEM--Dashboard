import { useState, type FormEvent } from "react";
import { Check, Loader2, Plus, Send } from "lucide-react";
import type { AuthState } from "../auth";
import { commonEventTypes, eventSeverities, type EventSeverity, type IngestEventInput } from "../api";
import { useEvents, useIngestEvent } from "../hooks";

const WRITE_ROLES = ["ADMIN", "SOC_MANAGER", "SECURITY_ANALYST"];

function canWrite(auth: AuthState) {
  return auth.roles.some((role) => WRITE_ROLES.includes(role));
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

const emptyForm: IngestEventInput = {
  eventType: "LOGIN_FAILURE",
  severity: "MEDIUM",
  category: "",
  sourceIp: "",
  sourceHost: "",
  destinationIp: "",
  destinationPort: undefined,
  userName: "",
  message: ""
};

export function EventsPage({ auth }: { auth: AuthState }) {
  const eventsQuery = useEvents();
  const ingestMutation = useIngestEvent();
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<IngestEventInput>(emptyForm);

  const write = canWrite(auth);
  const events = eventsQuery.data ?? [];

  function update<K extends keyof IngestEventInput>(key: K, value: IngestEventInput[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!form.eventType.trim() || !form.severity) {
      return;
    }
    ingestMutation.mutate(
      {
        ...form,
        category: form.category?.trim() || undefined,
        sourceIp: form.sourceIp?.trim() || undefined,
        sourceHost: form.sourceHost?.trim() || undefined,
        destinationIp: form.destinationIp?.trim() || undefined,
        userName: form.userName?.trim() || undefined,
        message: form.message?.trim() || undefined
      },
      {
        onSuccess: () => {
          setForm(emptyForm);
          setShowForm(false);
        }
      }
    );
  }

  return (
    <div className="page-stack">
      {write && (
        <section className="panel">
          <div className="panel-heading">
            <h2>Ingest Event</h2>
            <button
              type="button"
              className="secondary-action"
              onClick={() => setShowForm((prev) => !prev)}
            >
              <Plus size={16} />
              {showForm ? "Hide form" : "New event"}
            </button>
          </div>

          {showForm && (
            <form className="ingest-form" onSubmit={submit}>
              <div className="form-grid">
                <label className="field">
                  <span>Event type</span>
                  <input
                    list="event-types"
                    value={form.eventType}
                    onChange={(e) => update("eventType", e.target.value)}
                    required
                    maxLength={100}
                  />
                  <datalist id="event-types">
                    {commonEventTypes.map((type) => (
                      <option key={type} value={type} />
                    ))}
                  </datalist>
                </label>

                <label className="field">
                  <span>Severity</span>
                  <select
                    value={form.severity}
                    onChange={(e) => update("severity", e.target.value as EventSeverity)}
                  >
                    {eventSeverities.map((severity) => (
                      <option key={severity} value={severity}>
                        {severity}
                      </option>
                    ))}
                  </select>
                </label>

                <label className="field">
                  <span>Category</span>
                  <input
                    value={form.category ?? ""}
                    onChange={(e) => update("category", e.target.value)}
                    maxLength={80}
                    placeholder="AUTHENTICATION, NETWORK, ENDPOINT..."
                  />
                </label>

                <label className="field">
                  <span>Source IP</span>
                  <input
                    value={form.sourceIp ?? ""}
                    onChange={(e) => update("sourceIp", e.target.value)}
                    maxLength={64}
                    placeholder="10.0.0.1"
                  />
                </label>

                <label className="field">
                  <span>Source host</span>
                  <input
                    value={form.sourceHost ?? ""}
                    onChange={(e) => update("sourceHost", e.target.value)}
                    maxLength={128}
                    placeholder="edr-mac-88"
                  />
                </label>

                <label className="field">
                  <span>Destination IP</span>
                  <input
                    value={form.destinationIp ?? ""}
                    onChange={(e) => update("destinationIp", e.target.value)}
                    maxLength={64}
                    placeholder="10.10.4.8"
                  />
                </label>

                <label className="field">
                  <span>Destination port</span>
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    value={form.destinationPort ?? ""}
                    onChange={(e) => {
                      const value = e.target.value === "" ? undefined : Number(e.target.value);
                      update("destinationPort", value);
                    }}
                  />
                </label>

                <label className="field">
                  <span>User</span>
                  <input
                    value={form.userName ?? ""}
                    onChange={(e) => update("userName", e.target.value)}
                    maxLength={128}
                    placeholder="sam.admin"
                  />
                </label>
              </div>

              <label className="field">
                <span>Message</span>
                <textarea
                  value={form.message ?? ""}
                  onChange={(e) => update("message", e.target.value)}
                  maxLength={2000}
                  rows={3}
                  placeholder="Free-form description of the event"
                />
              </label>

              <div className="form-actions">
                <button type="submit" className="primary-action" disabled={ingestMutation.isPending}>
                  {ingestMutation.isPending ? <Loader2 size={18} className="spin" /> : <Send size={18} />}
                  Ingest
                </button>
                {ingestMutation.isError && (
                  <span className="form-error">{"Failed to ingest event. Check the API gateway."}</span>
                )}
              </div>
            </form>
          )}
        </section>
      )}

      <section className="panel event-panel">
        <div className="panel-heading">
          <h2>Ingested Events</h2>
          <span>{events.length} tracked</span>
        </div>
        {events.length === 0 ? (
          <div className="empty-state">
            No events yet. Push the pipeline with{" "}
            <code>scripts/ingest-demo-events.sh</code>.
          </div>
        ) : (
          <div className="data-table">
            <div className="data-row data-head">
              <span>Time</span>
              <span>Event</span>
              <span>Severity</span>
              <span>Category</span>
              <span>Source</span>
              <span>User</span>
            </div>
            {events.map((event) => (
              <div className="data-row" key={event.id}>
                <span>{formatTime(event.timestamp)}</span>
                <span>
                  <strong>{event.eventType}</strong>
                </span>
                <span>
                  <strong className={`severity ${event.severity.toLowerCase()}`}>{event.severity}</strong>
                </span>
                <span>{event.category || "-"}</span>
                <span>
                  {event.sourceHost || event.sourceIp || event.destinationIp || "-"}
                  {event.sourceIp && event.sourceHost ? ` (${event.sourceIp})` : ""}
                </span>
                <span>{event.userName || "-"}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      {ingestMutation.isSuccess && (
        <div className="toast">
          <Check size={16} /> Ingested event {ingestMutation.data.id.slice(0, 8)}
        </div>
      )}
    </div>
  );
}