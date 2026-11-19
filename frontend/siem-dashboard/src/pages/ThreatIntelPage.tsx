import { useState } from "react";
import type { AuthState } from "../auth";
import { eventSeverities, type EventSeverity, type IndicatorType } from "../api";
import { formatTime, hasAnyRole, MANAGER_ROLES, SeverityBadge } from "../components";
import { useCreateIndicator, useDeactivateIndicator, useIndicators, useSightings } from "../hooks";

const TYPES: IndicatorType[] = ["IP", "DOMAIN", "MD5", "SHA1", "SHA256"];

function shorten(value: string) {
  return value.length > 24 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
}

export function ThreatIntelPage({ auth }: { auth: AuthState }) {
  const indicators = useIndicators();
  const sightings = useSightings();
  const manage = hasAnyRole(auth.roles, MANAGER_ROLES);
  const list = indicators.data ?? [];
  const demoOnly = list.length > 0 && list.every((i) => i.source === "SIMULATED_DEMO");

  return (
    <div className="page-stack">
      <p className="notice" role="note">
        Indicators are curated by analysts. No external threat feeds are connected
        {demoOnly ? "; the entries below are labelled simulated demo data (documentation IPs and EICAR test hashes)" : ""}.
      </p>

      <section className="split-grid">
        <article className="panel">
          <div className="panel-heading">
            <h2>Indicators</h2>
            <span>{list.length} active</span>
          </div>
          {indicators.isError ? <div className="empty-state error">{indicators.error.message}</div> : null}
          {list.length === 0 && !indicators.isLoading ? <div className="empty-state">No active indicators.</div> : null}
          <div className="data-table" role="table" aria-label="Indicators">
            {list.length > 0 ? (
              <div className="data-row data-head ioc-grid" role="row">
                <span>Type</span>
                <span>Value</span>
                <span>Severity</span>
                <span>Source</span>
              </div>
            ) : null}
            {list.map((i) => (
              <div className="data-row ioc-grid" role="row" key={i.id}>
                <span>
                  <code>{i.type}</code>
                </span>
                <span title={i.value}>
                  <strong className="mono">{shorten(i.value)}</strong>
                  {i.description ? <small className="muted-block">{i.description}</small> : null}
                </span>
                <span>
                  <SeverityBadge severity={i.severity} />
                </span>
                <span>
                  <span className={`status-pill ${i.source === "SIMULATED_DEMO" ? "acknowledged" : "ready"}`}>
                    {i.source === "SIMULATED_DEMO" ? "simulated" : i.source.toLowerCase()}
                  </span>
                  <small className="muted-block">{i.createdBy}</small>
                  {manage ? <DeactivateButton id={i.id} value={i.value} /> : null}
                </span>
              </div>
            ))}
          </div>
          {manage ? <AddIndicator /> : null}
        </article>

        <article className="panel">
          <div className="panel-heading">
            <h2>Sightings</h2>
            <span>events matching an indicator</span>
          </div>
          {sightings.isError ? <div className="empty-state error">{sightings.error.message}</div> : null}
          {(sightings.data ?? []).length === 0 && !sightings.isLoading ? (
            <div className="empty-state">No sightings yet. Events whose IPs, domains or hashes match an indicator appear here.</div>
          ) : null}
          <ol className="timeline">
            {(sightings.data ?? []).map((s) => (
              <li key={`${s.indicatorId}-${s.eventId}-${s.field}`}>
                <span className="timeline-time">{formatTime(s.eventTime)}</span>
                <code>{s.type}</code> <strong className="mono">{shorten(s.value)}</strong> in <code>{s.field}</code>
                <small className="muted-block">event {s.eventId.slice(0, 8)}…</small>
              </li>
            ))}
          </ol>
        </article>
      </section>
    </div>
  );
}

function DeactivateButton({ id, value }: { id: string; value: string }) {
  const deactivate = useDeactivateIndicator();
  return (
    <button
      type="button"
      className="ghost-action"
      aria-label={`Deactivate ${value}`}
      disabled={deactivate.isPending}
      onClick={() => deactivate.mutate(id)}
    >
      Deactivate
    </button>
  );
}

function AddIndicator() {
  const create = useCreateIndicator();
  const [type, setType] = useState<IndicatorType>("IP");
  const [value, setValue] = useState("");
  const [severity, setSeverity] = useState<EventSeverity>("HIGH");
  const [description, setDescription] = useState("");

  return (
    <form
      className="inline-form wrap"
      aria-label="Add indicator"
      onSubmit={(e) => {
        e.preventDefault();
        create.mutate(
          { type, value: value.trim(), severity, description: description.trim() || undefined },
          {
            onSuccess: () => {
              setValue("");
              setDescription("");
            }
          }
        );
      }}
    >
      <select aria-label="Indicator type" value={type} onChange={(e) => setType(e.target.value as IndicatorType)}>
        {TYPES.map((t) => (
          <option key={t}>{t}</option>
        ))}
      </select>
      <input aria-label="Indicator value" value={value} onChange={(e) => setValue(e.target.value)} placeholder="value" maxLength={256} required />
      <select aria-label="Indicator severity" value={severity} onChange={(e) => setSeverity(e.target.value as EventSeverity)}>
        {eventSeverities.map((s) => (
          <option key={s}>{s}</option>
        ))}
      </select>
      <input
        aria-label="Description"
        value={description}
        onChange={(e) => setDescription(e.target.value)}
        placeholder="why this is malicious"
        maxLength={500}
      />
      <button type="submit" className="primary-action" disabled={!value.trim() || create.isPending}>
        Add indicator
      </button>
      {create.isError ? <p className="form-error">{create.error.message}</p> : null}
    </form>
  );
}
