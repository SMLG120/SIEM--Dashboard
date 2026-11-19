import { ExternalLink } from "lucide-react";
import type { AlertEvidence, EventSeverity, MitreTechnique } from "./api";

export const WRITE_ROLES = ["ADMIN", "SOC_MANAGER", "SECURITY_ANALYST"];
export const MANAGER_ROLES = ["ADMIN", "SOC_MANAGER"];

export function hasAnyRole(roles: string[], allowed: string[]) {
  return roles.some((role) => allowed.includes(role));
}

export function formatTime(iso?: string) {
  if (!iso) return "-";
  return new Date(iso).toLocaleString([], {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

export function SeverityBadge({ severity }: { severity: EventSeverity }) {
  return <strong className={`severity ${severity.toLowerCase()}`}>{severity}</strong>;
}

/** ATT&CK technique IDs link to the public MITRE page (T1059.001 -> techniques/T1059/001). */
export function mitreUrl(techniqueId: string) {
  return `https://attack.mitre.org/techniques/${techniqueId.replace(".", "/")}/`;
}

export function MitreChips({ mitre }: { mitre?: MitreTechnique[] }) {
  if (!mitre || mitre.length === 0) {
    return <span className="muted">No ATT&CK mapping</span>;
  }
  return (
    <span className="chip-row">
      {mitre.map((m) => (
        <a
          key={`${m.tactic}-${m.techniqueId}`}
          className="mitre-chip"
          href={mitreUrl(m.techniqueId)}
          target="_blank"
          rel="noreferrer noopener"
          title={`${m.tactic}: ${m.technique}`}
        >
          {m.techniqueId} <small>{m.technique}</small>
          <ExternalLink size={11} aria-hidden="true" />
        </a>
      ))}
    </span>
  );
}

/** Explains why an alert fired: matched clauses, window, group and contributing events. */
export function EvidencePanel({ evidence }: { evidence?: AlertEvidence }) {
  if (!evidence) {
    return <p className="muted">This alert predates evidence capture (schema v1).</p>;
  }
  return (
    <div className="evidence">
      <dl className="kv-grid">
        <dt>Rule type</dt>
        <dd>{evidence.ruleType}</dd>
        {evidence.groupKey ? (
          <>
            <dt>Grouped by</dt>
            <dd>
              <code>{evidence.groupKey}</code>
            </dd>
          </>
        ) : null}
        {evidence.windowSeconds ? (
          <>
            <dt>Window</dt>
            <dd>{evidence.windowSeconds}s</dd>
          </>
        ) : null}
        <dt>Events</dt>
        <dd>
          {evidence.eventCount}
          {evidence.eventIds.length < evidence.eventCount ? ` (first ${evidence.eventIds.length} listed)` : ""}
        </dd>
        <dt>Seen</dt>
        <dd>
          {formatTime(evidence.firstSeen)} → {formatTime(evidence.lastSeen)}
        </dd>
      </dl>
      <h4>Matched conditions</h4>
      <ul className="condition-list">
        {evidence.matchedConditions.map((c) => (
          <li key={c}>
            <code>{c}</code>
          </li>
        ))}
      </ul>
      <h4>Contributing events</h4>
      <div className="chip-row">
        {evidence.eventIds.map((id) => (
          <code key={id} className="id-chip">
            {id.length > 13 ? `${id.slice(0, 8)}…` : id}
          </code>
        ))}
      </div>
    </div>
  );
}
