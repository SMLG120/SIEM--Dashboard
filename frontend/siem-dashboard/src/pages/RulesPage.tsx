import { useMemo, useState } from "react";
import { FlaskConical, Play } from "lucide-react";
import type { AuthState } from "../auth";
import { eventSeverities, type DetectionRule, type RuleCondition, type SecurityEvent } from "../api";
import { EvidencePanel, formatTime, hasAnyRole, MANAGER_ROLES, MitreChips, SeverityBadge, WRITE_ROLES } from "../components";
import { useRuleHistory, useRuleTest, useRuleUpdate, useRules } from "../hooks";

/** Human-readable summary of the clauses an event must satisfy. */
export function describeCondition(c?: RuleCondition): string[] {
  if (!c) return [];
  const parts: string[] = [];
  if (c.eventTypes?.length) parts.push(`eventType in [${c.eventTypes.join(", ")}]`);
  if (c.severityMin) parts.push(`severity >= ${c.severityMin}`);
  if (c.category) parts.push(`category = ${c.category}`);
  if (c.messageContainsAny?.length) parts.push(`message contains any of [${c.messageContainsAny.join(", ")}]`);
  Object.entries(c.attributeContainsAny ?? {}).forEach(([k, v]) => parts.push(`${k} contains any of [${v.join(", ")}]`));
  Object.entries(c.attributeEquals ?? {}).forEach(([k, v]) => parts.push(`${k} in [${v.join(", ")}]`));
  if (c.destinationPorts?.length) parts.push(`destinationPort in [${c.destinationPorts.join(", ")}]`);
  if (c.externalDestination) parts.push("destination is a public IP");
  return parts;
}

function logic(rule: DetectionRule): string[] {
  const parts = describeCondition(rule.condition);
  const t = rule.threshold;
  if (t) {
    const measure = t.distinctField
      ? `distinct ${t.distinctField} >= ${t.minimum}`
      : t.sumAttribute
        ? `sum(${t.sumAttribute}) >= ${t.minimum}`
        : `count >= ${t.count}`;
    parts.push(`${measure} per ${t.groupBy.join("+")} within ${t.windowSeconds}s`);
    if (t.maxJitterRatio != null) parts.push(`interval jitter <= ${Math.round(t.maxJitterRatio * 100)}% (periodic)`);
  }
  if (rule.sequence) {
    parts.push(
      `sequence per ${rule.sequence.groupBy.join("+")} within ${rule.sequence.windowSeconds}s: ` +
        rule.sequence.steps.map((s) => `${s.name}${(s.minCount ?? 1) > 1 ? ` ×${s.minCount}` : ""}`).join(" → ")
    );
  }
  if (rule.suppressionSeconds) parts.push(`suppress repeats for ${rule.suppressionSeconds}s`);
  return parts;
}

export function RulesPage({ auth }: { auth: AuthState }) {
  const rules = useRules();
  const [selectedId, setSelectedId] = useState<string>();
  const [tactic, setTactic] = useState("ALL");
  const all = rules.data ?? [];
  const tactics = useMemo(() => [...new Set(all.flatMap((r) => r.mitre.map((m) => m.tactic)))].sort(), [all]);
  const visible = all.filter((r) => tactic === "ALL" || r.mitre.some((m) => m.tactic === tactic));
  const selected = all.find((r) => r.id === selectedId) ?? visible[0];
  const enabled = all.filter((r) => r.enabled).length;

  return (
    <div className="page-stack">
      <section className="metric-grid compact" aria-label="Rule coverage">
        <article className="metric-card low">
          <span>Rules</span>
          <strong>{all.length}</strong>
          <small>{enabled} enabled</small>
        </article>
        <article className="metric-card medium">
          <span>ATT&CK tactics</span>
          <strong>{tactics.length}</strong>
          <small>covered</small>
        </article>
        <article className="metric-card high">
          <span>Techniques</span>
          <strong>{new Set(all.flatMap((r) => r.mitre.map((m) => m.techniqueId))).size}</strong>
          <small>mapped</small>
        </article>
        <article className="metric-card critical">
          <span>Correlation rules</span>
          <strong>{all.filter((r) => r.type !== "SINGLE").length}</strong>
          <small>threshold / sequence</small>
        </article>
      </section>

      <section className="split-grid">
        <article className="panel">
          <div className="panel-heading">
            <h2>Catalogue</h2>
            <label className="inline-field">
              Tactic
              <select value={tactic} onChange={(e) => setTactic(e.target.value)}>
                <option value="ALL">All</option>
                {tactics.map((t) => (
                  <option key={t}>{t}</option>
                ))}
              </select>
            </label>
          </div>
          {rules.isError ? <div className="empty-state error">{rules.error.message}</div> : null}
          <ul className="rule-list" aria-label="Detection rules">
            {visible.map((rule) => (
              <li key={rule.id}>
                <button
                  type="button"
                  className={`rule-item ${selected?.id === rule.id ? "selected" : ""} ${rule.enabled ? "" : "disabled"}`}
                  onClick={() => setSelectedId(rule.id)}
                  aria-current={selected?.id === rule.id}
                >
                  <span>
                    <code>{rule.id}</code> <small className="muted">v{rule.version} · {rule.type}</small>
                  </span>
                  <strong>{rule.name}</strong>
                  <span className="chip-row">
                    <SeverityBadge severity={rule.severity} />
                    {!rule.enabled ? <span className="status-pill offline">disabled</span> : null}
                    {rule.mitre.map((m) => (
                      <small key={m.techniqueId} className="muted">
                        {m.techniqueId}
                      </small>
                    ))}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </article>

        {selected ? <RuleDetail key={selected.id} rule={selected} auth={auth} /> : null}
      </section>
    </div>
  );
}

function RuleDetail({ rule, auth }: { rule: DetectionRule; auth: AuthState }) {
  const update = useRuleUpdate();
  const history = useRuleHistory(rule.id);
  const manage = hasAnyRole(auth.roles, MANAGER_ROLES);
  const canTest = hasAnyRole(auth.roles, WRITE_ROLES);

  return (
    <article className="panel rule-detail" aria-label={`Rule ${rule.id}`}>
      <div className="panel-heading">
        <div>
          <p className="muted">
            {rule.id} · version {rule.version} · {rule.type}
          </p>
          <h2>{rule.name}</h2>
        </div>
        <SeverityBadge severity={rule.severity} />
      </div>
      <p>{rule.description}</p>

      <h3>Detection logic</h3>
      <ul className="condition-list">
        {logic(rule).map((l) => (
          <li key={l}>
            <code>{l}</code>
          </li>
        ))}
      </ul>

      <h3>MITRE ATT&CK</h3>
      <MitreChips mitre={rule.mitre} />

      <h3>Known false positives</h3>
      <ul className="plain-list">
        {rule.falsePositives.map((fp) => (
          <li key={fp}>{fp}</li>
        ))}
      </ul>

      {manage ? (
        <div className="row-actions">
          <label className="inline-field">
            Severity
            <select
              aria-label={`Severity for ${rule.name}`}
              value={rule.severity}
              disabled={update.isPending}
              onChange={(e) =>
                update.mutate({ id: rule.id, action: "severity", severity: e.target.value as DetectionRule["severity"] })
              }
            >
              {eventSeverities.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className={rule.enabled ? "ghost-action" : "primary-action"}
            disabled={update.isPending}
            onClick={() => update.mutate({ id: rule.id, action: rule.enabled ? "disable" : "enable" })}
          >
            {rule.enabled ? "Disable rule" : "Enable rule"}
          </button>
        </div>
      ) : null}
      {update.isError ? <p className="form-error">{update.error.message}</p> : null}

      {canTest ? <RuleTester rule={rule} /> : null}

      <h3>Change history</h3>
      {(history.data ?? []).length === 0 ? <p className="muted">No changes since the service started.</p> : null}
      <ol className="timeline">
        {[...(history.data ?? [])].reverse().map((h, i) => (
          <li key={`${h.changedAt}-${i}`}>
            <span className="timeline-time">{formatTime(h.changedAt)}</span>
            <strong>{h.action}</strong>
            {h.severity ? ` → ${h.severity}` : ""} by {h.actor ?? "unknown"}
            {h.resultingVersion ? <small className="muted"> (v{h.resultingVersion})</small> : null}
          </li>
        ))}
      </ol>
    </article>
  );
}

/**
 * Sandbox: replays events through this rule in an isolated engine. Nothing is published, stored or
 * alerted. Defaults to the rule's own packaged examples.
 */
function RuleTester({ rule }: { rule: DetectionRule }) {
  const test = useRuleTest();
  const [text, setText] = useState(() => JSON.stringify(rule.examples.match, null, 2));
  const [parseError, setParseError] = useState<string>();

  const run = () => {
    setParseError(undefined);
    let events: Partial<SecurityEvent>[];
    try {
      const parsed: unknown = JSON.parse(text);
      if (!Array.isArray(parsed)) throw new Error("Expected a JSON array of events.");
      if (parsed.length > 500) throw new Error("At most 500 events per test.");
      events = parsed as Partial<SecurityEvent>[];
    } catch (e) {
      setParseError(e instanceof Error ? e.message : "Invalid JSON");
      return;
    }
    test.mutate({ ruleId: rule.id, events });
  };

  const result = test.data;
  return (
    <section className="tester" aria-label="Rule tester">
      <h3>
        <FlaskConical size={16} aria-hidden="true" /> Test this rule
      </h3>
      <p className="muted">
        Runs in an isolated sandbox: nothing is published or stored. Missing ids and timestamps are filled in.
      </p>
      <div className="row-actions">
        <button type="button" className="ghost-action" onClick={() => setText(JSON.stringify(rule.examples.match, null, 2))}>
          Load matching example
        </button>
        <button
          type="button"
          className="ghost-action"
          onClick={() => setText(JSON.stringify(rule.examples.noMatch, null, 2))}
        >
          Load non-matching example
        </button>
        <button type="button" className="ghost-action" onClick={() => test.mutate({ ruleId: rule.id })}>
          Verify packaged examples
        </button>
      </div>
      <textarea
        aria-label="Events JSON"
        className="code-input"
        spellCheck={false}
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={10}
      />
      <button type="button" className="primary-action" onClick={run} disabled={test.isPending}>
        <Play size={16} aria-hidden="true" /> Run test
      </button>
      {parseError ? <p className="form-error">{parseError}</p> : null}
      {test.isError ? <p className="form-error">{test.error.message}</p> : null}
      {result ? (
        <div className="test-result" aria-live="polite">
          {result.examplesPassed != null ? (
            <p className={result.examplesPassed ? "ok-text" : "form-error"}>
              Packaged examples {result.examplesPassed ? "behave as declared" : "FAILED"}
              {result.checks
                ? ` (${Object.entries(result.checks)
                    .map(([k, v]) => `${k}: ${v ? "pass" : "fail"}`)
                    .join(", ")})`
                : ""}
            </p>
          ) : null}
          <p>
            <strong>{result.alerts.length}</strong> alert{result.alerts.length === 1 ? "" : "s"} would fire.
          </p>
          {result.alerts.map((a) => (
            <div key={a.id} className="evidence-card">
              <EvidencePanel evidence={a.evidence} />
            </div>
          ))}
        </div>
      ) : null}
    </section>
  );
}
