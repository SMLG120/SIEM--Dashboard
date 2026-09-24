import type { AuthState } from "../auth";
import { useRules } from "../hooks";

export function IntelligencePage({ auth }: { auth: AuthState }) {
  const rulesQuery = useRules();
  const read = auth.roles.includes("ADMIN") || auth.roles.includes("SOC_MANAGER") || auth.roles.includes("SECURITY_ANALYST");

  return (
    <div className="page-stack">
      <article className="panel">
        <div className="panel-heading">
          <h2>Detection Rules</h2>
          <span>{rulesQuery.data?.length ?? 0} loaded</span>
        </div>
        {!read ? (
          <div className="empty-state">VIEWER role cannot view detection rules.</div>
        ) : rulesQuery.isLoading ? (
          <div className="empty-state">Loading rules...</div>
        ) : (
          <div className="data-table">
            <div className="data-row data-head rule-grid">
              <span>ID</span>
              <span>Name</span>
              <span>Severity</span>
              <span>Enabled</span>
              <span>Conditions</span>
            </div>
            {(rulesQuery.data ?? []).map((rule) => (
              <div className="data-row rule-grid" key={rule.id}>
                <span>
                  <code>{rule.id}</code>
                </span>
                <span>
                  <strong>{rule.name}</strong>
                  {rule.description ? <small className="muted-block">{rule.description}</small> : null}
                </span>
                <span>
                  <strong className={`severity ${rule.severity.toLowerCase()}`}>{rule.severity}</strong>
                </span>
                <span>
                  <span
                    className={`status-pill ${rule.enabled ? "ready" : "offline"}`}
                  >
                    {rule.enabled ? "enabled" : "disabled"}
                  </span>
                </span>
                <span className="conditions-cell">
                  {rule.condition.eventTypes?.length
                    ? rule.condition.eventTypes.map((type) => (
                        <code key={type}>{type}</code>
                      ))
                    : null}
                  {rule.condition.severityMin ? (
                    <code>severity {'>='} {rule.condition.severityMin}</code>
                  ) : null}
                  {rule.condition.category ? <code>category={rule.condition.category}</code> : null}
                </span>
              </div>
            ))}
          </div>
        )}
      </article>
    </div>
  );
}