-- v2 alert contract: rule version, MITRE mapping and evidence (JSON text), last-change time.
ALTER TABLE siem_alert ADD COLUMN IF NOT EXISTS rule_version INTEGER;
ALTER TABLE siem_alert ADD COLUMN IF NOT EXISTS mitre TEXT;
ALTER TABLE siem_alert ADD COLUMN IF NOT EXISTS evidence TEXT;
ALTER TABLE siem_alert ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;
UPDATE siem_alert SET updated_at = created_at WHERE updated_at IS NULL;
ALTER TABLE siem_alert ALTER COLUMN updated_at SET NOT NULL;

-- Query paths used by the alerts API and dashboard.
CREATE INDEX IF NOT EXISTS idx_alert_status_created ON siem_alert (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_severity_created ON siem_alert (severity, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_rule_created ON siem_alert (rule_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_source_ip ON siem_alert (source_ip);
CREATE INDEX IF NOT EXISTS idx_alert_assigned_to ON siem_alert (assigned_to);

-- Append-only investigation history: every status change, assignment and note, with the actor.
CREATE TABLE IF NOT EXISTS siem_alert_history (
    id BIGSERIAL PRIMARY KEY,
    alert_id VARCHAR(64) NOT NULL,
    action VARCHAR(32) NOT NULL,
    from_status VARCHAR(24),
    to_status VARCHAR(24),
    actor VARCHAR(128) NOT NULL,
    detail VARCHAR(1000),
    occurred_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_history_alert ON siem_alert_history (alert_id, occurred_at);

-- Enforce append-only in the database itself, not just in application code.
CREATE OR REPLACE FUNCTION siem_forbid_update_delete() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'table % is append-only', TG_TABLE_NAME;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS siem_alert_history_append_only ON siem_alert_history;
CREATE TRIGGER siem_alert_history_append_only
    BEFORE UPDATE OR DELETE ON siem_alert_history
    FOR EACH ROW EXECUTE FUNCTION siem_forbid_update_delete();
