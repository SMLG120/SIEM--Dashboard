-- Central, append-only audit trail of security-relevant changes (rule changes, alert workflow,
-- incident lifecycle). Each source record is stored once (unique Kafka coordinates).
CREATE TABLE IF NOT EXISTS siem_audit_log (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMP NOT NULL,
    recorded_at TIMESTAMP NOT NULL,
    actor VARCHAR(128) NOT NULL,
    action VARCHAR(64) NOT NULL,
    resource_type VARCHAR(32) NOT NULL,
    resource_id VARCHAR(128) NOT NULL,
    detail VARCHAR(1000),
    source_topic VARCHAR(64) NOT NULL,
    source_partition INTEGER NOT NULL,
    source_offset BIGINT NOT NULL,
    CONSTRAINT uq_audit_source UNIQUE (source_topic, source_partition, source_offset)
);
CREATE INDEX IF NOT EXISTS idx_audit_occurred ON siem_audit_log (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON siem_audit_log (actor, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON siem_audit_log (resource_type, resource_id, occurred_at DESC);

CREATE OR REPLACE FUNCTION siem_audit_forbid_change() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'siem_audit_log is append-only';
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS siem_audit_log_append_only ON siem_audit_log;
CREATE TRIGGER siem_audit_log_append_only
    BEFORE UPDATE OR DELETE ON siem_audit_log
    FOR EACH ROW EXECUTE FUNCTION siem_audit_forbid_change();
