-- Alerts linked to incidents, one row per link. Correlation and duplicate checks query this table
-- instead of scanning every incident's JSON payload in memory.
CREATE TABLE IF NOT EXISTS siem_incident_alert (
    incident_id VARCHAR(64) NOT NULL REFERENCES siem_incident (id),
    alert_id VARCHAR(64) NOT NULL,
    source_ip VARCHAR(64),
    linked_at TIMESTAMP NOT NULL,
    PRIMARY KEY (incident_id, alert_id)
);
CREATE INDEX IF NOT EXISTS idx_incident_alert_alert ON siem_incident_alert (alert_id);
CREATE INDEX IF NOT EXISTS idx_incident_alert_source_ip ON siem_incident_alert (source_ip);

-- Backfill from existing payloads (written by Jackson, so valid JSON). Idempotent. linked_at uses
-- the incident's creation time because older payloads may encode instants as numbers or strings.
INSERT INTO siem_incident_alert (incident_id, alert_id, source_ip, linked_at)
SELECT i.id,
       a ->> 'id',
       NULLIF(a ->> 'sourceIp', ''),
       i.created_at
FROM siem_incident i
     CROSS JOIN LATERAL jsonb_array_elements(COALESCE(i.payload::jsonb -> 'relatedAlerts', '[]'::jsonb)) AS a
WHERE a ->> 'id' IS NOT NULL
ON CONFLICT DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_incident_status_updated ON siem_incident (status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_incident_assigned_to ON siem_incident (assigned_to);
