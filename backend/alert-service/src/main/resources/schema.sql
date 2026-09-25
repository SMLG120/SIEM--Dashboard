CREATE TABLE IF NOT EXISTS siem_alert (
    id VARCHAR(64) PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    rule_id VARCHAR(64) NOT NULL,
    rule_name VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(16) NOT NULL,
    event_type VARCHAR(64),
    event_id VARCHAR(64),
    source_ip VARCHAR(64),
    user_name VARCHAR(128),
    status VARCHAR(24) NOT NULL,
    assigned_to VARCHAR(128)
);

CREATE TABLE IF NOT EXISTS siem_alert_note (
    id VARCHAR(64) PRIMARY KEY,
    alert_id VARCHAR(64) NOT NULL,
    author VARCHAR(128),
    text TEXT,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alert_created_at ON siem_alert (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_note_alert_id ON siem_alert_note (alert_id);