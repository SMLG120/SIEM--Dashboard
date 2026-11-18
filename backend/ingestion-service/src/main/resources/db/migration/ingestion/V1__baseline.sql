CREATE TABLE IF NOT EXISTS siem_event (
    id VARCHAR(64) PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    category VARCHAR(64),
    source_ip VARCHAR(64),
    source_host VARCHAR(128),
    destination_ip VARCHAR(64),
    destination_port INTEGER,
    user_name VARCHAR(128),
    message TEXT
);

CREATE INDEX IF NOT EXISTS idx_siem_event_timestamp ON siem_event (timestamp DESC);