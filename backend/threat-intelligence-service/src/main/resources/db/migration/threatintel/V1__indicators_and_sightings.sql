-- Analyst-curated indicators of compromise. `source` says where each one came from; the platform
-- ships no external feed and never labels simulated data as real intelligence.
CREATE TABLE IF NOT EXISTS siem_indicator (
    id VARCHAR(64) PRIMARY KEY,
    type VARCHAR(16) NOT NULL,
    value VARCHAR(256) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    description VARCHAR(1000),
    source VARCHAR(32) NOT NULL,
    created_by VARCHAR(128) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP,
    active BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_indicator_type_value ON siem_indicator (type, value);
CREATE INDEX IF NOT EXISTS idx_indicator_value_active ON siem_indicator (value) WHERE active;

-- An event observed with an indicator's value. One row per (indicator, event, field).
CREATE TABLE IF NOT EXISTS siem_indicator_sighting (
    indicator_id VARCHAR(64) NOT NULL REFERENCES siem_indicator (id),
    event_id VARCHAR(64) NOT NULL,
    field VARCHAR(64) NOT NULL,
    observed_value VARCHAR(256) NOT NULL,
    event_time TIMESTAMP NOT NULL,
    recorded_at TIMESTAMP NOT NULL,
    PRIMARY KEY (indicator_id, event_id, field)
);
CREATE INDEX IF NOT EXISTS idx_sighting_recorded ON siem_indicator_sighting (recorded_at DESC);
