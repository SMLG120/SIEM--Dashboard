-- Event metadata: when the platform received the event (timestamp is the event time) and the
-- client's own identifier, used for idempotent retries.
ALTER TABLE siem_event ADD COLUMN IF NOT EXISTS received_at TIMESTAMP;
ALTER TABLE siem_event ADD COLUMN IF NOT EXISTS source_event_id VARCHAR(128);
ALTER TABLE siem_event ADD COLUMN IF NOT EXISTS schema_version INTEGER NOT NULL DEFAULT 1;
UPDATE siem_event SET received_at = timestamp WHERE received_at IS NULL;
ALTER TABLE siem_event ALTER COLUMN received_at SET NOT NULL;

-- Indexes for the filters the events API offers (newest first within each filter).
CREATE INDEX IF NOT EXISTS idx_siem_event_severity_ts ON siem_event (severity, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_siem_event_type_ts ON siem_event (event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_siem_event_source_ip_ts ON siem_event (source_ip, timestamp DESC);

-- Transactional outbox. A row is written in the same transaction as the event and deleted
-- some time after the relay has published it to Kafka.
CREATE TABLE IF NOT EXISTS siem_event_outbox (
    id BIGSERIAL PRIMARY KEY,
    event_id VARCHAR(64) NOT NULL,
    topic VARCHAR(128) NOT NULL,
    message_key VARCHAR(128) NOT NULL,
    payload TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    published_at TIMESTAMP,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error VARCHAR(1000)
);

CREATE INDEX IF NOT EXISTS idx_event_outbox_pending ON siem_event_outbox (id) WHERE published_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_event_outbox_published ON siem_event_outbox (published_at) WHERE published_at IS NOT NULL;
