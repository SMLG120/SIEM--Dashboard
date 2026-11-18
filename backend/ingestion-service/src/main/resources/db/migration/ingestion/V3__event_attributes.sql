-- Schema v2 events carry bounded key/value attributes (e.g. bytesOut, fileHash, group) used by
-- detection rules. Stored as JSON text; NULL for v1 events.
ALTER TABLE siem_event ADD COLUMN IF NOT EXISTS attributes TEXT;
