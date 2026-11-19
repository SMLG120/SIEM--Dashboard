package com.enterprise.siem.ingestion;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

@Repository
public class OutboxRepository {
    private final JdbcClient jdbc;

    public OutboxRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public void append(String eventId, String topic, String key, String payload, Instant createdAt) {
        jdbc.sql("""
                        INSERT INTO siem_event_outbox (event_id, topic, message_key, payload, created_at)
                        VALUES (:eventId, :topic, :key, :payload, :createdAt)
                        """)
                .param("eventId", eventId)
                .param("topic", topic)
                .param("key", key)
                .param("payload", payload)
                .param("createdAt", Timestamp.from(createdAt))
                .update();
    }

    /**
     * Locks the oldest pending rows for this transaction. {@code SKIP LOCKED} lets several ingestion
     * replicas run the relay concurrently without publishing the same row twice at the same time.
     */
    public List<OutboxMessage> lockPending(int limit) {
        return jdbc.sql("""
                        SELECT id, event_id, topic, message_key, payload, attempts
                        FROM siem_event_outbox
                        WHERE published_at IS NULL
                        ORDER BY id
                        LIMIT :limit
                        FOR UPDATE SKIP LOCKED
                        """)
                .param("limit", limit)
                .query((rs, rowNum) -> new OutboxMessage(
                        rs.getLong("id"),
                        rs.getString("event_id"),
                        rs.getString("topic"),
                        rs.getString("message_key"),
                        rs.getString("payload"),
                        rs.getInt("attempts")))
                .list();
    }

    public void markPublished(long id, Instant at) {
        jdbc.sql("UPDATE siem_event_outbox SET published_at = :at, last_error = NULL WHERE id = :id")
                .param("at", Timestamp.from(at))
                .param("id", id)
                .update();
    }

    public void markFailed(long id, String error) {
        jdbc.sql("UPDATE siem_event_outbox SET attempts = attempts + 1, last_error = :error WHERE id = :id")
                .param("error", error == null ? null : error.substring(0, Math.min(error.length(), 1000)))
                .param("id", id)
                .update();
    }

    public int deletePublishedBefore(Instant cutoff) {
        return jdbc.sql("DELETE FROM siem_event_outbox WHERE published_at IS NOT NULL AND published_at < :cutoff")
                .param("cutoff", Timestamp.from(cutoff))
                .update();
    }

    public long pendingCount() {
        Long value = jdbc.sql("SELECT COUNT(*) FROM siem_event_outbox WHERE published_at IS NULL")
                .query(Long.class).single();
        return value == null ? 0 : value;
    }

    /** Age of the oldest unpublished row; zero when the outbox is drained. */
    public Duration oldestPendingAge(Instant now) {
        Timestamp oldest = jdbc.sql("SELECT MIN(created_at) FROM siem_event_outbox WHERE published_at IS NULL")
                .query(Timestamp.class).optional().orElse(null);
        return oldest == null ? Duration.ZERO : Duration.between(oldest.toInstant(), now);
    }

    public record OutboxMessage(long id, String eventId, String topic, String key, String payload, int attempts) {
    }
}
