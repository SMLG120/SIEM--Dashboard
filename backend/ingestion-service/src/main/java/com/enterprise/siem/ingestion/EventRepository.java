package com.enterprise.siem.ingestion;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SecurityEvent;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Repository
public class EventRepository {
    private static final String COLUMNS = """
            id, timestamp, event_type, severity, category, source_ip, source_host,
            destination_ip, destination_port, user_name, message, schema_version
            """;
    private static final RowMapper<SecurityEvent> MAPPER = (rs, rowNum) -> new SecurityEvent(
            rs.getString("id"),
            rs.getTimestamp("timestamp").toInstant(),
            rs.getString("event_type"),
            EventSeverity.valueOf(rs.getString("severity")),
            rs.getString("category"),
            rs.getString("source_ip"),
            rs.getString("source_host"),
            rs.getString("destination_ip"),
            rs.getObject("destination_port", Integer.class),
            rs.getString("user_name"),
            rs.getString("message"),
            rs.getInt("schema_version")
    );

    private final JdbcClient jdbc;

    public EventRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public void insert(SecurityEvent event) {
        insert(event, Instant.now(), null);
    }

    /** @return true if a row was written, false if an event with this ID already exists. */
    public boolean insert(SecurityEvent event, Instant receivedAt, String sourceEventId) {
        return jdbc.sql("""
                        INSERT INTO siem_event (id, timestamp, event_type, severity, category, source_ip, source_host,
                                                destination_ip, destination_port, user_name, message,
                                                received_at, source_event_id, schema_version)
                        VALUES (:id, :timestamp, :eventType, :severity, :category, :sourceIp, :sourceHost,
                                :destinationIp, :destinationPort, :userName, :message,
                                :receivedAt, :sourceEventId, :schemaVersion)
                        ON CONFLICT (id) DO NOTHING
                        """)
                .param("id", event.id())
                .param("timestamp", Timestamp.from(event.timestamp()))
                .param("eventType", event.eventType())
                .param("severity", event.severity().name())
                .param("category", event.category())
                .param("sourceIp", event.sourceIp())
                .param("sourceHost", event.sourceHost())
                .param("destinationIp", event.destinationIp())
                .param("destinationPort", event.destinationPort())
                .param("userName", event.userName())
                .param("message", event.message())
                .param("receivedAt", Timestamp.from(receivedAt))
                .param("sourceEventId", sourceEventId)
                .param("schemaVersion", event.schemaVersion())
                .update() == 1;
    }

    public Optional<SecurityEvent> findById(String id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM siem_event WHERE id = :id")
                .param("id", id)
                .query(MAPPER)
                .optional();
    }

    public List<SecurityEvent> recent(int limit) {
        return search(new EventQuery(null, null, null, null, null, null, limit));
    }

    /**
     * Keyset pagination: pass the timestamp and ID of the last row of the previous page as the cursor.
     * All filters are bound parameters; nothing from the request is concatenated into SQL.
     */
    public List<SecurityEvent> search(EventQuery query) {
        List<String> where = new ArrayList<>();
        Map<String, Object> params = new LinkedHashMap<>();
        if (query.severity() != null) {
            where.add("severity = :severity");
            params.put("severity", query.severity().name());
        }
        if (query.eventType() != null) {
            where.add("event_type = :eventType");
            params.put("eventType", query.eventType());
        }
        if (query.sourceIp() != null) {
            where.add("source_ip = :sourceIp");
            params.put("sourceIp", query.sourceIp());
        }
        if (query.from() != null) {
            where.add("timestamp >= :from");
            params.put("from", Timestamp.from(query.from()));
        }
        if (query.to() != null) {
            where.add("timestamp < :to");
            params.put("to", Timestamp.from(query.to()));
        }
        if (query.before() != null) {
            where.add("(timestamp, id) < (:beforeTs, :beforeId)");
            params.put("beforeTs", Timestamp.from(query.before().timestamp()));
            params.put("beforeId", query.before().id());
        }
        String sql = "SELECT " + COLUMNS + " FROM siem_event"
                + (where.isEmpty() ? "" : " WHERE " + String.join(" AND ", where))
                + " ORDER BY timestamp DESC, id DESC LIMIT :limit";
        params.put("limit", query.limit());
        return jdbc.sql(sql).params(params).query(MAPPER).list();
    }

    public long count() {
        Long value = jdbc.sql("SELECT COUNT(*) FROM siem_event").query(Long.class).single();
        return value == null ? 0L : value;
    }

    public record Cursor(Instant timestamp, String id) {
    }

    public record EventQuery(EventSeverity severity, String eventType, String sourceIp, Instant from, Instant to,
                             Cursor before, int limit) {
    }
}
