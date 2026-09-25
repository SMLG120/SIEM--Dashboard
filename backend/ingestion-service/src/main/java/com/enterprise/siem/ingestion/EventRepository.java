package com.enterprise.siem.ingestion;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SecurityEvent;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.List;

@Repository
public class EventRepository {
    private final JdbcClient jdbc;

    public EventRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public void insert(SecurityEvent event) {
        jdbc.sql("""
                INSERT INTO siem_event (id, timestamp, event_type, severity, category, source_ip, source_host,
                                        destination_ip, destination_port, user_name, message)
                SELECT :id, :timestamp, :eventType, :severity, :category, :sourceIp, :sourceHost,
                       :destinationIp, :destinationPort, :userName, :message
                WHERE NOT EXISTS (SELECT 1 FROM siem_event WHERE id = :id)
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
                .update();
    }

    public List<SecurityEvent> recent(int limit) {
        return jdbc.sql("""
                SELECT id, timestamp, event_type, severity, category, source_ip, source_host,
                       destination_ip, destination_port, user_name, message
                FROM siem_event
                ORDER BY timestamp DESC, id DESC
                LIMIT :limit
                """)
                .param("limit", limit)
                .query((rs, rowNum) -> new SecurityEvent(
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
                        rs.getString("message")
                ))
                .list();
    }

    public long count() {
        Long value = jdbc.sql("SELECT COUNT(*) FROM siem_event").query(Long.class).single();
        return value == null ? 0L : value;
    }
}