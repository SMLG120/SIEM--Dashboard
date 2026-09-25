package com.enterprise.siem.incident;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.incident.model.Incident;
import com.enterprise.siem.incident.model.IncidentNote;
import com.enterprise.siem.incident.model.IncidentStatus;
import com.enterprise.siem.incident.model.RelatedAlert;
import com.enterprise.siem.incident.model.TimelineEntry;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.List;

@Repository
public class IncidentRepository {
    private record Payload(List<RelatedAlert> relatedAlerts, List<TimelineEntry> timeline, List<IncidentNote> notes) {
        static Payload empty() {
            return new Payload(List.of(), List.of(), List.of());
        }
    }

    private final JdbcClient jdbc;
    private final ObjectMapper mapper;

    public IncidentRepository(JdbcClient jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    public void save(Incident incident) {
        String payload = toPayload(incident);
        jdbc.sql("""
                INSERT INTO siem_incident (id, title, description, severity, status, assigned_to, created_at,
                                           updated_at, payload)
                SELECT :id, :title, :description, :severity, :status, :assignedTo, :createdAt, :updatedAt, :payload
                WHERE NOT EXISTS (SELECT 1 FROM siem_incident WHERE id = :id)
                """)
                .param("id", incident.id())
                .param("title", incident.title())
                .param("description", incident.description())
                .param("severity", incident.severity().name())
                .param("status", incident.status().name())
                .param("assignedTo", incident.assignedTo())
                .param("createdAt", Timestamp.from(incident.createdAt()))
                .param("updatedAt", Timestamp.from(incident.updatedAt()))
                .param("payload", payload)
                .update();
        jdbc.sql("""
                UPDATE siem_incident
                SET title = :title, description = :description, severity = :severity, status = :status,
                    assigned_to = :assignedTo, updated_at = :updatedAt, payload = :payload
                WHERE id = :id
                """)
                .param("id", incident.id())
                .param("title", incident.title())
                .param("description", incident.description())
                .param("severity", incident.severity().name())
                .param("status", incident.status().name())
                .param("assignedTo", incident.assignedTo())
                .param("updatedAt", Timestamp.from(incident.updatedAt()))
                .param("payload", payload)
                .update();
    }

    public List<Incident> recent(int limit) {
        return jdbc.sql("""
                SELECT id, title, description, severity, status, assigned_to, created_at, updated_at, payload
                FROM siem_incident
                ORDER BY updated_at DESC, id DESC
                LIMIT :limit
                """)
                .param("limit", limit)
                .query((rs, rowNum) -> fromRow(
                        rs.getString("id"),
                        rs.getString("title"),
                        rs.getString("description"),
                        rs.getString("severity"),
                        rs.getString("status"),
                        rs.getString("assigned_to"),
                        rs.getTimestamp("created_at").toInstant(),
                        rs.getTimestamp("updated_at").toInstant(),
                        rs.getString("payload")
                ))
                .list();
    }

    public long count() {
        Long value = jdbc.sql("SELECT COUNT(*) FROM siem_incident").query(Long.class).single();
        return value == null ? 0L : value;
    }

    private String toPayload(Incident incident) {
        try {
            return mapper.writeValueAsString(new Payload(
                    incident.relatedAlerts(),
                    incident.timeline(),
                    incident.notes()
            ));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize incident payload for " + incident.id(), e);
        }
    }

    private Incident fromRow(String id, String title, String description, String severity, String status,
                             String assignedTo, java.time.Instant createdAt, java.time.Instant updatedAt,
                             String payload) {
        Payload parsed = parse(payload);
        return new Incident(
                id,
                title,
                description,
                EventSeverity.valueOf(severity),
                IncidentStatus.valueOf(status),
                assignedTo,
                createdAt,
                updatedAt,
                parsed.relatedAlerts(),
                parsed.timeline(),
                parsed.notes()
        );
    }

    private Payload parse(String payload) {
        try {
            return payload == null || payload.isBlank()
                    ? Payload.empty()
                    : mapper.readValue(payload, Payload.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to deserialize incident payload", e);
        }
    }
}