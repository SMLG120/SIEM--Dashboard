package com.enterprise.siem.incident;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.incident.model.Incident;
import com.enterprise.siem.incident.model.IncidentNote;
import com.enterprise.siem.incident.model.IncidentStatus;
import com.enterprise.siem.incident.model.RelatedAlert;
import com.enterprise.siem.incident.model.TimelineEntry;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
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
                VALUES (:id, :title, :description, :severity, :status, :assignedTo, :createdAt, :updatedAt, :payload)
                ON CONFLICT (id) DO UPDATE
                SET title = EXCLUDED.title, description = EXCLUDED.description, severity = EXCLUDED.severity,
                    status = EXCLUDED.status, assigned_to = EXCLUDED.assigned_to, updated_at = EXCLUDED.updated_at,
                    payload = EXCLUDED.payload
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
        // Keep the link table in step with the payload (links are only ever added).
        for (RelatedAlert alert : incident.relatedAlerts()) {
            jdbc.sql("""
                    INSERT INTO siem_incident_alert (incident_id, alert_id, source_ip, linked_at)
                    VALUES (:incidentId, :alertId, :sourceIp, :linkedAt)
                    ON CONFLICT DO NOTHING
                    """)
                    .param("incidentId", incident.id())
                    .param("alertId", alert.id())
                    .param("sourceIp", alert.sourceIp())
                    .param("linkedAt", Timestamp.from(incident.updatedAt()))
                    .update();
        }
    }

    private static final String COLUMNS =
            "id, title, description, severity, status, assigned_to, created_at, updated_at, payload";

    private final org.springframework.jdbc.core.RowMapper<Incident> rowMapper = (rs, rowNum) -> fromRow(
            rs.getString("id"),
            rs.getString("title"),
            rs.getString("description"),
            rs.getString("severity"),
            rs.getString("status"),
            rs.getString("assigned_to"),
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("updated_at").toInstant(),
            rs.getString("payload"));

    public List<Incident> recent(int limit) {
        return search(null, limit);
    }

    public List<Incident> search(IncidentStatus status, int limit) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM siem_incident"
                        + (status == null ? "" : " WHERE status = :status")
                        + " ORDER BY updated_at DESC, id DESC LIMIT :limit")
                .params(status == null ? java.util.Map.of("limit", limit)
                        : java.util.Map.of("limit", limit, "status", status.name()))
                .query(rowMapper)
                .list();
    }

    public java.util.Optional<Incident> findById(String id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM siem_incident WHERE id = :id")
                .param("id", id).query(rowMapper).optional();
    }

    /** Reads the incident with a row lock; callers must be in a transaction. */
    public java.util.Optional<Incident> lock(String id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM siem_incident WHERE id = :id FOR UPDATE")
                .param("id", id).query(rowMapper).optional();
    }

    /** Most recently updated active incident with an alert from this source, locked. */
    public java.util.Optional<Incident> lockActiveBySourceIp(String sourceIp) {
        return jdbc.sql("""
                        SELECT i.id, i.title, i.description, i.severity, i.status, i.assigned_to, i.created_at,
                               i.updated_at, i.payload
                        FROM siem_incident i
                        WHERE i.status IN ('OPEN', 'INVESTIGATING', 'CONTAINED')
                          AND EXISTS (SELECT 1 FROM siem_incident_alert l
                                      WHERE l.incident_id = i.id AND l.source_ip = :sourceIp)
                        ORDER BY i.updated_at DESC, i.id DESC
                        LIMIT 1
                        FOR UPDATE
                        """)
                .param("sourceIp", sourceIp).query(rowMapper).optional();
    }

    public boolean isAlertLinked(String alertId) {
        return jdbc.sql("SELECT EXISTS (SELECT 1 FROM siem_incident_alert WHERE alert_id = :id)")
                .param("id", alertId).query(Boolean.class).single();
    }

    /**
     * Serialises correlation for one key until the transaction ends, so two alerts from the same
     * source arriving at once can't both create an incident.
     */
    public void lockCorrelationKey(String key) {
        jdbc.sql("SELECT pg_advisory_xact_lock(hashtext(:key))").param("key", "incident-correlation:" + key)
                .query((rs, n) -> 1).single();
    }

    public java.util.Map<String, Long> countByStatus() {
        java.util.Map<String, Long> out = new java.util.LinkedHashMap<>();
        jdbc.sql("SELECT status, COUNT(*) AS n FROM siem_incident GROUP BY status")
                .query((rs, n) -> java.util.Map.entry(rs.getString("status"), rs.getLong("n"))).list()
                .forEach(e -> out.put(e.getKey(), e.getValue()));
        return out;
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
        } catch (JacksonException e) {
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
        } catch (JacksonException e) {
            throw new IllegalStateException("Failed to deserialize incident payload", e);
        }
    }
}