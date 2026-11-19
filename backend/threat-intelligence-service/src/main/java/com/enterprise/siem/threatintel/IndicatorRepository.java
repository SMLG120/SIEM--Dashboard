package com.enterprise.siem.threatintel;

import com.enterprise.siem.common.model.EventSeverity;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public class IndicatorRepository {
    private static final String COLUMNS =
            "id, type, value, severity, description, source, created_by, created_at, expires_at, active";
    private static final RowMapper<Indicator> MAPPER = (rs, n) -> new Indicator(
            rs.getString("id"),
            IndicatorType.valueOf(rs.getString("type")),
            rs.getString("value"),
            EventSeverity.valueOf(rs.getString("severity")),
            rs.getString("description"),
            rs.getString("source"),
            rs.getString("created_by"),
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("expires_at") == null ? null : rs.getTimestamp("expires_at").toInstant(),
            rs.getBoolean("active"));

    private final JdbcClient jdbc;

    public IndicatorRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /** @return false if an indicator with the same type and value already exists. */
    public boolean insert(Indicator i) {
        return jdbc.sql("""
                        INSERT INTO siem_indicator (id, type, value, severity, description, source, created_by,
                                                    created_at, expires_at, active)
                        VALUES (:id, :type, :value, :severity, :description, :source, :createdBy, :createdAt,
                                :expiresAt, :active)
                        ON CONFLICT DO NOTHING
                        """)
                .param("id", i.id()).param("type", i.type().name()).param("value", i.value())
                .param("severity", i.severity().name()).param("description", i.description())
                .param("source", i.source()).param("createdBy", i.createdBy())
                .param("createdAt", Timestamp.from(i.createdAt()))
                .param("expiresAt", i.expiresAt() == null ? null : Timestamp.from(i.expiresAt()))
                .param("active", i.active())
                .update() == 1;
    }

    public List<Indicator> list(boolean activeOnly, int limit) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM siem_indicator"
                        + (activeOnly ? " WHERE active" : "") + " ORDER BY created_at DESC, id LIMIT :limit")
                .param("limit", limit).query(MAPPER).list();
    }

    public Optional<Indicator> findById(String id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM siem_indicator WHERE id = :id")
                .param("id", id).query(MAPPER).optional();
    }

    /** Active, unexpired indicators whose value is one of {@code values}. */
    public List<Indicator> matching(Collection<String> values, Instant at) {
        if (values.isEmpty()) {
            return List.of();
        }
        return jdbc.sql("SELECT " + COLUMNS + " FROM siem_indicator WHERE active AND value IN (:values)"
                        + " AND (expires_at IS NULL OR expires_at > :at)")
                .param("values", values).param("at", Timestamp.from(at)).query(MAPPER).list();
    }

    public boolean deactivate(String id) {
        return jdbc.sql("UPDATE siem_indicator SET active = FALSE WHERE id = :id AND active")
                .param("id", id).update() == 1;
    }

    public long count() {
        return jdbc.sql("SELECT COUNT(*) FROM siem_indicator").query(Long.class).single();
    }

    /** @return true if this sighting is new (redelivered events are recorded once). */
    public boolean recordSighting(String indicatorId, String eventId, String field, String value, Instant eventTime,
                                  Instant recordedAt) {
        return jdbc.sql("""
                        INSERT INTO siem_indicator_sighting (indicator_id, event_id, field, observed_value,
                                                             event_time, recorded_at)
                        VALUES (:indicatorId, :eventId, :field, :value, :eventTime, :recordedAt)
                        ON CONFLICT DO NOTHING
                        """)
                .param("indicatorId", indicatorId).param("eventId", eventId).param("field", field)
                .param("value", value).param("eventTime", Timestamp.from(eventTime))
                .param("recordedAt", Timestamp.from(recordedAt))
                .update() == 1;
    }

    public List<Sighting> sightings(String indicatorId, int limit) {
        return jdbc.sql("""
                        SELECT s.indicator_id, i.type, i.value, s.event_id, s.field, s.event_time, s.recorded_at
                        FROM siem_indicator_sighting s JOIN siem_indicator i ON i.id = s.indicator_id
                        """ + (indicatorId == null ? "" : " WHERE s.indicator_id = :id")
                        + " ORDER BY s.recorded_at DESC LIMIT :limit")
                .params(indicatorId == null ? java.util.Map.of("limit", limit)
                        : java.util.Map.of("limit", limit, "id", indicatorId))
                .query((rs, n) -> new Sighting(rs.getString("indicator_id"), IndicatorType.valueOf(rs.getString("type")),
                        rs.getString("value"), rs.getString("event_id"), rs.getString("field"),
                        rs.getTimestamp("event_time").toInstant(), rs.getTimestamp("recorded_at").toInstant()))
                .list();
    }
}
