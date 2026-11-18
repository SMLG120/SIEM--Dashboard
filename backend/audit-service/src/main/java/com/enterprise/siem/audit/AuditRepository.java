package com.enterprise.siem.audit;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Repository
public class AuditRepository {
    private final JdbcClient jdbc;

    public AuditRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /** @return false when this Kafka record was already stored (redelivery). */
    public boolean append(Instant occurredAt, String actor, String action, String resourceType, String resourceId,
                          String detail, String topic, int partition, long offset) {
        return jdbc.sql("""
                        INSERT INTO siem_audit_log (occurred_at, recorded_at, actor, action, resource_type, resource_id,
                                                    detail, source_topic, source_partition, source_offset)
                        VALUES (:occurredAt, :recordedAt, :actor, :action, :resourceType, :resourceId, :detail,
                                :topic, :partition, :offset)
                        ON CONFLICT ON CONSTRAINT uq_audit_source DO NOTHING
                        """)
                .param("occurredAt", Timestamp.from(occurredAt))
                .param("recordedAt", Timestamp.from(Instant.now()))
                .param("actor", truncate(actor, 128))
                .param("action", truncate(action, 64))
                .param("resourceType", resourceType)
                .param("resourceId", truncate(resourceId, 128))
                .param("detail", truncate(detail, 1000))
                .param("topic", topic).param("partition", partition).param("offset", offset)
                .update() == 1;
    }

    public List<AuditEntry> search(String actor, String resourceType, String resourceId, Instant from, int limit) {
        List<String> where = new ArrayList<>();
        Map<String, Object> params = new LinkedHashMap<>();
        if (actor != null) {
            where.add("actor = :actor");
            params.put("actor", actor);
        }
        if (resourceType != null) {
            where.add("resource_type = :resourceType");
            params.put("resourceType", resourceType);
        }
        if (resourceId != null) {
            where.add("resource_id = :resourceId");
            params.put("resourceId", resourceId);
        }
        if (from != null) {
            where.add("occurred_at >= :from");
            params.put("from", Timestamp.from(from));
        }
        params.put("limit", limit);
        return jdbc.sql("SELECT id, occurred_at, actor, action, resource_type, resource_id, detail FROM siem_audit_log"
                        + (where.isEmpty() ? "" : " WHERE " + String.join(" AND ", where))
                        + " ORDER BY occurred_at DESC, id DESC LIMIT :limit")
                .params(params)
                .query((rs, n) -> new AuditEntry(rs.getLong("id"), rs.getTimestamp("occurred_at").toInstant(),
                        rs.getString("actor"), rs.getString("action"), rs.getString("resource_type"),
                        rs.getString("resource_id"), rs.getString("detail")))
                .list();
    }

    private static String truncate(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }
}
