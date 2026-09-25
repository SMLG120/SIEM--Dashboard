package com.enterprise.siem.alert;

import com.enterprise.siem.common.model.AlertStatus;
import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SiemAlert;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Repository
public class AlertRepository {
    private final JdbcClient jdbc;

    public AlertRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public void insert(SiemAlert alert) {
        jdbc.sql("""
                INSERT INTO siem_alert (id, created_at, rule_id, rule_name, description, severity, event_type,
                                        event_id, source_ip, user_name, status)
                SELECT :id, :createdAt, :ruleId, :ruleName, :description, :severity, :eventType,
                       :eventId, :sourceIp, :userName, :status
                WHERE NOT EXISTS (SELECT 1 FROM siem_alert WHERE id = :id)
                """)
                .param("id", alert.id())
                .param("createdAt", Timestamp.from(alert.createdAt()))
                .param("ruleId", alert.ruleId())
                .param("ruleName", alert.ruleName())
                .param("description", alert.description())
                .param("severity", alert.severity().name())
                .param("eventType", alert.eventType())
                .param("eventId", alert.eventId())
                .param("sourceIp", alert.sourceIp())
                .param("userName", alert.userName())
                .param("status", alert.status().name())
                .update();
    }

    public void updateStatus(SiemAlert alert) {
        jdbc.sql("UPDATE siem_alert SET status = :status WHERE id = :id")
                .param("status", alert.status().name())
                .param("id", alert.id())
                .update();
    }

    public void assign(String id, String assignedTo) {
        jdbc.sql("UPDATE siem_alert SET assigned_to = :assignedTo WHERE id = :id")
                .param("assignedTo", assignedTo)
                .param("id", id)
                .update();
    }

    public void insertNote(String alertId, AlertNote note) {
        jdbc.sql("""
                INSERT INTO siem_alert_note (id, alert_id, author, text, created_at)
                SELECT :id, :alertId, :author, :text, :createdAt
                WHERE NOT EXISTS (SELECT 1 FROM siem_alert_note WHERE id = :id)
                """)
                .param("id", note.id())
                .param("alertId", alertId)
                .param("author", note.author())
                .param("text", note.text())
                .param("createdAt", Timestamp.from(note.createdAt()))
                .update();
    }

    public List<AlertDetail> recent(int limit) {
        List<AlertDetail> base = jdbc.sql("""
                SELECT id, created_at, rule_id, rule_name, description, severity, event_type,
                       event_id, source_ip, user_name, status, assigned_to
                FROM siem_alert
                ORDER BY created_at DESC, id DESC
                LIMIT :limit
                """)
                .param("limit", limit)
                .query((rs, rowNum) -> new AlertDetail(
                        new SiemAlert(
                                rs.getString("id"),
                                rs.getTimestamp("created_at").toInstant(),
                                rs.getString("rule_id"),
                                rs.getString("rule_name"),
                                rs.getString("description"),
                                EventSeverity.valueOf(rs.getString("severity")),
                                rs.getString("event_type"),
                                rs.getString("event_id"),
                                rs.getString("source_ip"),
                                rs.getString("user_name"),
                                AlertStatus.valueOf(rs.getString("status"))
                        ),
                        rs.getString("assigned_to"),
                        List.of()
                ))
                .list();

        if (base.isEmpty()) {
            return List.of();
        }

        List<String> ids = base.stream().map(detail -> detail.alert().id()).toList();
        Map<String, List<AlertNote>> notesByAlert = jdbc.sql("""
                SELECT id, alert_id, author, text, created_at
                FROM siem_alert_note
                WHERE alert_id IN (:ids)
                ORDER BY created_at ASC, id ASC
                """)
                .param("ids", ids)
                .query((rs, rowNum) -> Map.entry(
                        rs.getString("alert_id"),
                        new AlertNote(
                                rs.getString("id"),
                                rs.getString("author"),
                                rs.getString("text"),
                                rs.getTimestamp("created_at").toInstant()
                        )
                ))
                .list()
                .stream()
                .collect(Collectors.groupingBy(Map.Entry::getKey,
                        Collectors.mapping(Map.Entry::getValue, Collectors.toList())));

        return base.stream()
                .map(detail -> new AlertDetail(
                        detail.alert(),
                        detail.assignedTo(),
                        notesByAlert.getOrDefault(detail.alert().id(), List.of())
                ))
                .toList();
    }

    public long count() {
        Long value = jdbc.sql("SELECT COUNT(*) FROM siem_alert").query(Long.class).single();
        return value == null ? 0L : value;
    }
}