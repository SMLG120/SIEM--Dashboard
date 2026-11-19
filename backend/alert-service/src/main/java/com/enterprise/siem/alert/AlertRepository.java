package com.enterprise.siem.alert;

import com.enterprise.siem.common.model.AlertEvidence;
import com.enterprise.siem.common.model.AlertStatus;
import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.MitreTechnique;
import com.enterprise.siem.common.model.SiemAlert;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * PostgreSQL is the only store: every read is a query, so nothing is limited to a recent in-memory
 * window and every replica returns the same answer.
 */
@Repository
public class AlertRepository {
    private static final String COLUMNS = """
            id, created_at, rule_id, rule_name, description, severity, event_type, event_id, source_ip,
            user_name, status, assigned_to, rule_version, mitre, evidence
            """;
    /** Sorting by severity uses this rank, so CRITICAL sorts above HIGH rather than alphabetically. */
    private static final String SEVERITY_RANK = """
            CASE severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END
            """;
    private static final TypeReference<List<MitreTechnique>> MITRE_LIST = new TypeReference<>() {
    };

    private final JdbcClient jdbc;
    private final ObjectMapper json;

    public AlertRepository(JdbcClient jdbc, ObjectMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    /** @return true if the alert is new, false if it already existed (Kafka redelivery). */
    public boolean insert(SiemAlert alert) {
        return jdbc.sql("""
                        INSERT INTO siem_alert (id, created_at, rule_id, rule_name, description, severity, event_type,
                                                event_id, source_ip, user_name, status, rule_version, mitre, evidence,
                                                updated_at)
                        VALUES (:id, :createdAt, :ruleId, :ruleName, :description, :severity, :eventType,
                                :eventId, :sourceIp, :userName, :status, :ruleVersion, :mitre, :evidence, :createdAt)
                        ON CONFLICT (id) DO NOTHING
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
                .param("status", (alert.status() == null ? AlertStatus.OPEN : alert.status()).name())
                .param("ruleVersion", alert.ruleVersion())
                .param("mitre", alert.mitre().isEmpty() ? null : json.writeValueAsString(alert.mitre()))
                .param("evidence", alert.evidence() == null ? null : json.writeValueAsString(alert.evidence()))
                .update() == 1;
    }

    public Optional<AlertDetail> findDetail(String id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM siem_alert WHERE id = :id")
                .param("id", id)
                .query(this::detail)
                .optional()
                .map(d -> new AlertDetail(d.alert(), d.assignedTo(), notesFor(List.of(id)).getOrDefault(id, List.of())));
    }

    public Optional<SiemAlert> findById(String id) {
        return findDetail(id).map(AlertDetail::alert);
    }

    /** Current status, read with a row lock so concurrent transitions serialise. */
    public Optional<AlertStatus> lockStatus(String id) {
        return jdbc.sql("SELECT status FROM siem_alert WHERE id = :id FOR UPDATE")
                .param("id", id)
                .query((rs, n) -> AlertStatus.valueOf(rs.getString("status")))
                .optional();
    }

    public void updateStatus(String id, AlertStatus status, Instant at) {
        jdbc.sql("UPDATE siem_alert SET status = :status, updated_at = :at WHERE id = :id")
                .param("status", status.name())
                .param("at", Timestamp.from(at))
                .param("id", id)
                .update();
    }

    /** Kept for existing callers/tests. */
    public void updateStatus(SiemAlert alert) {
        updateStatus(alert.id(), alert.status(), Instant.now());
    }

    public void assign(String id, String assignedTo) {
        jdbc.sql("UPDATE siem_alert SET assigned_to = :assignedTo, updated_at = :at WHERE id = :id")
                .param("assignedTo", assignedTo)
                .param("at", Timestamp.from(Instant.now()))
                .param("id", id)
                .update();
    }

    public void insertNote(String alertId, AlertNote note) {
        jdbc.sql("""
                        INSERT INTO siem_alert_note (id, alert_id, author, text, created_at)
                        VALUES (:id, :alertId, :author, :text, :createdAt)
                        ON CONFLICT (id) DO NOTHING
                        """)
                .param("id", note.id())
                .param("alertId", alertId)
                .param("author", note.author())
                .param("text", note.text())
                .param("createdAt", Timestamp.from(note.createdAt()))
                .update();
    }

    public void appendHistory(AlertHistoryEntry entry) {
        jdbc.sql("""
                        INSERT INTO siem_alert_history (alert_id, action, from_status, to_status, actor, detail, occurred_at)
                        VALUES (:alertId, :action, :from, :to, :actor, :detail, :at)
                        """)
                .param("alertId", entry.alertId())
                .param("action", entry.action())
                .param("from", entry.fromStatus() == null ? null : entry.fromStatus().name())
                .param("to", entry.toStatus() == null ? null : entry.toStatus().name())
                .param("actor", entry.actor())
                .param("detail", entry.detail())
                .param("at", Timestamp.from(entry.occurredAt()))
                .update();
    }

    public List<AlertHistoryEntry> history(String alertId) {
        return jdbc.sql("""
                        SELECT alert_id, action, from_status, to_status, actor, detail, occurred_at
                        FROM siem_alert_history WHERE alert_id = :id ORDER BY occurred_at, id
                        """)
                .param("id", alertId)
                .query((rs, n) -> new AlertHistoryEntry(
                        rs.getString("alert_id"),
                        rs.getString("action"),
                        rs.getString("from_status") == null ? null : AlertStatus.valueOf(rs.getString("from_status")),
                        rs.getString("to_status") == null ? null : AlertStatus.valueOf(rs.getString("to_status")),
                        rs.getString("actor"),
                        rs.getString("detail"),
                        rs.getTimestamp("occurred_at").toInstant()))
                .list();
    }

    /** Filtered, sorted page. Every filter value is a bound parameter. */
    public Page search(AlertQuery query) {
        List<String> where = new ArrayList<>();
        Map<String, Object> params = new LinkedHashMap<>();
        if (query.statuses() != null && !query.statuses().isEmpty()) {
            where.add("status IN (:statuses)");
            params.put("statuses", query.statuses().stream().map(Enum::name).toList());
        }
        if (query.severities() != null && !query.severities().isEmpty()) {
            where.add("severity IN (:severities)");
            params.put("severities", query.severities().stream().map(Enum::name).toList());
        }
        if (query.ruleId() != null) {
            where.add("rule_id = :ruleId");
            params.put("ruleId", query.ruleId());
        }
        if (query.assignedTo() != null) {
            where.add("assigned_to = :assignedTo");
            params.put("assignedTo", query.assignedTo());
        }
        if (query.sourceIp() != null) {
            where.add("source_ip = :sourceIp");
            params.put("sourceIp", query.sourceIp());
        }
        if (query.from() != null) {
            where.add("created_at >= :from");
            params.put("from", Timestamp.from(query.from()));
        }
        String filter = where.isEmpty() ? "" : " WHERE " + String.join(" AND ", where);
        String order = query.sort() == Sort.SEVERITY
                ? SEVERITY_RANK + " DESC, created_at DESC, id DESC"
                : "created_at DESC, id DESC";

        long total = jdbc.sql("SELECT COUNT(*) FROM siem_alert" + filter).params(params).query(Long.class).single();
        Map<String, Object> pageParams = new LinkedHashMap<>(params);
        pageParams.put("limit", query.size());
        pageParams.put("offset", (long) query.page() * query.size());
        List<AlertDetail> rows = jdbc.sql("SELECT " + COLUMNS + " FROM siem_alert" + filter
                        + " ORDER BY " + order + " LIMIT :limit OFFSET :offset")
                .params(pageParams)
                .query(this::detail)
                .list();
        return new Page(rows.stream().map(AlertDetail::alert).toList(), total, query.page(), query.size());
    }

    public List<AlertDetail> recent(int limit) {
        List<AlertDetail> base = jdbc.sql("SELECT " + COLUMNS + " FROM siem_alert ORDER BY created_at DESC, id DESC LIMIT :limit")
                .param("limit", limit)
                .query(this::detail)
                .list();
        Map<String, List<AlertNote>> notes = notesFor(base.stream().map(d -> d.alert().id()).toList());
        return base.stream()
                .map(d -> new AlertDetail(d.alert(), d.assignedTo(), notes.getOrDefault(d.alert().id(), List.of())))
                .toList();
    }

    public Summary summary() {
        Map<String, Long> byStatus = new LinkedHashMap<>();
        jdbc.sql("SELECT status, COUNT(*) AS n FROM siem_alert GROUP BY status")
                .query((rs, n) -> Map.entry(rs.getString("status"), rs.getLong("n"))).list()
                .forEach(e -> byStatus.put(e.getKey(), e.getValue()));
        Map<String, Long> openBySeverity = new LinkedHashMap<>();
        jdbc.sql("SELECT severity, COUNT(*) AS n FROM siem_alert WHERE status <> 'RESOLVED' GROUP BY severity")
                .query((rs, n) -> Map.entry(rs.getString("severity"), rs.getLong("n"))).list()
                .forEach(e -> openBySeverity.put(e.getKey(), e.getValue()));
        List<RuleCount> topRules = jdbc.sql("""
                        SELECT rule_id, MAX(rule_name) AS rule_name, COUNT(*) AS n FROM siem_alert
                        GROUP BY rule_id ORDER BY n DESC, rule_id LIMIT 10
                        """)
                .query((rs, n) -> new RuleCount(rs.getString("rule_id"), rs.getString("rule_name"), rs.getLong("n")))
                .list();
        long total = byStatus.values().stream().mapToLong(Long::longValue).sum();
        return new Summary(total, byStatus, openBySeverity, topRules);
    }

    public long count() {
        Long value = jdbc.sql("SELECT COUNT(*) FROM siem_alert").query(Long.class).single();
        return value == null ? 0L : value;
    }

    private Map<String, List<AlertNote>> notesFor(Collection<String> ids) {
        if (ids.isEmpty()) {
            return Map.of();
        }
        return jdbc.sql("""
                        SELECT id, alert_id, author, text, created_at FROM siem_alert_note
                        WHERE alert_id IN (:ids) ORDER BY created_at ASC, id ASC
                        """)
                .param("ids", ids)
                .query((rs, rowNum) -> Map.entry(rs.getString("alert_id"), new AlertNote(
                        rs.getString("id"), rs.getString("author"), rs.getString("text"),
                        rs.getTimestamp("created_at").toInstant())))
                .list().stream()
                .collect(Collectors.groupingBy(Map.Entry::getKey, LinkedHashMap::new,
                        Collectors.mapping(Map.Entry::getValue, Collectors.toList())));
    }

    private AlertDetail detail(ResultSet rs, int rowNum) throws SQLException {
        String mitre = rs.getString("mitre");
        String evidence = rs.getString("evidence");
        Object version = rs.getObject("rule_version");
        SiemAlert alert = new SiemAlert(
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
                AlertStatus.valueOf(rs.getString("status")),
                version == null ? null : ((Number) version).intValue(),
                mitre == null ? List.of() : json.readValue(mitre, MITRE_LIST),
                evidence == null ? null : json.readValue(evidence, AlertEvidence.class),
                evidence == null ? 1 : SiemAlert.CURRENT_SCHEMA_VERSION);
        return new AlertDetail(alert, rs.getString("assigned_to"), List.of());
    }


    public enum Sort { CREATED, SEVERITY }

    public record AlertQuery(List<AlertStatus> statuses, List<EventSeverity> severities, String ruleId,
                             String assignedTo, String sourceIp, Instant from, Sort sort, int page, int size) {
    }

    public record Page(List<SiemAlert> items, long total, int page, int size) {
    }

    public record RuleCount(String ruleId, String ruleName, long alerts) {
    }

    public record Summary(long total, Map<String, Long> byStatus, Map<String, Long> openBySeverity,
                          List<RuleCount> topRules) {
    }
}
