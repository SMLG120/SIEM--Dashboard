package com.enterprise.siem.audit;

import com.enterprise.siem.common.kafka.NonRetryableRecordException;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Normalises change records from the services into the audit log:
 * <ul>
 *   <li>{@code siem.rules}: rule enable/disable/severity changes (detection service)</li>
 *   <li>{@code siem.audit}: alert workflow history (alert service)</li>
 *   <li>{@code siem.incidents}: incident timeline entries (incident service)</li>
 * </ul>
 * Records are mapped field by field from raw JSON, so producers can evolve without class coupling.
 */
@Component
public class AuditConsumer {
    private final AuditRepository repository;
    private final ObjectMapper json;

    public AuditConsumer(AuditRepository repository, ObjectMapper json) {
        this.repository = repository;
        this.json = json;
    }

    @KafkaListener(topics = {"siem.rules", "siem.audit", "siem.incidents"}, groupId = "audit-service")
    public void onRecord(ConsumerRecord<String, String> record) {
        JsonNode node;
        try {
            node = json.readTree(record.value());
        } catch (JacksonException | IllegalArgumentException e) {
            throw new NonRetryableRecordException("unparseable audit record");
        }
        if (node == null || !node.isObject()) {
            throw new NonRetryableRecordException("audit record is not a JSON object");
        }
        switch (record.topic()) {
            case "siem.rules" -> repository.append(
                    instant(node.get("changedAt")), text(node, "actor", "unknown"),
                    prefixed("RULE_", text(node, "action", "CHANGED")), "RULE", text(node, "ruleId", "?"),
                    node.hasNonNull("severity") ? "severity=" + node.get("severity").asString()
                            + (node.hasNonNull("resultingVersion") ? " version=" + node.get("resultingVersion").asString() : "")
                            : node.hasNonNull("resultingVersion") ? "version=" + node.get("resultingVersion").asString() : null,
                    record.topic(), record.partition(), record.offset());
            case "siem.audit" -> repository.append(
                    instant(node.get("occurredAt")), text(node, "actor", "unknown"),
                    prefixed("ALERT_", text(node, "action", "CHANGED")), "ALERT", text(node, "alertId", "?"),
                    detail(node), record.topic(), record.partition(), record.offset());
            case "siem.incidents" -> repository.append(
                    instant(node.get("at")), text(node, "actor", "system"),
                    prefixed("INCIDENT_", text(node, "action", "CHANGED")), "INCIDENT", text(node, "incidentId", "?"),
                    node.hasNonNull("detail") ? node.get("detail").asString() : text(node, "title", null),
                    record.topic(), record.partition(), record.offset());
            default -> throw new NonRetryableRecordException("unexpected topic " + record.topic());
        }
    }

    /** Incident actions already read e.g. INCIDENT_CREATED; avoid INCIDENT_INCIDENT_CREATED. */
    static String prefixed(String prefix, String action) {
        return action.startsWith(prefix) ? action : prefix + action;
    }

    private static String detail(JsonNode node) {
        StringBuilder sb = new StringBuilder();
        if (node.hasNonNull("fromStatus") || node.hasNonNull("toStatus")) {
            sb.append(text(node, "fromStatus", "-")).append(" -> ").append(text(node, "toStatus", "-"));
        }
        if (node.hasNonNull("detail")) {
            if (!sb.isEmpty()) {
                sb.append("; ");
            }
            sb.append(node.get("detail").asString());
        }
        return sb.isEmpty() ? null : sb.toString();
    }

    private static String text(JsonNode node, String field, String fallback) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() || value.asString().isBlank() ? fallback : value.asString();
    }

    /** Accepts ISO-8601 strings and the epoch-seconds decimals older Jackson 2 producers wrote. */
    static Instant instant(JsonNode value) {
        if (value == null || value.isNull()) {
            return Instant.now();
        }
        if (value.isNumber()) {
            BigDecimal seconds = value.decimalValue();
            return Instant.ofEpochSecond(seconds.longValue(),
                    seconds.remainder(BigDecimal.ONE).movePointRight(9).intValue());
        }
        try {
            return Instant.parse(value.asString());
        } catch (RuntimeException e) {
            return Instant.now();
        }
    }
}
